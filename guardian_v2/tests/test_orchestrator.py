"""Orchestration mechanics with stub agents (offline): parallel dispatch, handoffs,
critic -> explainer retry, human gate interrupt/resume, validation failure ->
remediation re-plan -> second approval -> validation pass."""
from langgraph.types import Command

import guardian_v2.orchestrator as orch
from guardian_v2.agents import gate
from guardian_v2.agents.base import Agent, AgentResult, handoff

A = "pkg:pypi/a@1.0"
CALLS = {}


def stub(name, fn=None):
    def run(state, task):
        CALLS[name] = CALLS.get(name, 0) + 1
        return fn(state, task) if fn else AgentResult(summary=f"{name} ok")
    return run


def anomaly(state, task):
    first = CALLS["anomaly"] == 1
    return AgentResult(summary="suspicious pkg", requests=[handoff("reachability", "check usage", focus=[A])] if first else [])


def remediation(state, task):
    prev = state.get("remediation_plans", {}).get("PLAN::" + A, {})
    attempt = prev.get("attempt", 0) + 1 if task.get("components") or not prev else prev["attempt"]
    return AgentResult(delta={"remediation_plans": {"PLAN::" + A: {
        "component": A, "action": "upgrade", "target_version": "2.0" if attempt == 1 else "3.0",
        "attempt": attempt, "status": "proposed", "strategy": task.get("strategy", "minimal")}}},
        summary=f"plan attempt {attempt}")


def explainer(state, task):
    return AgentResult(delta={"llm_claims": [{"bad": bool(not task.get("rejections"))}],
                              **({} if task.get("rejections") else {"critic_attempts": 0})}, summary="claims")


def critic(state, task):
    bad = state["llm_claims"][0]["bad"]
    if bad and state.get("critic_attempts", 0) < 1:
        return AgentResult(delta={"critic": {"pass": False}, "critic_attempts": 1},
                           requests=[handoff("explainer", "hallucinated id", rejections=["CVE-2099-1 not an alias"])],
                           summary="rejected")
    return AgentResult(delta={"critic": {"pass": True, "final": True}}, summary="verified")


def validation(state, task):
    plan = state["remediation_plans"]["PLAN::" + A]
    if plan["target_version"] == "2.0":
        return AgentResult(delta={"remediation_plans": {"PLAN::" + A: {"status": "failed_validation"}}},
                           requests=[handoff("remediation", "ImportError after upgrade", strategy="latest_safe",
                                             components=[A])], summary="tests FAILED")
    return AgentResult(delta={"remediation_plans": {"PLAN::" + A: {"status": "validated"}}}, summary="tests pass")


def fake_catalog(context, llm_call=None, providers=()):
    cond_final = lambda s: bool((s.get("critic") or {}).get("final"))
    cond_appr = lambda s: any(p.get("status") == "approved" for p in s.get("remediation_plans", {}).values())
    return [
        Agent("discovery", "", [], stub("discovery")), Agent("cicd", "", [], stub("cicd")),
        Agent("vuln_intel", "", ["discovery"], stub("vuln_intel")),
        Agent("reputation", "", ["discovery"], stub("reputation")),
        Agent("reachability", "", ["discovery"], stub("reachability")),
        Agent("exploit_intel", "", ["vuln_intel"], stub("exploit_intel")),
        Agent("anomaly", "", ["reputation"], stub("anomaly", anomaly)),
        Agent("scoring", "", ["vuln_intel", "exploit_intel", "anomaly", "cicd", "reachability"], stub("scoring")),
        Agent("remediation", "", ["scoring", "reputation"], stub("remediation", remediation)),
        Agent("explainer", "", ["remediation"], stub("explainer", explainer)),
        Agent("critic", "", ["explainer"], stub("critic", critic)),
        Agent("approval", "", ["critic"], gate.run_approval, exclusive=True, condition=cond_final),
        Agent("validation", "", ["approval"], stub("validation", validation), condition=cond_appr),
    ]


def test_full_orchestration_loop(monkeypatch, tmp_path):
    CALLS.clear()
    monkeypatch.setattr(orch, "build_catalog", fake_catalog)
    monkeypatch.setattr(orch, "report_agent", type("R", (), {"run": staticmethod(
        lambda s, t: AgentResult(delta={"report": {"ok": True}}, summary="report"))}))
    app, _ = orch.build_orchestrator()
    cfg = {"configurable": {"thread_id": "x"}, "recursion_limit": 200}
    app.invoke({"run_id": "t", "inputs": {}}, cfg)
    gates = 0
    while app.get_state(cfg).next:
        gates += 1
        app.invoke(Command(resume={"all": "approve", "reviewer": "alice"}), cfg)
    st = app.get_state(cfg).values
    sup = [m for m in st["messages"] if m["from"] == "supervisor"]

    assert sup[0]["to"] == ["discovery", "cicd"]                          # parallel first turn
    assert set(sup[1]["to"]) == {"vuln_intel", "reputation", "reachability"}
    assert CALLS["reachability"] == 2                                     # anomaly -> reachability handoff
    assert any(m["to"] == ["reachability"] and "scoring" in m["text"] for m in sup)  # scoring deferred
    assert gates == 2                                                     # human asked twice
    assert CALLS["explainer"] >= 3 and CALLS["critic"] >= 3               # retry + re-explain after re-plan
    plan = st["remediation_plans"]["PLAN::" + A]
    assert plan["attempt"] == 2 and plan["target_version"] == "3.0" and plan["status"] == "validated"
    assert [a["decision"] for a in st["approvals"]] == ["approved", "approved"]
    assert all(r["status"] == "done" for r in st["requests"].values())
    assert st["report"] == {"ok": True}
