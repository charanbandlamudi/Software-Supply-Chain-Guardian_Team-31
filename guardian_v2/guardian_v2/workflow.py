"""Guardian v2 LangGraph workflow.

START -> ingestion -> dependency_graph
      -> [Send] source_worker x N (grype, osv, ghsa, ...)      parallel per source
      -> alias_dedup (findings created here, once, with dependency paths)
      -> enrichment | reputation | anomaly | container_cicd | reachability   parallel
      -> risk_scoring -> upgrade_planner -> llm_inference -> evidence_critic
         (critic rejects -> llm_inference, max 2 retries, then template fallback)
      -> human_approval (interrupt) -> sandbox_validation? -> report -> END
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, Send, interrupt

from . import versions as V
from .critic import verify_claims
from .dedup import merge_advisories
from .graph_paths import all_paths, introducing_direct
from .llm_contract import build_prompt, parse_response, template_claim
from .safe_version import plan_for_component
from .scoring import score
from .state import GuardianState

MAX_CRITIC_RETRIES = 2


def _passthrough(state: dict) -> dict:
    return {}


@dataclass
class GuardianDeps:
    # v1 nodes (wrap with adapters.adapt). Each must return a delta dict.
    ingestion: Callable = _passthrough
    dependency_graph: Callable = _passthrough
    reputation: Callable = _passthrough      # should fill components[purl]["registry_versions"]
    anomaly: Callable = _passthrough         # non-CVE findings
    container_cicd: Callable = _passthrough
    reachability: Callable = _passthrough    # should fill components[purl]["reachability"]
    report: Callable | None = None
    # name -> fn(state_slice) -> {"raw_advisories", "evidence", "coverage"}
    sources: dict[str, Callable] = field(default_factory=dict)
    kev_catalog: Callable[[], dict] | None = None             # -> {cve: record}
    epss_lookup: Callable[[list[str]], dict] | None = None    # cves -> {cve: {"epss","percentile"}}
    llm_call: Callable[[list[dict]], str] | None = None       # Groq -> Gemini chain
    validator: Callable[[dict, dict], dict] | None = None     # sandbox build/test/rescan
    context: dict = field(default_factory=lambda: {"exposure": "internet", "mission": "medium"})


def build_workflow(deps: GuardianDeps, checkpointer=None):
    g = StateGraph(GuardianState)

    # ---------- discover ----------
    g.add_node("ingestion", deps.ingestion)
    g.add_node("dependency_graph", deps.dependency_graph)

    def route_sources(state: GuardianState):
        purls = [p for p in state.get("components", {}) if V.version_of(p)]
        return [Send("source_worker", {"source": name, "purls": purls,
                                       "inputs": state.get("inputs", {})})
                for name in deps.sources] or ["alias_dedup"]

    def source_worker(payload: dict) -> dict:
        name = payload["source"]
        try:
            return deps.sources[name](payload)
        except Exception as exc:  # one dead source never kills the run
            return {"coverage": {f"source:{name}": f"failed: {type(exc).__name__}: {exc}"}}

    g.add_node("source_worker", source_worker)

    # ---------- detect: one finding per (issue, component) ----------
    def alias_dedup(state: GuardianState) -> dict:
        comps, edges = state.get("components", {}), state.get("edges", [])
        merged = merge_advisories(state.get("raw_advisories", []))
        findings = {}
        for key, adv in merged.items():
            paths = all_paths(comps, edges, adv["purl"])
            findings[f"VULN::{key}"] = {
                "type": "vulnerability", "component_purl": adv["purl"], "status": "open",
                **{k: adv[k] for k in ("canonical_id", "aliases", "sources", "recommended_fix",
                                       "cvss", "source_conflicts", "summary", "evidence_ids")},
                "paths": paths, "introduced_by": introducing_direct(paths),
                "direct": bool(comps.get(adv["purl"], {}).get("direct")),
            }
        return {"advisories": merged, "findings": findings,
                "coverage": {"alias_dedup": f"{len(state.get('raw_advisories', []))} raw -> "
                                            f"{len(merged)} unique"}}

    g.add_node("alias_dedup", alias_dedup)

    def enrichment(state: GuardianState) -> dict:
        out, cov = {}, {}
        vulns = {fid: f for fid, f in state.get("findings", {}).items() if f["type"] == "vulnerability"}
        cve_of = {fid: next((i for i in [f["canonical_id"], *f["aliases"]] if i.startswith("CVE-")), None)
                  for fid, f in vulns.items()}
        cves = sorted({c for c in cve_of.values() if c})
        kev, epss = {}, {}
        try:
            kev = deps.kev_catalog() if deps.kev_catalog else {}
            cov["source:kev"] = "ok" if deps.kev_catalog else "not configured"
        except Exception as exc:
            cov["source:kev"] = f"failed: {exc}"
        try:
            epss = deps.epss_lookup(cves) if deps.epss_lookup and cves else {}
            cov["source:epss"] = f"ok ({len(epss)}/{len(cves)})" if deps.epss_lookup else "not configured"
        except Exception as exc:
            cov["source:epss"] = f"failed: {exc}"
        for fid, cve in cve_of.items():
            out[fid] = {"cve": cve, "kev": bool(cve and cve in kev),
                        "kev_record": kev.get(cve) if cve else None,
                        "epss": epss.get(cve) if cve else None}
        return {"findings": out, "coverage": cov}

    g.add_node("enrichment", enrichment)
    analysis = ["enrichment", "reputation", "anomaly", "container_cicd", "reachability"]
    g.add_node("reputation", deps.reputation)
    g.add_node("anomaly", deps.anomaly)
    g.add_node("container_cicd", deps.container_cicd)
    g.add_node("reachability", deps.reachability)

    # ---------- analyze ----------
    def risk_scoring(state: GuardianState) -> dict:
        comps = state.get("components", {})
        out = {}
        for fid, f in state.get("findings", {}).items():
            comp = comps.get(f.get("component_purl"), {})
            s = score(f, comp, deps.context)
            s["reachability_state"] = (comp.get("reachability") or {}).get("state", "unknown")
            s["evidence_ids"] = (comp.get("reachability") or {}).get("evidence_ids", [])
            out[fid] = s
        return {"findings": out}

    g.add_node("risk_scoring", risk_scoring)

    def upgrade_planner(state: GuardianState) -> dict:
        by_comp: dict[str, list] = {}
        for f in state.get("findings", {}).values():
            if f["type"] == "vulnerability" and f.get("status") == "open":
                by_comp.setdefault(f["component_purl"], []).append(f["canonical_id"])
        advs = state.get("advisories", {})
        comps, plans = state.get("components", {}), {}
        for purl, ids in by_comp.items():
            relevant = [advs[f"{i}::{purl}"] for i in ids if f"{i}::{purl}" in advs]
            available = comps.get(purl, {}).get("registry_versions", [])
            try:
                plan = plan_for_component(purl, relevant, available, state.get("edges", []))
            except ValueError as exc:  # ecosystem without deterministic ordering
                plan = {"component": purl, "action": "request_review", "reason": str(exc),
                        "requires_human_approval": True, "merge": False}
            if not available:
                plan.setdefault("reason", "registry version list missing (reputation node)")
            plans[f"PLAN::{purl}"] = {**plan, "status": "proposed"}
        return {"remediation_plans": plans}

    g.add_node("upgrade_planner", upgrade_planner)

    def _top_findings(state, n=15):
        fs = state.get("findings", {})
        return sorted(fs, key=lambda k: -(fs[k].get("score") or 0))[:n]

    def llm_inference(state: GuardianState) -> dict:
        ids = _top_findings(state)
        attempt = state.get("critic_attempts", 0)
        if deps.llm_call and attempt <= MAX_CRITIC_RETRIES:
            msgs = build_prompt(state, ids)
            prev = state.get("critic") or {}
            if prev.get("rejected"):
                msgs.append({"role": "user", "content": "Your previous claims were rejected for: "
                             + "; ".join(r for x in prev["rejected"] for r in x["reasons"])
                             + ". Fix them using only the given facts."})
            try:
                claims = parse_response(deps.llm_call(msgs))
                return {"llm_claims": claims, "coverage": {"llm": f"ok (attempt {attempt + 1})"}}
            except Exception as exc:
                cov = {"llm": f"failed: {type(exc).__name__}: {exc}; template fallback used"}
        else:
            cov = {"llm": "not configured or retries exhausted; template fallback used"}
        plans = state.get("remediation_plans", {})
        fs = state.get("findings", {})
        claims = [template_claim(fid, fs[fid], plans.get(f"PLAN::{fs[fid].get('component_purl')}"))
                  for fid in ids if fs[fid]["type"] == "vulnerability"]
        return {"llm_claims": claims, "coverage": cov}

    g.add_node("llm_inference", llm_inference)

    def evidence_critic(state: GuardianState) -> dict:
        verdict = verify_claims(state.get("llm_claims", []), state)
        upd = {"critic": verdict, "critic_attempts": state.get("critic_attempts", 0) + 1}
        final = verdict["pass"] or state.get("critic_attempts", 0) >= MAX_CRITIC_RETRIES
        if final:
            fs, plans = state.get("findings", {}), state.get("remediation_plans", {})
            out = {c["finding_id"]: {"ai_inferences": [c]} for c in verdict["accepted"]}
            # Findings whose LLM claims were all rejected get a deterministic explanation.
            for r in verdict["rejected"]:
                fid = r["claim"].get("finding_id")
                if fid in fs and fid not in out and fs[fid]["type"] == "vulnerability":
                    plan = plans.get(f"PLAN::{fs[fid].get('component_purl')}")
                    out[fid] = {"ai_inferences": [template_claim(fid, fs[fid], plan)]}
            upd["findings"] = out
        return upd

    def after_critic(state: GuardianState):
        v = state.get("critic") or {}
        if not v.get("pass") and state.get("critic_attempts", 0) <= MAX_CRITIC_RETRIES:
            return "llm_inference"
        return "human_approval"

    g.add_node("evidence_critic", evidence_critic)

    # ---------- remediate: human gate ----------
    def human_approval(state: GuardianState) -> dict:
        plans = {pid: p for pid, p in state.get("remediation_plans", {}).items()
                 if p.get("status") == "proposed"}
        if not plans:
            return {}
        decision = interrupt({"question": "Approve remediation plans?", "plans": plans})
        reviewer = decision.get("reviewer", "unknown")
        upd, approvals = {}, []
        for pid, choice in decision.get("decisions", {}).items():
            if pid in plans:
                status = "approved" if choice == "approve" else "rejected"
                upd[pid] = {**plans[pid], "status": status}
                approvals.append({"plan_id": pid, "decision": status, "reviewer": reviewer})
        return {"remediation_plans": upd, "approvals": approvals}

    def after_approval(state: GuardianState):
        approved = any(p.get("status") == "approved"
                       for p in state.get("remediation_plans", {}).values())
        return "sandbox_validation" if approved else "report"

    g.add_node("human_approval", human_approval)

    # ---------- validate ----------
    def sandbox_validation(state: GuardianState) -> dict:
        out = {}
        for pid, plan in state.get("remediation_plans", {}).items():
            if plan.get("status") != "approved":
                continue
            if deps.validator is None:
                out[pid] = {"status": "not_run", "reason": "no sandbox validator configured"}
                continue
            res = deps.validator(plan, state)
            before = set(state.get("components", {}))
            after = set(res.get("after_components", []))
            res["sbom_diff"] = {"added": sorted(after - before), "removed": sorted(before - after)}
            res["new_findings"] = res.get("after_finding_ids", [])
            out[pid] = res
        return {"validation": out}

    g.add_node("sandbox_validation", sandbox_validation)

    def default_report(state: GuardianState) -> dict:
        fs = state.get("findings", {})
        ranked = sorted(fs.items(), key=lambda kv: -(kv[1].get("score") or 0))
        return {"report": {
            "run_id": state.get("run_id"),
            "inventory": {"components": len(state.get("components", {})),
                          "edges": len(state.get("edges", []))},
            "findings": [{"id": k, **v} for k, v in ranked],
            "remediation_plans": state.get("remediation_plans", {}),
            "approvals": state.get("approvals", []),
            "validation": state.get("validation", {}),
            "critic": {"rejected": state.get("critic", {}).get("rejected", [])},
            "coverage": state.get("coverage", {}),
        }}

    g.add_node("report", deps.report or default_report)

    # ---------- edges ----------
    g.add_edge(START, "ingestion")
    g.add_edge("ingestion", "dependency_graph")
    g.add_conditional_edges("dependency_graph", route_sources, ["source_worker", "alias_dedup"])
    g.add_edge("source_worker", "alias_dedup")
    for node in analysis:
        g.add_edge("alias_dedup", node)
    g.add_edge(analysis, "risk_scoring")          # join: waits for all five
    g.add_edge("risk_scoring", "upgrade_planner")
    g.add_edge("upgrade_planner", "llm_inference")
    g.add_edge("llm_inference", "evidence_critic")
    g.add_conditional_edges("evidence_critic", after_critic, ["llm_inference", "human_approval"])
    g.add_conditional_edges("human_approval", after_approval, ["sandbox_validation", "report"])
    g.add_edge("sandbox_validation", "report")
    g.add_edge("report", END)
    return g.compile(checkpointer=checkpointer or MemorySaver())


__all__ = ["GuardianDeps", "build_workflow", "Command"]
