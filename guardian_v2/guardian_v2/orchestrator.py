"""Multi-agent orchestrator (supervisor pattern on LangGraph).

  supervisor --Command(goto=[agents])--> agents run in parallel --> supervisor --> ...

The supervisor keeps a blackboard (GuardianState) and decides each turn which
agents run, from three inputs:
  1. dataflow readiness: an agent runs when every agent it depends on has
     produced output it has not seen yet (so re-runs propagate downstream);
  2. handoff requests that agents send each other through the supervisor
     (anomaly -> reachability, critic -> explainer, validation -> remediation);
  3. optionally an LLM planner, whose choice is checked by guardrails and
     replaced by the deterministic policy if it is invalid.
Human approval is an exclusive turn that pauses the graph with interrupt().
"""
from __future__ import annotations

import json
import operator
import time
from typing import Annotated, Callable

from langgraph.checkpoint.memory import MemorySaver
from langgraph.errors import GraphBubbleUp
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command

from .agents import anomaly, cicd, discovery, gate, intel, reachability, reasoning, remediation, reputation
from .agents import report as report_agent
from .agents.base import Agent, AgentResult
from .state import GuardianState, merge_dict, merge_keyed_deep

MAX_TURNS = 40
INVESTIGATION_TARGETS = {"reputation", "reachability", "vuln_intel"}


class OrchestratorState(GuardianState, total=False):
    messages: Annotated[list, operator.add]
    requests: Annotated[dict, merge_keyed_deep]
    gen: Annotated[dict, merge_dict]
    seen: Annotated[dict, merge_dict]
    assignments: dict
    turn: int
    discrepancies: list
    plan_log: Annotated[list, operator.add]


def build_catalog(context: dict, llm_call=None, providers=()) -> list[Agent]:
    return [
        Agent("discovery", "Parse SBOM, dependency graphs and lockfiles into inventory + graph", [], discovery.run),
        Agent("cicd", "Check Dockerfiles and CI workflows for unpinned/unsafe components", [], cicd.run),
        Agent("vuln_intel", "Pull advisories from PyPI/OSV, npm audit, GHSA, Grype; dedupe by alias",
              ["discovery"], intel.run_vuln_intel),
        Agent("reputation", "Registry metadata: versions, yanked, maintainers, integrity, install scripts",
              ["discovery"], reputation.run),
        Agent("reachability", "Source import analysis: is each package actually used?",
              ["discovery"], reachability.run),
        Agent("exploit_intel", "CISA KEV and FIRST EPSS exploitation signals", ["vuln_intel"], intel.run_exploit_intel),
        Agent("anomaly", "Non-CVE risks: malicious/typosquat packages, lockfile tampering, install scripts",
              ["reputation"], anomaly.run),
        Agent("scoring", "Explainable risk score, confidence and SSVC decision",
              ["vuln_intel", "exploit_intel", "anomaly", "cicd", "reachability"], reasoning.make_scoring(context)),
        Agent("remediation", "Find live-verified safe versions, resolve co-upgrades, propose actions",
              ["scoring", "reputation"], remediation.run),
        Agent("explainer", "LLM: evidence-cited explanation and next steps", ["remediation"],
              reasoning.make_explainer(llm_call, list(providers)), uses_llm=True),
        Agent("critic", "Verify every LLM claim against the evidence store", ["explainer"], reasoning.run_critic),
        Agent("approval", "Human approval gate (pauses the run)", ["critic"], gate.run_approval, exclusive=True,
              condition=lambda s: bool((s.get("critic") or {}).get("final"))),
        Agent("validation", "Sandbox build + tests + live re-scan of approved changes", ["approval"],
              gate.run_validation,
              condition=lambda s: any(p.get("status") == "approved"
                                      for p in s.get("remediation_plans", {}).values())),
    ]


def _ready(catalog, state) -> list[str]:
    gen, seen, out = state.get("gen", {}), state.get("seen", {}), []
    for a in catalog:
        if any(gen.get(r, 0) == 0 for r in a.requires):
            continue
        if a.condition and not a.condition(state):
            continue
        last = seen.get(a.name)
        if last is None or any(gen.get(r, 0) > last.get(r, 0) for r in a.requires):
            out.append(a.name)
    return out


def _policy(catalog, state, ready, requested):
    """Deterministic plan: requested agents first, defer anything that depends on them."""
    by_name = {a.name: a for a in catalog}
    run = list(dict.fromkeys(requested + ready))
    deps = lambda n: set(by_name[n].requires)
    run = [n for n in run if not (deps(n) & set(run))]                 # wait for upstream in the same turn
    non_excl = [n for n in run if not by_name[n].exclusive]
    return non_excl or run[:1]


def make_supervisor(catalog: list[Agent], planner_llm: Callable | None):
    by_name = {a.name: a for a in catalog}

    def supervisor(state: OrchestratorState):
        turn = state.get("turn", 0) + 1
        open_reqs = {rid: r for rid, r in state.get("requests", {}).items() if r["status"] == "open"
                     and all(state.get("gen", {}).get(x, 0) > 0 for x in by_name[r["to"]].requires)}
        requested = list(dict.fromkeys(r["to"] for r in open_reqs.values()))
        ready = _ready(catalog, state)

        if turn > MAX_TURNS or not (ready or requested):
            why = "turn budget exhausted" if turn > MAX_TURNS else "no agent has new inputs and no handoffs are open"
            return Command(goto="report", update={"turn": turn, "messages": [
                {"turn": turn, "from": "supervisor", "to": "report", "text": f"finish: {why}"}]})

        chosen = _policy(catalog, state, ready, requested)
        reason = f"policy: ready={ready}, handoffs={requested}"
        extra = {}
        if planner_llm:
            try:
                proposal = json.loads(planner_llm(_planner_prompt(catalog, state, ready, requested)))
                pick = [n for n in proposal.get("run", []) if n in set(ready) | set(requested)]
                excl = [n for n in pick if by_name[n].exclusive]
                if pick and (not excl or len(pick) == 1) and not any(set(by_name[n].requires) & set(pick) for n in pick):
                    chosen, reason = pick, "llm planner: " + str(proposal.get("reason", ""))[:200]
                for inv in proposal.get("investigate", [])[:2]:
                    if inv.get("to") in INVESTIGATION_TARGETS and inv.get("focus"):
                        rid = f"REQ-planner-{turn}-{inv['to']}"
                        extra[rid] = {"from": "supervisor", "to": inv["to"], "status": "open",
                                      "reason": str(inv.get("reason", ""))[:200], "task": {"focus": inv["focus"][:10]}}
            except Exception as exc:
                reason += f" (llm planner rejected: {type(exc).__name__})"

        assignments, dispatched = {}, {}
        for rid, r in open_reqs.items():
            if r["to"] in chosen:
                assignments[r["to"]] = {**assignments.get(r["to"], {}), **r["task"], "request_id": rid}
                dispatched[rid] = {"status": "dispatched"}
        for n in chosen:
            assignments.setdefault(n, {})
        msg = {"turn": turn, "from": "supervisor", "to": chosen, "text": reason}
        return Command(goto=chosen, update={"turn": turn, "assignments": assignments,
                                            "requests": {**dispatched, **extra}, "messages": [msg],
                                            "plan_log": [{"turn": turn, "run": chosen, "reason": reason}]})
    return supervisor


def _planner_prompt(catalog, state, ready, requested):
    recent = state.get("messages", [])[-8:]
    return [{"role": "system", "content":
             "You coordinate security agents. Choose which READY or REQUESTED agents to run now. "
             "You may add up to 2 investigations (to: reputation|reachability|vuln_intel, focus: [purls]). "
             'Return JSON only: {"run":[names],"investigate":[{"to":..,"focus":[..],"reason":..}],"reason":str}'},
            {"role": "user", "content": json.dumps({
                "agents": {a.name: a.role for a in catalog}, "ready": ready, "requested": requested,
                "recent_messages": recent,
                "open_findings": len(state.get("findings", {}))})}]


def make_node(agent: Agent):
    def node(state: OrchestratorState) -> dict:
        task = state.get("assignments", {}).get(agent.name, {})
        t0 = time.time()
        try:
            res = agent.run(state, task)
        except GraphBubbleUp:
            raise                                   # interrupt() for the human gate
        except Exception as exc:
            res = AgentResult(delta={"coverage": {f"agent:{agent.name}": f"failed: {type(exc).__name__}: {exc}"}},
                              summary=f"FAILED: {type(exc).__name__}: {exc}")
        turn, gen = state.get("turn", 0), state.get("gen", {})
        new_reqs = {f"REQ-{agent.name}-{turn}-{i}": {"from": agent.name, "to": r["to"], "status": "open",
                                                     "reason": r["reason"], "task": r["task"]}
                    for i, r in enumerate(res.requests)}
        done = {rid: {"status": "done"} for rid, r in state.get("requests", {}).items()
                if r["to"] == agent.name and r["status"] == "dispatched"}
        text = res.summary + (f"  [{time.time() - t0:.1f}s]" if time.time() - t0 > 1 else "")
        msgs = [{"turn": turn, "from": agent.name, "to": "supervisor", "text": text}]
        msgs += [{"turn": turn, "from": agent.name, "to": r["to"], "text": f"handoff: {r['reason']}"}
                 for r in res.requests]
        delta = dict(res.delta)
        delta.update({"gen": {agent.name: gen.get(agent.name, 0) + 1},
                      "seen": {agent.name: {r: gen.get(r, 0) for r in agent.requires}},
                      "requests": {**new_reqs, **done}, "messages": msgs})
        return delta
    node.__name__ = agent.name
    return node


DAY1_AGENTS = {"discovery", "cicd", "vuln_intel", "reputation", "reachability", "exploit_intel",
               "anomaly", "scoring"}


# Agents that need a human or a container runtime; left out of unattended runs.
INTERACTIVE_AGENTS = {"approval", "validation"}


def build_orchestrator(context: dict | None = None, llm_call=None, providers=(), planner_llm=None,
                       checkpointer=None, stage: str = "full"):
    """stage="day1": Discover + Detect + initial risk level, then report (no remediation).
    stage="analysis": every agent except the human approval gate and sandbox validation,
    so the run never pauses (used by the web pipeline; remediation plans stay "proposed")."""
    catalog = build_catalog(context or {"exposure": "internet", "mission": "medium"}, llm_call, providers)
    if stage == "day1":
        catalog = [a for a in catalog if a.name in DAY1_AGENTS]
    elif stage == "analysis":
        catalog = [a for a in catalog if a.name not in INTERACTIVE_AGENTS]
    g = StateGraph(OrchestratorState)
    g.add_node("supervisor", make_supervisor(catalog, planner_llm),
               destinations=tuple(a.name for a in catalog) + ("report",))
    for a in catalog:
        g.add_node(a.name, make_node(a))
        g.add_edge(a.name, "supervisor")
    g.add_node("report", make_node(Agent("report", "Write reports", [], report_agent.run)))
    g.add_edge(START, "supervisor")
    g.add_edge("report", END)
    return g.compile(checkpointer=checkpointer or MemorySaver()), catalog
