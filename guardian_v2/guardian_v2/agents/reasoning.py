"""Scoring, Explainer (LLM) and Critic agents."""
from __future__ import annotations

from ..critic import verify_claims
from ..llm_contract import build_prompt, parse_response, template_claim
from ..scoring import score
from .base import AgentResult, handoff

TOP_N = 12


def make_scoring(context: dict):
    def run(state: dict, task: dict) -> AgentResult:
        comps, out = state.get("components", {}), {}
        for fid, f in state.get("findings", {}).items():
            comp = comps.get(f.get("component_purl"), {})
            s = score(f, comp, context)
            reach = comp.get("reachability") or {}
            s["reachability_state"] = reach.get("state", "n/a" if f["component_purl"].startswith("file:") else "unknown")
            s["evidence_ids"] = reach.get("evidence_ids", [])
            out[fid] = s
        ranked = sorted(out.items(), key=lambda kv: -kv[1]["score"])[:3]
        top = "; ".join(f"{state['findings'][k].get('canonical_id')} on "
                        f"{state['findings'][k]['component_purl'].split('/')[-1]} = {v['score']}" for k, v in ranked)
        return AgentResult(delta={"findings": out}, summary=f"scored {len(out)} findings; top: {top}")
    return run


def _top(state):
    fs = state.get("findings", {})
    return [k for k in sorted(fs, key=lambda k: -(fs[k].get("score") or 0)) if fs[k].get("status") != "info"][:TOP_N]


def make_explainer(llm_call, provider_names):
    def run(state: dict, task: dict) -> AgentResult:
        res = _explain(state, task)
        if not task.get("rejections"):          # fresh explanation round: reset critic retries
            res.delta["critic_attempts"] = 0
        return res

    def _explain(state: dict, task: dict) -> AgentResult:
        ids = _top(state)
        if llm_call:
            msgs = build_prompt(state, ids)
            if task.get("rejections"):
                msgs.append({"role": "user", "content": "Your previous claims were rejected: "
                             + "; ".join(task["rejections"]) + ". Fix them using only the facts given."})
            try:
                claims = parse_response(llm_call(msgs))
                return AgentResult(delta={"llm_claims": claims,
                                          "coverage": {"llm": f"ok via {provider_names}"}},
                                   summary=f"LLM produced {len(claims)} evidence-cited claims")
            except Exception as exc:
                cov = f"failed ({str(exc)[:120]}); deterministic templates used"
        else:
            cov = "no LLM key configured; deterministic templates used"
        fs, plans = state.get("findings", {}), state.get("remediation_plans", {})
        claims = [template_claim(fid, fs[fid], plans.get(f"PLAN::{fs[fid]['component_purl']}")) for fid in ids]
        return AgentResult(delta={"llm_claims": claims, "coverage": {"llm": cov}},
                           summary=f"{len(claims)} template explanations ({cov})")
    return run


def run_critic(state: dict, task: dict) -> AgentResult:
    verdict = verify_claims(state.get("llm_claims", []), state)
    attempts = state.get("critic_attempts", 0) + 1
    delta = {"critic": verdict, "critic_attempts": attempts}
    if not verdict["pass"] and attempts <= 2:
        reasons = sorted({r for x in verdict["rejected"] for r in x["reasons"]})
        return AgentResult(delta=delta,
                           summary=f"rejected {len(verdict['rejected'])}/{len(verdict['rejected']) + len(verdict['accepted'])} claims",
                           requests=[handoff("explainer", "claims failed verification", rejections=reasons[:10])])
    fs, plans = state.get("findings", {}), state.get("remediation_plans", {})
    out = {c["finding_id"]: {"ai_inferences": [c]} for c in verdict["accepted"]}
    for r in verdict["rejected"]:
        fid = r["claim"].get("finding_id")
        if fid in fs and fid not in out:
            out[fid] = {"ai_inferences": [template_claim(fid, fs[fid], plans.get(f"PLAN::{fs[fid]['component_purl']}"))]}
    delta["findings"] = out
    delta["critic"] = {**verdict, "pass": True, "final": True}
    return AgentResult(delta=delta, summary=f"verified {len(verdict['accepted'])} claims; "
                                            f"{len(verdict['rejected'])} replaced by templates")
