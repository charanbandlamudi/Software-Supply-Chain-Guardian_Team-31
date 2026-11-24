"""Scoring, Explainer (LLM) and Critic agents."""
from __future__ import annotations

from ..critic import verify_claims
from ..llm_contract import build_prompt, parse_response, template_claim
from ..scoring import score
from .base import AgentResult, handoff

TOP_N = 12          # highest-scored findings explained
MAX_EXPLAINED = 24  # plus the worst finding of every other type, so each report section is covered
BATCH = 6           # findings per LLM request


def _call_with_retry(llm_call, msgs, tries: int = 5):
    """Retry rate limits (HTTP 429, e.g. Groq free tier: 8k tokens/minute) after the wait the
    provider asks for, and malformed-JSON replies (HTTP 400 json_validate_failed) once or twice."""
    import re
    import time
    for attempt in range(tries):
        try:
            return llm_call(msgs)
        except Exception as exc:
            text = str(exc)
            retryable = "429" in text or "json_validate_failed" in text or "HTTP 400" in text
            if not retryable or attempt == tries - 1:
                raise
            m = re.search(r"try again in ([\d.]+)s", text)
            time.sleep(min(60.0, float(m.group(1)) + 1.0) if m else 5.0 * (attempt + 1))


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
    ranked = [k for k in sorted(fs, key=lambda k: -(fs[k].get("score") or 0)) if fs[k].get("status") != "info"]
    picked = ranked[:TOP_N]
    seen_types = {fs[k].get("type") for k in picked}
    for k in ranked[TOP_N:]:                       # worst finding of each type not yet covered
        if len(picked) >= MAX_EXPLAINED:
            break
        if fs[k].get("type") not in seen_types:
            picked.append(k)
            seen_types.add(fs[k].get("type"))
    return picked


def make_explainer(llm_call, provider_names):
    def run(state: dict, task: dict) -> AgentResult:
        res = _explain(state, task)
        if not task.get("rejections"):          # fresh explanation round: reset critic retries
            res.delta["critic_attempts"] = 0
        return res

    def _explain(state: dict, task: dict) -> AgentResult:
        ids = _top(state)
        if llm_call:
            # Small batches keep each request under provider payload / tokens-per-minute limits
            # (one large prompt got HTTP 413 from Groq). A failed batch falls back to templates
            # for those findings only; the critic fills any finding the LLM skipped.
            claims, failures = [], []
            for start in range(0, len(ids), BATCH):
                msgs = build_prompt(state, ids[start:start + BATCH])
                if task.get("rejections"):
                    msgs.append({"role": "user", "content": "Your previous claims were rejected: "
                                 + "; ".join(task["rejections"]) + ". Fix them using only the facts given."})
                try:
                    batch = parse_response(_call_with_retry(llm_call, msgs))
                    served = getattr(llm_call, "last_served", None) or {"provider": ",".join(provider_names), "model": None}
                    for c in batch:
                        c.update(agent="explainer", llm_provider=served["provider"], llm_model=served["model"])
                    claims += batch
                except Exception as exc:
                    failures.append(str(exc)[:120])
            if claims:
                cov = f"ok via {provider_names}" + (f"; {len(failures)} batch(es) failed: {failures[0]}" if failures else "")
                return AgentResult(delta={"llm_claims": claims, "coverage": {"llm": cov}},
                                   summary=f"LLM produced {len(claims)} evidence-cited claims for {len(ids)} findings"
                                           + (f" ({len(failures)} batch(es) failed)" if failures else ""))
            cov = f"failed ({failures[0] if failures else 'no claims'}); deterministic templates used"
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
    out = {c["finding_id"]: {"ai_inferences": [{**c, "verified_by": "critic"}]} for c in verdict["accepted"]}
    for r in verdict["rejected"]:
        fid = r["claim"].get("finding_id")
        if fid in fs and fid not in out:
            out[fid] = {"ai_inferences": [template_claim(fid, fs[fid], plans.get(f"PLAN::{fs[fid]['component_purl']}"))]}
    for fid in _top(state):                     # the LLM skipped it: deterministic template, labelled as such
        if fid in fs and fid not in out:
            out[fid] = {"ai_inferences": [template_claim(fid, fs[fid], plans.get(f"PLAN::{fs[fid]['component_purl']}"))]}
    delta["findings"] = out
    delta["critic"] = {**verdict, "pass": True, "final": True}
    return AgentResult(delta=delta, summary=f"verified {len(verdict['accepted'])} claims; "
                                            f"{len(verdict['rejected'])} replaced by templates")
