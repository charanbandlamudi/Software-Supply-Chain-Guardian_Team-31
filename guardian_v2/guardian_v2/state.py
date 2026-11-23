"""Shared LangGraph state with reducers.

Parallel branches write to the same keys in one superstep, so every shared key
needs a reducer. Without one, LangGraph raises InvalidUpdateError. Nodes must
return ONLY the delta they produced, never the full state, or the reducers
will merge the old values a second time (see adapters.adapt).
"""
from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict


def merge_dict(left: dict | None, right: dict | None) -> dict:
    """Shallow merge; right wins on key collision."""
    out = dict(left or {})
    out.update(right or {})
    return out


def _deep_merge(a: Any, b: Any) -> Any:
    if isinstance(a, dict) and isinstance(b, dict):
        out = dict(a)
        for k, v in b.items():
            out[k] = _deep_merge(out[k], v) if k in out else v
        return out
    if isinstance(a, list) and isinstance(b, list):
        seen, out = set(), []
        for item in a + b:
            key = repr(item)
            if key not in seen:
                seen.add(key)
                out.append(item)
        return out
    return b


def merge_keyed_deep(left: dict | None, right: dict | None) -> dict:
    """Deep-merge records keyed by id (finding id, PURL). Parallel branches can
    enrich the same finding or component (reputation adds registry_versions,
    reachability adds reachability) without one overwriting the other."""
    out = dict(left or {})
    for fid, finding in (right or {}).items():
        out[fid] = _deep_merge(out[fid], finding) if fid in out else finding
    return out


class GuardianState(TypedDict, total=False):
    run_id: str
    inputs: dict
    components: Annotated[dict, merge_keyed_deep]  # purl -> component
    edges: Annotated[list, operator.add]           # {"from","to","scope","constraint"}
    raw_advisories: Annotated[list, operator.add]  # per-source normalized records
    advisories: Annotated[dict, merge_dict]        # canonical_id::purl -> merged advisory
    findings: Annotated[dict, merge_keyed_deep]    # finding_id -> finding
    evidence: Annotated[dict, merge_dict]          # evidence_id -> evidence record
    coverage: Annotated[dict, merge_dict]          # stage/source -> status
    remediation_plans: Annotated[dict, merge_keyed_deep]  # plan_id -> plan
    llm_claims: list                               # last LLM attempt (overwritten)
    critic: dict                                   # last critic verdict (overwritten)
    critic_attempts: int
    approvals: Annotated[list, operator.add]
    validation: Annotated[dict, merge_dict]        # plan_id -> validation result
    report: dict
