"""Evidence critic: runs AFTER the LLM and rejects any claim it cannot verify."""
from __future__ import annotations

import re

ID_RE = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|"
                   r"RUSTSEC-\d{4}-\d+|GO-\d{4}-\d+|MAL-\d{4}-\d+)\b", re.I)
OVERCLAIM = re.compile(r"\b(actively exploited|exploited in the wild|definitely exploitable)\b", re.I)


def verify_claims(claims: list[dict], state: dict) -> dict:
    findings, evidence = state.get("findings", {}), state.get("evidence", {})
    plans = state.get("remediation_plans", {})
    accepted, rejected = [], []
    for c in claims:
        reasons = []
        f = findings.get(c.get("finding_id"))
        if f is None:
            rejected.append({"claim": c, "reasons": ["unknown finding_id"]})
            continue
        cited = c.get("evidence_ids") or []
        if not cited:
            reasons.append("no evidence cited")
        for eid in cited:
            if eid not in evidence:
                reasons.append(f"evidence {eid} does not exist")
            elif eid not in f.get("evidence_ids", []):
                reasons.append(f"evidence {eid} is not linked to this finding")

        known = {i.upper() for i in [f.get("canonical_id")] + f.get("aliases", []) if i}
        for vid in ID_RE.findall(c.get("statement", "")):
            if vid.upper() not in known:
                reasons.append(f"mentions {vid}, which is not an alias of this finding")

        facts = c.get("facts") or {}
        det_cvss = (f.get("cvss") or {}).get("score")
        if facts.get("cvss") is not None and det_cvss is not None and float(facts["cvss"]) != float(det_cvss):
            reasons.append(f"cvss {facts['cvss']} != deterministic {det_cvss}")
        if facts.get("kev") is not None and bool(facts["kev"]) != bool(f.get("kev")):
            reasons.append("kev flag contradicts KEV catalog")
        plan = plans.get(f"PLAN::{f.get('component_purl')}", {})
        if facts.get("target_version") and facts["target_version"] not in (
                plan.get("target_version"), plan.get("latest_safe")):
            reasons.append(f"target_version {facts['target_version']} is not a verified safe version")

        if OVERCLAIM.search(c.get("statement", "")) and not f.get("kev"):
            reasons.append("claims active exploitation without KEV evidence")

        (rejected if reasons else accepted).append(
            {"claim": c, "reasons": reasons} if reasons else c)
    return {"accepted": accepted, "rejected": rejected, "pass": not rejected}
