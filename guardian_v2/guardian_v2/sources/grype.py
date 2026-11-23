"""Adapter: Grype JSON report -> normalized raw advisory records."""
from __future__ import annotations

import json
from pathlib import Path

from ..evidence import make_evidence


def _load(path: str) -> dict:
    data = Path(path).read_bytes()
    for enc in ("utf-8-sig", "utf-16"):
        try:
            return json.loads(data.decode(enc))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
    raise ValueError(f"unreadable Grype report: {path}")


def _best_cvss(vuln: dict) -> dict | None:
    for c in vuln.get("cvss") or []:
        score = (c.get("metrics") or {}).get("baseScore")
        if score is not None:
            return {"version": c.get("version"), "vector": c.get("vector"), "score": float(score)}
    return None


def collect(report_path: str) -> dict:
    report = _load(report_path)
    raw, evidence = [], {}
    for m in report.get("matches", []):
        art, vuln = m.get("artifact", {}), m.get("vulnerability", {})
        purl = art.get("purl")
        if not purl:
            continue
        eid, ev = make_evidence("tool_output", "grype", report_path, m)
        evidence[eid] = ev
        aliases = [rv["id"] for rv in m.get("relatedVulnerabilities", []) if rv.get("id")]
        raw.append({
            "source": "grype", "id": vuln.get("id"), "aliases": aliases, "purl": purl,
            "ranges": None,  # Grype already matched the version
            "fixed": (vuln.get("fix") or {}).get("versions", []),
            "cvss": _best_cvss(vuln) or next(
                (_best_cvss(rv) for rv in m.get("relatedVulnerabilities", []) if _best_cvss(rv)), None),
            "severity": vuln.get("severity"), "summary": vuln.get("description", ""),
            "evidence_id": eid, "withdrawn": False,
        })
    return {"raw_advisories": raw, "evidence": evidence,
            "coverage": {"source:grype": f"ok ({len(raw)} matches)"}}
