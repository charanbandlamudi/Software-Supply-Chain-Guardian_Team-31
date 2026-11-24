"""Adapters: OSV-Scanner and Trivy JSON reports -> normalized raw advisory records.

Same record schema as sources/grype.py (see dedup.merge_advisories). Both tools
have already matched the installed version, so ranges=None. Every record keeps a
hashed evidence entry pointing at the raw tool output.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..evidence import make_evidence

_SEV = {"MODERATE": "MEDIUM"}


def _purl(p: str | None) -> str | None:
    return p.split("?", 1)[0] if p else None          # drop qualifiers (?source=...)


def collect_osv_scanner(report_path: str) -> dict:
    report = json.loads(Path(report_path).read_text())
    raw, evidence = [], {}
    for res in report.get("results", []):
        for p in res.get("packages", []):
            pkg = p.get("package", {})
            purl = _purl(pkg.get("purl"))
            if not purl:
                continue
            for v in p.get("vulnerabilities", []):
                eid, ev = make_evidence("tool_output", "osv-scanner", report_path,
                                        {"package": pkg, "id": v.get("id"), "aliases": v.get("aliases")})
                evidence[eid] = ev
                fixed = sorted({e["fixed"] for aff in v.get("affected", [])
                                if (aff.get("package") or {}).get("name") == pkg.get("name")
                                for r in aff.get("ranges", []) for e in r.get("events", []) if "fixed" in e})
                sev = ((v.get("database_specific") or {}).get("severity") or "").upper() or None
                raw.append({"source": "osv-scanner", "id": v["id"], "aliases": v.get("aliases") or [],
                            "purl": purl, "ranges": None, "fixed": fixed, "cvss": None,
                            "severity": _SEV.get(sev, sev), "summary": v.get("summary") or v.get("details", "")[:400],
                            "evidence_id": eid, "withdrawn": bool(v.get("withdrawn"))})
    return {"raw_advisories": raw, "evidence": evidence,
            "coverage": {"source:osv-scanner": f"ok ({len(raw)} matches)"}}


def collect_trivy(report_path: str) -> dict:
    report = json.loads(Path(report_path).read_text())
    raw, evidence = [], {}
    for res in report.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            purl = _purl((v.get("PkgIdentifier") or {}).get("PURL"))
            if not purl:
                continue
            eid, ev = make_evidence("tool_output", "trivy", report_path,
                                    {k: v.get(k) for k in ("VulnerabilityID", "PkgName", "InstalledVersion",
                                                           "FixedVersion", "Severity", "VendorIDs")})
            evidence[eid] = ev
            cvss = None
            for src in (v.get("CVSS") or {}).values():
                score = src.get("V3Score") or src.get("V40Score")
                if score:
                    cvss = {"version": "3" if src.get("V3Score") else "4",
                            "vector": src.get("V3Vector") or src.get("V40Vector"), "score": float(score)}
                    break
            raw.append({"source": "trivy", "id": v.get("VulnerabilityID"), "aliases": v.get("VendorIDs") or [],
                        "purl": purl, "ranges": None,
                        "fixed": [f.strip().lstrip(">=") for f in (v.get("FixedVersion") or "").split(",") if f.strip()],
                        "cvss": cvss, "severity": v.get("Severity"),
                        "summary": v.get("Title") or (v.get("Description") or "")[:400],
                        "evidence_id": eid, "withdrawn": False})
    return {"raw_advisories": raw, "evidence": evidence,
            "coverage": {"source:trivy": f"ok ({len(raw)} matches)"}}


TRIVY_BASE = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0, "UNKNOWN": 4.0}


def trivy_repo_findings(report_path: str) -> tuple[dict, dict]:
    """Trivy misconfigurations + secrets as Guardian findings. Secret values are never copied."""
    report = json.loads(Path(report_path).read_text())
    findings, evidence = {}, {}
    for res in report.get("Results") or []:
        target = res.get("Target")
        for m in res.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            line = (m.get("CauseMetadata") or {}).get("StartLine")
            facts = {k: m.get(k) for k in ("ID", "AVDID", "Title", "Severity", "Message", "Resolution", "PrimaryURL")}
            eid, ev = make_evidence("tool_output", "trivy-misconfig", f"{target}:{line}", facts)
            evidence[eid] = ev
            sev = (m.get("Severity") or "UNKNOWN").upper()
            findings[f"MISCONFIGURATION::{m.get('ID')}::{target}:{line}"] = {
                "type": "misconfiguration", "component_purl": f"file:{target}", "status": "open",
                "canonical_id": m.get("ID"), "aliases": [m["AVDID"]] if m.get("AVDID") else [],
                "sources": ["trivy"], "summary": f"{m.get('Title')}: {m.get('Message')}",
                "calibrated_base": TRIVY_BASE.get(sev, 4.0), "tool_severity": sev,
                "recommended_action": m.get("Resolution"), "reference": m.get("PrimaryURL"),
                "evidence_ids": [eid], "location": {"file": target, "line": line}, "paths": []}
        for s in res.get("Secrets") or []:
            facts = {k: s.get(k) for k in ("RuleID", "Category", "Title", "Severity", "StartLine", "EndLine")}
            eid, ev = make_evidence("tool_output", "trivy-secret", f"{target}:{s.get('StartLine')}", facts)
            evidence[eid] = ev
            sev = (s.get("Severity") or "UNKNOWN").upper()
            findings[f"EXPOSED_SECRET::{s.get('RuleID')}::{target}:{s.get('StartLine')}"] = {
                "type": "exposed_secret", "component_purl": f"file:{target}", "status": "open",
                "canonical_id": f"SECRET-{s.get('RuleID')}", "aliases": [], "sources": ["trivy"],
                "summary": f"{s.get('Title')} committed in {target} (line {s.get('StartLine')}); value redacted.",
                "calibrated_base": TRIVY_BASE.get(sev, 4.0), "tool_severity": sev,
                "evidence_ids": [eid], "location": {"file": target, "line": s.get("StartLine")}, "paths": []}
    return findings, evidence
