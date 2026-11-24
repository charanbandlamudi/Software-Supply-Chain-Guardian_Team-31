"""Report agent: Guardian JSON, Markdown, SARIF 2.1.0 and the agent trace."""
from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from ..audit import verify_chain, write_audit

from .base import AgentResult
from .day1_outputs import cyclonedx, mermaid_graph, origin

LEVEL = lambda s: "error" if s >= 60 else "warning" if s >= 30 else "note"


def _status(f, plans):
    p = plans.get(f"PLAN::{f['component_purl']}", {})
    if p.get("status") == "validated" and f["id"] in p.get("finding_ids", []):
        return "fixed_in_sandbox (awaiting PR merge by a human)"
    if p.get("status") in ("approved", "proposed"):
        return f"plan {p['status']}"
    if p.get("status") == "rejected":
        return "accepted_risk (plan rejected by reviewer)"
    return p.get("status") or "open"


def run(state: dict, task: dict) -> AgentResult:
    out_dir = Path(state.get("inputs", {}).get("out_dir", "guardian-out"))
    out_dir.mkdir(parents=True, exist_ok=True)
    comps, plans = state.get("components", {}), state.get("remediation_plans", {})
    fs = [{"id": k, **v} for k, v in state.get("findings", {}).items()]
    fs.sort(key=lambda f: -(f.get("score") or 0))
    for f in fs:
        f["resolution"] = _status(f, plans)

    audit_entries = state.get("audit", [])
    audit_ok, audit_error = verify_chain(audit_entries)
    audit_sha = write_audit(out_dir / "audit.jsonl", audit_entries) if audit_entries else None
    head_hash = audit_entries[-1]["hash"] if audit_entries else None
    report = {
        "run_id": state.get("run_id"),
        "stage": state.get("inputs", {}).get("stage", "full"),
        "inventory": {"components": [{k: c.get(k) for k in ("purl", "direct", "scope", "sources")}
                                     | {"reachability": (c.get("reachability") or {}).get("state"),
                                        "origin": origin(c)}
                                     for c in comps.values()],
                      "edges": state.get("edges", [])},
        "findings": [{k: f.get(k) for k in ("id", "type", "canonical_id", "aliases", "component_purl", "score",
                                            "confidence", "ssvc", "score_breakdown", "reachability_state", "kev",
                                            "epss", "sources", "source_conflicts", "paths", "introduced_by",
                                            "recommended_fix", "summary", "evidence_ids", "ai_inferences",
                                            "tool_severity", "recommended_action", "reference", "facts",
                                            "resolution", "location")} for f in fs],
        "remediation_plans": plans, "approvals": state.get("approvals", []),
        "validation": state.get("validation", {}), "coverage": state.get("coverage", {}),
        "agent_trace": state.get("messages", []),
        "claims": state.get("critic", {}).get("accepted", []) + [
            {**x["claim"], "label": "REJECTED", "reasons": x["reasons"]}
            for x in state.get("critic", {}).get("rejected", [])
        ],
        "audit": {"entries": len(audit_entries), "head_hash": head_hash,
                  "integrity": "valid" if audit_ok else "invalid",
                  "error": audit_error, "sha256": audit_sha},
    }
    (out_dir / "guardian-report.json").write_text(json.dumps(report, indent=2, default=str))
    (out_dir / "guardian-sbom.cdx.json").write_text(json.dumps(cyclonedx(state), indent=2))
    (out_dir / "dependency-graph.mmd").write_text(mermaid_graph(state))

    sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "runs": [{"tool": {"driver": {"name": "Supply Chain Guardian", "version": "2.0",
                                           "rules": [{"id": t} for t in sorted({f["type"] for f in fs})]}},
                       "results": [{"ruleId": f["type"], "level": LEVEL(f.get("score") or 0),
                                    "message": {"text": f"{f.get('canonical_id')} in {f['component_purl']}: "
                                                        f"{(f.get('summary') or '')[:200]}"},
                                    "locations": [{"physicalLocation": {"artifactLocation": {
                                        "uri": (f.get("location") or {}).get("file") or f["component_purl"]},
                                        **({"region": {"startLine": f["location"]["line"]}} if f.get("location") else {})}}],
                                    "properties": {"score": f.get("score"), "confidence": f.get("confidence")}}
                                   for f in fs]}]}
    (out_dir / "guardian.sarif").write_text(json.dumps(sarif, indent=2))
    vex_statements = []
    for f in fs:
        if f["component_purl"].startswith("file:"):
            continue
        if f.get("reachability_state") == "not_in_runtime" or f.get("reachability_state") == "not_imported":
            c = comps.get(f["component_purl"], {})
            evidence_ids = c.get("reachability", {}).get("evidence_ids", [])
            if evidence_ids:
                vex_statements.append({
                    "vulnerability": {"name": f.get("canonical_id")},
                    "products": [{"@id": f["component_purl"]}],
                    "status": "not_affected",
                    "justification": "vulnerable_code_not_in_execute_path",
                    "impact_statement": "Static reachability evidence found no application import or runtime call path.",
                })
    vex = {"@context": "https://openvex.dev/ns/v0.2.0",
           "@id": f"urn:uuid:guardian-{state.get('run_id')}",
           "author": "Software Supply Chain Guardian",
           "timestamp": datetime.now(timezone.utc).isoformat(),
           "version": 1, "statements": vex_statements}
    (out_dir / "guardian.openvex.json").write_text(json.dumps(vex, indent=2))

    report_bytes = (out_dir / "guardian-report.json").read_bytes()
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "guardian-report.json", "digest": {"sha256": hashlib.sha256(report_bytes).hexdigest()}},
                    {"name": "guardian-sbom.cdx.json",
                     "digest": {"sha256": hashlib.sha256((out_dir / "guardian-sbom.cdx.json").read_bytes()).hexdigest()}}],
        "predicateType": "https://bgsw.example/guardian-report/v1",
        "predicate": {"run_id": state.get("run_id"), "audit_head_hash": head_hash,
                      "validated_by": "Software Supply Chain Guardian"},
    }
    (out_dir / "guardian.in-toto.json").write_text(json.dumps(statement, indent=2))

    md = [f"# Guardian Report: run {state.get('run_id')}", ""]
    vulns = [f for f in fs if f["type"] == "vulnerability"]
    md += [f"{len(comps)} components, {len(state.get('edges', []))} edges, {len(vulns)} unique vulnerabilities, "
           f"{len(fs) - len(vulns)} non-CVE findings.", "",
           "## Top findings", "", "| Score | Conf | SSVC | Finding | Component | Reachability | Resolution |",
           "|---|---|---|---|---|---|---|"]
    for f in fs[:20]:
        md.append(f"| {f.get('score')} | {f.get('confidence')} | {(f.get('ssvc') or {}).get('decision')} | "
                  f"{f.get('canonical_id')} | {f['component_purl'].split('/')[-1]} | "
                  f"{f.get('reachability_state')} | {f['resolution']} |")
    changed = [f for f in fs if f["type"] in ("lockfile_tampering", "dependency_added", "unexpected_dependency",
                                             "suspicious_update")]
    md += ["", "## What changed", ""] + ([f"- **{f['type']}**: {f['summary']}" for f in changed]
                                         or ["- no baseline supplied, or no changes found"])
    md += ["", "## Dependency graph", "", "```mermaid", mermaid_graph(state), "```"]
    md += ["", "## Remediation plans", "", "| Component | Action | Target | Attempt | Status | Rationale |",
           "|---|---|---|---|---|---|"]
    for p in plans.values():
        md.append(f"| {p['component'].split('/')[-1]} | {p.get('action')} | {p.get('target_version') or ''} | "
                  f"{p.get('attempt', '')} | {p.get('status')} | {(p.get('rationale') or '')[:90]} |")
    md += ["", "## Validation", ""]
    for eco, v in state.get("validation", {}).items():
        md.append(f"- **{eco}**: {'PASS' if v['ok'] else 'FAIL'}; " + ", ".join(
            f"{k} {'ok' if s['ok'] else 'failed'}" for k, s in v["steps"].items()))
        if v.get("ok"):
            md.append(f"  - SBOM diff: +{len(v['sbom_diff']['added'])} / -{len(v['sbom_diff']['removed'])}; "
                      f"residual vulnerable packages: {v['after_scan'] or 'none'}")
    md += ["", "## Source coverage", ""] + [f"- {k}: {v}" for k, v in state.get("coverage", {}).items()]
    md += ["", "## Agent trace", ""]
    for m in state.get("messages", []):
        md.append(f"{m['turn']:>2}. **{m['from']}** → {m['to']}: {m['text']}")
    (out_dir / "guardian-report.md").write_text("\n".join(md))
    return AgentResult(delta={"report": {"dir": str(out_dir), "findings": len(fs)}},
                       summary=f"wrote guardian-report.json/.md, guardian.sarif, guardian-sbom.cdx.json, "
                               f"dependency-graph.mmd to {out_dir}")
