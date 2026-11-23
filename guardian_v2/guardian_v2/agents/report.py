"""Report agent: Guardian JSON, Markdown, SARIF 2.1.0 and the agent trace."""
from __future__ import annotations

import json
from pathlib import Path

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
                                            "resolution", "location")} for f in fs],
        "remediation_plans": plans, "approvals": state.get("approvals", []),
        "validation": state.get("validation", {}), "coverage": state.get("coverage", {}),
        "agent_trace": state.get("messages", []),
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
