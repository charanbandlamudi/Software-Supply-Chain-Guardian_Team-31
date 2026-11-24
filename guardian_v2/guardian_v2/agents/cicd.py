"""Container & CI/CD agent: Dockerfile and GitHub Actions hygiene."""
from __future__ import annotations

import re
from pathlib import Path

from ..evidence import make_evidence
from .base import AgentResult

SHA = re.compile(r"@[0-9a-f]{40}$")


def run(state: dict, task: dict) -> AgentResult:
    inp, findings, evidence = state.get("inputs", {}), {}, {}

    def add(kind, target, line_no, line, detail, base):
        eid, ev = make_evidence("file_excerpt", "cicd", f"{target}:{line_no}", line)
        evidence[eid] = ev
        findings[f"{kind.upper()}::{target}:{line_no}"] = {
            "type": kind, "component_purl": f"file:{target}", "status": "open",
            "canonical_id": kind.upper(), "aliases": [], "sources": ["guardian-detector"],
            "summary": detail, "calibrated_base": base, "evidence_ids": [eid],
            "location": {"file": target, "line": line_no}, "paths": []}

    for df in inp.get("dockerfiles", []):
        for i, line in enumerate(Path(df).read_text().splitlines(), 1):
            m = re.match(r"\s*FROM\s+(\S+)", line, re.I)
            if m and "@sha256:" not in m.group(1) and m.group(1).lower() != "scratch":
                add("unpinned_base_image", df, i, line,
                    f"Base image {m.group(1)} is referenced by tag, not digest; the tag can be re-pointed.", 5.5)
    for wf in inp.get("workflows", []):
        text = Path(wf).read_text()
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            m = re.search(r"uses:\s*([^\s#]+)", line)
            if m and not m.group(1).startswith("./") and not SHA.search(m.group(1)):
                add("unpinned_action", wf, i, line,
                    f"Action {m.group(1)} is pinned to a tag/branch, not a commit SHA "
                    f"(tags were re-pointed in the tj-actions/changed-files compromise, CVE-2025-30066).",
                    7.0 if "tj-actions" in m.group(1) else 5.0)
        if "pull_request_target" in text and re.search(r"head\.(sha|ref)", text):
            i = next(n for n, l in enumerate(lines, 1) if "pull_request_target" in l)
            add("dangerous_workflow", wf, i, lines[i - 1],
                "pull_request_target checks out untrusted PR code with repository secrets available.", 8.0)
        if re.search(r"permissions:\s*write-all", text):
            i = next(n for n, l in enumerate(lines, 1) if "write-all" in l)
            add("excessive_permissions", wf, i, lines[i - 1], "Workflow token has write-all permissions.", 6.0)
    own = len(findings)
    extra = ""
    if inp.get("trivy_report"):
        from ..sources.scanners import trivy_repo_findings
        tf, tev = trivy_repo_findings(inp["trivy_report"])
        findings.update(tf)
        evidence.update(tev)
        nm = sum(1 for f in tf.values() if f["type"] == "misconfiguration")
        extra = f"; Trivy: {nm} misconfigurations, {len(tf) - nm} secrets (values redacted)"
    return AgentResult(delta={"findings": findings, "evidence": evidence},
                       summary=f"{own} container/CI findings in "
                               f"{len(inp.get('dockerfiles', [])) + len(inp.get('workflows', []))} files" + extra)
