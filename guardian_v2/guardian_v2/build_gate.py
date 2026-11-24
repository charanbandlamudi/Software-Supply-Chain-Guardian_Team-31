"""Deterministic build gate: unresolved ACT findings, pins, merge and publish actions."""
from __future__ import annotations

import re


UNPINNED_ACTION_RE = re.compile(r"uses:\\s*[^\\s]+@(main|master|[A-Za-z][A-Za-z0-9_-]*)\\s*$", re.I)


def evaluate(report: dict) -> dict:
    reasons = []
    findings = report.get("findings", [])
    for finding in findings:
        ssvc = finding.get("ssvc")
        if isinstance(ssvc, dict):
            ssvc = ssvc.get("decision")
        if ssvc == "Act" and finding.get("resolution") not in {"approved", "resolved", "validated"}:
            reasons.append(f"unresolved ACT finding: {finding.get('canonical_id', finding.get('id'))}")

    for workflow in report.get("cicd_findings", []):
        text = str(workflow)
        if "@main" in text or "@master" in text:
            reasons.append("unpinned GitHub Action")

    for image in report.get("container_images", []):
        if "@" not in str(image):
            reasons.append(f"unpinned container image: {image}")

    blocked_tools = {"git.merge", "git.push_default", "npm.publish", "pypi.upload",
                     "docker.push_public", "deploy"}
    for action in report.get("requested_actions", []):
        if action in blocked_tools:
            reasons.append(f"public or merge operation blocked: {action}")

    license_violations = report.get("license_violations", [])
    for violation in license_violations:
        reasons.append(f"license policy violation: {violation}")

    return {"allow": not reasons, "deny_reason": sorted(set(reasons))}
