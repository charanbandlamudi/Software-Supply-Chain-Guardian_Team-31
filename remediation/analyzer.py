from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable


def normalize_ecosystem(artifact: dict) -> str:
    artifact_type = str(artifact.get("type") or "").lower()
    purl = str(artifact.get("purl") or "")

    if artifact_type in ("npm", "javascript") or purl.startswith("pkg:npm/"):
        return "npm"
    if artifact_type in ("python", "pypi") or purl.startswith("pkg:pypi/"):
        return "pip"
    if artifact_type in ("maven", "java") or purl.startswith("pkg:maven/"):
        return "maven"
    if artifact_type in ("cargo", "rust") or purl.startswith("pkg:cargo/"):
        return "cargo"
    return "unsupported"


def _unique(values: Iterable[str | None]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def extract_grype_findings(grype_path: str | Path) -> list[dict]:
    data = json.loads(Path(grype_path).read_text(encoding="utf-8"))
    findings: list[dict] = []

    for match in data.get("matches", []):
        artifact = match.get("artifact") or {}
        vulnerability = match.get("vulnerability") or {}
        name = artifact.get("name")
        version = artifact.get("version")
        if not name or not version:
            continue

        fix = vulnerability.get("fix") or {}
        fixed_versions = _unique(fix.get("versions") or [])
        suggested_versions: list[str] = []
        for detail in match.get("matchDetails") or []:
            detail_fix = detail.get("fix") or {}
            suggested_versions.extend(detail_fix.get("suggestedVersion") or [] if
                                      isinstance(detail_fix.get("suggestedVersion"), list)
                                      else ([detail_fix.get("suggestedVersion")]
                                            if detail_fix.get("suggestedVersion") else []))

        aliases = _unique(
            [vulnerability.get("id")]
            + [item.get("id") for item in match.get("relatedVulnerabilities") or []]
        )
        findings.append({
            "package": name,
            "current_version": version,
            "purl": artifact.get("purl"),
            "ecosystem": normalize_ecosystem(artifact),
            "severity": (vulnerability.get("severity") or "UNKNOWN").upper(),
            "vulnerability_id": vulnerability.get("id"),
            "aliases": aliases,
            "fixed_versions": fixed_versions,
            "suggested_versions": _unique(suggested_versions),
        })

    return findings

