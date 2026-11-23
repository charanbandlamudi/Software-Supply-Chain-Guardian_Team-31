"""Normalize OSV.dev vulnerability JSON (from /v1/vulns/{id}) into raw advisory
records. Plug your existing OSV querybatch code in front of this."""
from __future__ import annotations

from .. import versions as V

_OSV_ECOSYSTEM = {"pypi": "PyPI", "npm": "npm", "maven": "Maven", "golang": "Go",
                  "nuget": "NuGet", "gem": "RubyGems", "cargo": "crates.io", "composer": "Packagist"}


def normalize(vuln: dict, purl: str, evidence_id: str) -> list[dict]:
    eco = _OSV_ECOSYSTEM.get(V.ecosystem_of(purl))
    name = V.name_of(purl).lower()
    out = []
    for aff in vuln.get("affected", []):
        pkg = aff.get("package", {})
        if pkg.get("ecosystem") != eco or pkg.get("name", "").lower() != name:
            continue
        ranges, fixed = [], []
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue  # GIT ranges are commit hashes, not versions
            cur: dict = {}
            for ev in rng.get("events", []):
                if "introduced" in ev:
                    if cur:
                        ranges.append(cur)
                    cur = {"introduced": ev["introduced"]}
                elif "fixed" in ev:
                    cur["fixed"] = ev["fixed"]
                    fixed.append(ev["fixed"])
                elif "last_affected" in ev:
                    cur["last_affected"] = ev["last_affected"]
            if cur:
                ranges.append(cur)
        explicit = aff.get("versions") or []
        if not ranges and explicit:  # version-list-only advisories
            ranges = [{"introduced": v, "last_affected": v} for v in explicit]
        sev = next((s for s in vuln.get("severity", []) if s.get("type", "").startswith("CVSS")), None)
        out.append({
            "source": "osv", "id": vuln["id"], "aliases": vuln.get("aliases", []), "purl": purl,
            "ranges": ranges or None, "fixed": fixed,
            # OSV stores the vector; compute the numeric score with the `cvss` package if needed.
            "cvss": {"vector": sev["score"], "score": None} if sev else None,
            "severity": (vuln.get("database_specific") or {}).get("severity"),
            "summary": vuln.get("summary") or vuln.get("details", "")[:400],
            "evidence_id": evidence_id, "withdrawn": bool(vuln.get("withdrawn")),
            "malicious": vuln["id"].startswith("MAL-"),
        })
    return out
