"""PyPI JSON API. /pypi/<name>/<version>/json carries a `vulnerabilities`
list sourced from OSV (PYSEC/GHSA records with aliases and fixed_in)."""
from __future__ import annotations

from .http import fetch_json

BASE = "https://pypi.org/pypi"


def version_info(name: str, version: str):
    return fetch_json(f"{BASE}/{name}/{version}/json", "pypi")


def project_info(name: str):
    return fetch_json(f"{BASE}/{name}/json", "pypi")


def release_list(project: dict) -> list[dict]:
    out = []
    for ver, files in (project or {}).get("releases", {}).items():
        if not files:
            continue
        out.append({"version": ver, "yanked": all(f.get("yanked") for f in files),
                    "uploaded": min(f.get("upload_time_iso_8601", "") for f in files)})
    return out


def advisories_for(name: str, version: str, purl: str) -> tuple[list[dict], dict]:
    """Raw advisory records (guardian schema) for an exact version."""
    data, eid, ev = version_info(name, version)
    raw = []
    for v in (data or {}).get("vulnerabilities", []):
        raw.append({"source": "pypi-osv", "id": v["id"], "aliases": v.get("aliases") or [],
                    "purl": purl, "ranges": None, "fixed": v.get("fixed_in") or [],
                    "cvss": None, "severity": None,
                    "summary": v.get("summary") or (v.get("details") or "")[:400],
                    "evidence_id": eid, "withdrawn": bool(v.get("withdrawn"))})
    return raw, {eid: ev}
