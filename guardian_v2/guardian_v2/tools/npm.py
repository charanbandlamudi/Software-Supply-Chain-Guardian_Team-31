"""npm registry: packuments and the bulk advisory endpoint used by `npm audit`
(GHSA-backed, returns only advisories that affect the versions sent)."""
from __future__ import annotations

import urllib.parse

from .http import fetch_json

REGISTRY = "https://registry.npmjs.org"


def packument(name: str):
    return fetch_json(f"{REGISTRY}/{urllib.parse.quote(name, safe='@')}", "npm")


def bulk_advisories(versions_by_name: dict[str, list[str]]):
    return fetch_json(f"{REGISTRY}/-/npm/v1/security/advisories/bulk", "npm-audit",
                      method="POST", body=versions_by_name)


def to_raw(name: str, version: str, purl: str, advisories: list[dict], eid: str) -> list[dict]:
    raw = []
    for a in advisories:
        ghsa = a.get("url", "").rsplit("/", 1)[-1]
        rng = a.get("vulnerable_versions", "")
        raw.append({"source": "npm-audit", "id": ghsa or str(a.get("id")), "aliases": [],
                    "purl": purl, "ranges": None, "npm_range": rng, "fixed": [],
                    "cvss": ({"vector": a["cvss"].get("vectorString"), "score": a["cvss"].get("score")}
                             if (a.get("cvss") or {}).get("score") else None),
                    "severity": a.get("severity"), "summary": a.get("title", ""),
                    "evidence_id": eid, "withdrawn": False})
    return raw
