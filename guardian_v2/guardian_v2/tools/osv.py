"""OSV.dev: querybatch (ids only) then /v1/vulns/{id} for details.
Numeric CVSS base scores are computed from the vector with the `cvss` package."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from ..sources.osv import normalize
from .http import fetch_json

API = "https://api.osv.dev/v1"


def cvss_score(vector: str | None) -> float | None:
    if not vector:
        return None
    try:
        from cvss import CVSS3, CVSS4
        if vector.startswith("CVSS:4"):
            return float(CVSS4(vector).base_score)
        if vector.startswith("CVSS:3"):
            return float(CVSS3(vector).base_score)
    except Exception:
        return None
    return None


def advisories_for(comps: list[dict]) -> tuple[list[dict], dict]:
    eco = {"pypi": "PyPI", "npm": "npm"}
    queries = [{"package": {"name": c["name"], "ecosystem": eco[c["ecosystem"]]}, "version": c["version"]}
               for c in comps]
    raw, evidence = [], {}
    for start in range(0, len(queries), 1000):
        data, eid, ev = fetch_json(f"{API}/querybatch", "osv", method="POST",
                                   body={"queries": queries[start:start + 1000]})
        evidence[eid] = ev
        pairs = [(comps[start + i], v["id"]) for i, r in enumerate(data.get("results", []))
                 for v in r.get("vulns", [])]

        def detail(pair):
            c, vid = pair
            vuln, veid, vev = fetch_json(f"{API}/vulns/{vid}", "osv")
            return c, vuln, veid, vev
        with ThreadPoolExecutor(8) as pool:
            for c, vuln, veid, vev in pool.map(detail, pairs):
                evidence[veid] = {**vev, "payload": vev["payload"][:3000]}
                for rec in normalize(vuln, c["purl"], veid):
                    if rec.get("cvss"):
                        rec["cvss"]["score"] = cvss_score(rec["cvss"]["vector"])
                    raw.append(rec)
    return raw, evidence
