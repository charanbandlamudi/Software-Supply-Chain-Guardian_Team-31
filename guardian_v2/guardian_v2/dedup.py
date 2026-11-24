"""Alias de-duplication and cross-source conflict resolution.

Raw records from Grype, OSV, GHSA etc. describe the same issue under different
ids (CVE-2023-25577 == GHSA-xg9f-g7g7-2323 == PYSEC-2023-58). Union-find over
id + aliases gives one advisory per (issue, component), with every source's
view kept so disagreements are visible instead of silently resolved.
"""
from __future__ import annotations

from . import versions as V

# Severity source preference: reviewed GHSA / CNA first, NVD next, scanners last.
SEVERITY_PREFERENCE = ["ghsa", "cna", "nvd", "osv", "osv-scanner", "grype", "trivy"]


class _UnionFind:
    def __init__(self):
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def canonical_id(ids: set[str]) -> str:
    """CVE > GHSA > anything else (PYSEC, RUSTSEC, GO, MAL...), then lexical."""
    def rank(i: str):
        u = i.upper()
        return (0 if u.startswith("CVE-") else 1 if u.startswith("GHSA-") else 2, u)
    return sorted(ids, key=rank)[0]


def _min_fixed_above(eco: str, current: str, fixed: list[str]) -> str | None:
    cur = V.parse(eco, current)
    above = [f for f in fixed if V.parse(eco, f) > cur]
    return min(above, key=lambda f: V.parse(eco, f)) if above else None


def merge_advisories(raw: list[dict]) -> dict[str, dict]:
    """raw record schema (one per source per component):
      {source, id, aliases[], purl, ranges[] | None, fixed[], cvss: {version, vector, score} | None,
       severity, summary, evidence_id, withdrawn: bool}
    ranges=None means the source already did the version match itself (e.g. Grype).
    """
    uf = _UnionFind()
    for r in raw:
        uf.find(r["id"])
        for a in r.get("aliases", []):
            uf.union(r["id"], a)

    groups: dict[tuple[str, str], list[dict]] = {}
    for r in raw:
        if r.get("npm_range") and not r.get("ranges"):
            r = {**r, "ranges": [{"native": r["npm_range"]}]}
        if r.get("withdrawn"):
            continue
        groups.setdefault((uf.find(r["id"]), r["purl"]), []).append(r)

    merged: dict[str, dict] = {}
    for (_, purl), recs in groups.items():
        eco, current = V.ecosystem_of(purl), V.version_of(purl)
        ids = {r["id"] for r in recs} | {a for r in recs for a in r.get("aliases", [])}
        cid = canonical_id(ids)

        # Per-source affected verdict: sources with ranges are re-evaluated
        # deterministically; range-less sources (scanners) stand on their match.
        verdicts = {}
        for r in recs:
            if r.get("ranges"):
                verdicts[r["source"]] = V.is_affected(eco, current, r["ranges"])
            else:
                verdicts[r["source"]] = True
        if not any(verdicts.values()):
            continue  # every source agrees this version is not affected

        # Conservative fix: the highest per-source "first fixed above current".
        per_source_fix = {}
        for r in recs:
            f = _min_fixed_above(eco, current, r.get("fixed", [])) if current else None
            if f:
                per_source_fix[r["source"]] = f
        fix_values = set(per_source_fix.values())
        recommended_fix = (max(fix_values, key=lambda f: V.parse(eco, f)) if fix_values else None)

        cvss_by_source = {r["source"]: r["cvss"] for r in recs if r.get("cvss")}
        chosen = next((cvss_by_source[s] for s in SEVERITY_PREFERENCE if s in cvss_by_source),
                      next(iter(cvss_by_source.values()), None))
        severities = {r["source"]: (r.get("severity") or "").upper() for r in recs if r.get("severity")}

        conflicts = []
        if len(set(verdicts.values())) > 1:
            conflicts.append({"field": "affected", "by_source": verdicts})
        if len(fix_values) > 1:
            conflicts.append({"field": "fixed_version", "by_source": per_source_fix})
        if len(set(severities.values())) > 1:
            conflicts.append({"field": "severity", "by_source": severities})

        merged[f"{cid}::{purl}"] = {
            "canonical_id": cid,
            "aliases": sorted(ids - {cid}),
            "purl": purl,
            "sources": sorted({r["source"] for r in recs}),
            "affected_by_source": verdicts,
            "recommended_fix": recommended_fix,
            "fix_by_source": per_source_fix,
            "ranges_by_source": {r["source"]: r["ranges"] for r in recs if r.get("ranges")},
            "cvss": chosen,
            "cvss_by_source": cvss_by_source,
            "severity_by_source": severities,
            "summary": next((r["summary"] for r in recs if r.get("summary")), ""),
            "evidence_ids": sorted({r["evidence_id"] for r in recs if r.get("evidence_id")}),
            "source_conflicts": conflicts,
        }
    return merged
