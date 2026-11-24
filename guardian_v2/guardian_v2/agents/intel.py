"""Vulnerability Intelligence and Exploit Intelligence agents (multi-source)."""
from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor

from ..dedup import merge_advisories
from ..graph_paths import all_paths, introducing_direct
from ..sources import ghsa as ghsa_source
from ..sources import grype as grype_source
from ..tools import exploit, npm, osv, pypi
from ..tools.http import HttpError
from .base import AgentResult


def _pypi_worker(comps):
    raw, ev, errors = [], {}, []
    def one(c):
        return pypi.advisories_for(c["name"], c["version"], c["purl"])
    with ThreadPoolExecutor(8) as pool:
        for c, fut in [(c, pool.submit(one, c)) for c in comps]:
            try:
                r, e = fut.result()
                raw += r
                ev.update(e)
            except HttpError as exc:
                errors.append(f"{c['name']}: {exc}")
    return raw, ev, errors


def _npm_worker(comps):
    if not comps:
        return [], {}, []
    by_name: dict[str, list[str]] = {}
    for c in comps:
        by_name.setdefault(c["name"], []).append(c["version"])
    data, eid, ev = npm.bulk_advisories(by_name)
    raw = []
    for c in comps:
        raw += npm.to_raw(c["name"], c["version"], c["purl"], (data or {}).get(c["name"], []), eid)
    return raw, {eid: ev}, []


def run_vuln_intel(state: dict, task: dict) -> AgentResult:
    comps = state.get("components", {})
    py = [c for c in comps.values() if c.get("ecosystem") == "pypi" and c.get("version")]
    js = [c for c in comps.values() if c.get("ecosystem") == "npm" and c.get("version")]
    jobs = {"pypi-osv": lambda: _pypi_worker(py), "npm-audit": lambda: _npm_worker(js),
            "osv": lambda: (*osv.advisories_for(py + js), [])}
    if os.getenv("GITHUB_TOKEN") or task.get("force_ghsa"):
        def gh():
            out = ghsa_source.collect([c["purl"] for c in py + js])
            return out["raw_advisories"], out["evidence"], (
                [] if out["coverage"]["source:ghsa"] == "ok" else [out["coverage"]["source:ghsa"]])
        jobs["ghsa"] = gh
    from ..sources import scanners as scanner_sources
    for key, name, fn in (("osv_scanner_report", "osv-scanner", scanner_sources.collect_osv_scanner),
                          ("trivy_report", "trivy", scanner_sources.collect_trivy)):
        if state.get("inputs", {}).get(key):
            def job(path=state["inputs"][key], fn=fn):
                out = fn(path)
                return out["raw_advisories"], out["evidence"], []
            jobs[name] = job
    if state.get("inputs", {}).get("grype_report"):
        def gr():
            out = grype_source.collect(state["inputs"]["grype_report"])
            return out["raw_advisories"], out["evidence"], []
        jobs["grype"] = gr

    raw, evidence, coverage = [], {}, {}
    with ThreadPoolExecutor(len(jobs)) as pool:        # sources run in parallel
        futures = {name: pool.submit(fn) for name, fn in jobs.items()}
        for name, fut in futures.items():
            try:
                r, e, errs = fut.result()
                raw += r
                evidence.update(e)
                coverage[f"source:{name}"] = "ok" if not errs else f"partial: {errs[:2]}"
            except Exception as exc:
                coverage[f"source:{name}"] = f"failed: {exc}"
    if "ghsa" not in jobs:
        coverage["source:ghsa"] = "skipped: set GITHUB_TOKEN (unauthenticated limit is 60 req/h)"

    merged = merge_advisories(raw)
    edges = state.get("edges", [])
    findings = {}
    for key, adv in merged.items():
        paths = all_paths(comps, edges, adv["purl"])
        findings[f"VULN::{key}"] = {
            "type": "vulnerability", "component_purl": adv["purl"], "status": "open",
            **{k: adv[k] for k in ("canonical_id", "aliases", "sources", "recommended_fix", "cvss",
                                   "source_conflicts", "summary", "evidence_ids")},
            "paths": paths, "introduced_by": introducing_direct(paths),
            "direct": bool(comps.get(adv["purl"], {}).get("direct")),
        }
    per_comp: dict[str, int] = {}
    for f in findings.values():
        per_comp[f["component_purl"]] = per_comp.get(f["component_purl"], 0) + 1
    top = ", ".join(f"{p.split('/')[-1]}={n}" for p, n in sorted(per_comp.items(), key=lambda x: -x[1])[:6])
    return AgentResult(
        delta={"raw_advisories": raw, "advisories": merged, "findings": findings,
               "evidence": evidence, "coverage": coverage},
        summary=f"{len(raw)} raw advisory records from {sum(1 for v in coverage.values() if v == 'ok')}/"
                f"{len(jobs)} sources -> {len(merged)} unique "
                f"vulnerabilities on {len(per_comp)} packages ({top})",
        metrics={"raw": len(raw), "unique": len(merged)})


def run_exploit_intel(state: dict, task: dict) -> AgentResult:
    findings = {fid: f for fid, f in state.get("findings", {}).items() if f["type"] == "vulnerability"}
    cve_of = {fid: next((i for i in [f["canonical_id"], *f.get("aliases", [])] if i.startswith("CVE-")), None)
              for fid, f in findings.items()}
    cves = sorted({c for c in cve_of.values() if c})
    coverage, evidence, kev, epss = {}, {}, {}, {}
    try:
        kev, eid, ev = exploit.kev_catalog()
        evidence[eid] = {**ev, "payload": f"<KEV catalog, {len(kev)} entries, sha256 {ev['sha256']}>"}
        coverage["source:cisa-kev"] = f"ok ({len(kev)} entries)"
    except Exception as exc:
        coverage["source:cisa-kev"] = f"failed: {exc}"
        eid = None
    try:
        if cves:
            epss, e2, ev2 = exploit.epss(cves)
            evidence[e2] = ev2
        coverage["source:epss"] = f"ok ({len(epss)}/{len(cves)})"
    except Exception as exc:
        coverage["source:epss"] = f"failed: {str(exc)[:120]}"
    out = {}
    for fid, cve in cve_of.items():
        upd = {"cve": cve, "kev": bool(cve and cve in kev), "epss": epss.get(cve) if cve else None}
        if cve and cve in kev:
            upd["kev_record"] = {k: kev[cve].get(k) for k in ("dateAdded", "dueDate", "knownRansomwareCampaignUse")}
            if eid:
                upd["evidence_ids"] = [eid]
        out[fid] = upd
    n_kev = sum(1 for v in out.values() if v["kev"])
    return AgentResult(delta={"findings": out, "evidence": evidence, "coverage": coverage},
                       summary=f"{len(cves)} CVEs checked: {n_kev} in CISA KEV, EPSS for {len(epss)}",
                       metrics={"kev": n_kev})
