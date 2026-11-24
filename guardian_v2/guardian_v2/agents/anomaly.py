"""Supply-Chain Anomaly agent: non-CVE risks, all from deterministic checks."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from ..evidence import make_evidence
from .base import AgentResult, handoff

POPULAR = {
    "npm": ["lodash", "react", "express", "chalk", "debug", "axios", "moment", "request", "commander",
            "mkdirp", "minimist", "async", "underscore", "uuid", "webpack", "typescript", "jquery",
            "colors", "yargs", "glob", "semver", "rimraf", "dotenv", "cross-env", "electron", "eslint"],
    "pypi": ["requests", "flask", "django", "numpy", "pandas", "urllib3", "werkzeug", "jinja2", "boto3",
             "setuptools", "pyyaml", "cryptography", "pillow", "scipy", "matplotlib", "colorama",
             "python-dateutil", "certifi", "idna", "click", "beautifulsoup4", "selenium", "tensorflow"],
}
TRUSTED_HOSTS = {"registry.npmjs.org", "files.pythonhosted.org", "pypi.org"}

# Calibrated base scores (0-10) for findings without CVSS. Heuristics; tune on labelled data.
BASE = {"malicious_package": 9.5, "integrity_mismatch": 8.5, "untrusted_resolved_url": 7.5,
        "typosquat_suspect": 7.0, "unpublished_version": 7.0, "install_script": 5.0,
        "yanked_or_deprecated": 4.0, "environment_only": 1.0, "unexpected_dependency": 5.0,
        "lockfile_tampering": 8.5, "dependency_confusion": 9.0, "suspicious_update": 6.0,
        "dependency_added": 2.0}
MIN_RELEASE_AGE_DAYS = 14
ESTABLISHED_MIN_VERSIONS = 20      # typosquat check: long-lived projects are not squats
ESTABLISHED_MIN_AGE_DAYS = 730   # cooling-off window: most hijacked releases are pulled within days


def _lock_entries(path: str) -> dict[str, dict]:
    lock = json.loads(Path(path).read_text())
    return {k.split("node_modules/")[-1]: v for k, v in lock.get("packages", {}).items() if k}


def _age_days(ts: str | None, now: datetime) -> float | None:
    if not ts:
        return None
    try:
        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (now - (t if t.tzinfo else t.replace(tzinfo=timezone.utc))).total_seconds() / 86400


def _osa(a: str, b: str) -> int:
    """Optimal string alignment (Damerau-Levenshtein with adjacent transpositions)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def typosquat_target(name: str, ecosystem: str) -> str | None:
    n = name.lower().replace("_", "-")
    for p in POPULAR.get(ecosystem, []):
        if n != p and abs(len(n) - len(p)) <= 2 and _osa(n, p) <= (1 if len(p) <= 5 else 2):
            return p
    return None


def run(state: dict, task: dict) -> AgentResult:
    comps, findings, evidence, requests = state.get("components", {}), {}, {}, []

    def add(kind, purl, detail, facts, sev=None):
        eid, ev = make_evidence("detector_output", f"anomaly-{kind}", purl, facts)
        evidence[eid] = ev
        c = comps[purl]
        findings[f"{kind.upper()}::{purl}"] = {
            "type": kind, "component_purl": purl, "status": "open", "canonical_id": kind.upper(),
            "aliases": [], "sources": ["guardian-detector"], "summary": detail,
            "calibrated_base": sev if sev is not None else BASE[kind],
            "evidence_ids": [eid, *c.get("evidence_ids", [])[:1]], "facts": facts,
            "direct": c.get("direct", False), "paths": [],
        }

    suspicious, established = [], []
    for purl, c in comps.items():
        reg, lock, eco = c.get("registry") or {}, c.get("lock") or {}, c.get("ecosystem")
        if reg.get("security_holding"):
            add("malicious_package", purl,
                f"{c['name']} has been replaced on the registry by a security holding package; "
                f"the locked version {c['version']} was removed as malicious.",
                {"registry_latest": reg.get("latest"), "locked_version": c["version"]})
            suspicious.append(purl)
        elif reg.get("exists") and reg.get("version_published") is False:
            add("unpublished_version", purl,
                f"{c['name']}@{c['version']} is locked but no longer published on the registry.",
                {"locked_version": c["version"]})
            suspicious.append(purl)
        target = typosquat_target(c["name"], eco)
        if target:
            # Name similarity alone is not evidence of malice (e.g. cypress vs express). Skip packages
            # whose registry history shows an established project; flag the rest as unverified suspects.
            rel = c.get("registry_versions") or []
            first = min((r["uploaded"] for r in rel if r.get("uploaded")), default=None)
            age = _age_days(first, datetime.now(timezone.utc)) if first else None
            if len(rel) >= ESTABLISHED_MIN_VERSIONS and age is not None and age > ESTABLISHED_MIN_AGE_DAYS:
                established.append(f"{c['name']} (~{target}: {len(rel)} versions, {int(age / 365)}y)")
            else:
                basis = (f"{len(rel)} published versions, first release {int(age)} days ago" if rel and age is not None
                         else "no registry history checked")
                add("typosquat_suspect", purl,
                    f"'{c['name']}' is within edit distance 2 of popular package '{target}' ({basis}); "
                    f"unverified: name similarity alone does not prove malicious intent.",
                    {"name": c["name"], "looks_like": target, "registry_versions": len(rel), "age_days": age})
                suspicious.append(purl)
        if lock.get("resolved"):
            host = urlparse(lock["resolved"]).hostname
            if host not in TRUSTED_HOSTS:
                add("untrusted_resolved_url", purl, f"Lockfile resolves {c['name']} from untrusted host {host}.",
                    {"resolved": lock["resolved"]})
                suspicious.append(purl)
        if lock.get("integrity") and reg.get("integrity") and lock["integrity"] != reg["integrity"]:
            add("integrity_mismatch", purl,
                f"Lockfile integrity for {c['name']}@{c['version']} differs from the registry's published hash.",
                {"lockfile": lock["integrity"][:40] + "...", "registry": reg["integrity"][:40] + "..."})
            suspicious.append(purl)
        if lock.get("hasInstallScript") or reg.get("install_scripts"):
            add("install_script", purl, f"{c['name']} runs code at install time.",
                {"lockfile_flag": lock.get("hasInstallScript"), "scripts": reg.get("install_scripts")})
        if reg.get("yanked") or reg.get("deprecated"):
            add("yanked_or_deprecated", purl, f"{c['name']}@{c['version']} is yanked or deprecated.",
                {"yanked": reg.get("yanked"), "deprecated": reg.get("deprecated")})
        if c.get("scope") == "environment":
            add("environment_only", purl,
                f"{c['name']} is installer tooling in the environment, not an application dependency.",
                {"scope": "environment"})

    # ---- release age: very new versions are the window in which hijacks happen ----
    now = datetime.now(timezone.utc)
    min_age = state.get("inputs", {}).get("min_release_age_days", MIN_RELEASE_AGE_DAYS)
    for purl, c in comps.items():
        age = _age_days((c.get("registry") or {}).get("uploaded"), now)
        if age is not None and age < min_age:
            add("suspicious_update", purl,
                f"{c['name']}@{c['version']} was published {age:.1f} days ago (< {min_age}-day cooling-off window).",
                {"published": c["registry"]["uploaded"], "age_days": round(age, 1)})

    # ---- dependency confusion: internal names must never resolve from a public registry ----
    internal = state.get("inputs", {}).get("internal_namespaces", [])
    for purl, c in comps.items():
        if any(c["name"].startswith(ns) for ns in internal):
            reg, lock = c.get("registry") or {}, c.get("lock") or {}
            host = urlparse(lock.get("resolved") or "").hostname
            if reg.get("exists") or host in TRUSTED_HOSTS:
                add("dependency_confusion", purl,
                    f"Internal package {c['name']} exists on / resolves from the public registry.",
                    {"public_registry_has_name": reg.get("exists"), "resolved_host": host})
                suspicious.append(purl)

    # ---- lockfile vs baseline: what changed, and was the change explained by the manifest? ----
    inp = state.get("inputs", {})
    if inp.get("npm_lock_baseline") and inp.get("npm_lock"):
        base, cur = _lock_entries(inp["npm_lock_baseline"]), _lock_entries(inp["npm_lock"])
        manifest = json.loads(Path(inp["npm_manifest"]).read_text()).get("dependencies", {}) \
            if inp.get("npm_manifest") else {}
        by_name = {c["name"]: p for p, c in comps.items() if c.get("ecosystem") == "npm"}
        for name, meta in cur.items():
            purl = by_name.get(name)
            if not purl:
                continue
            old = base.get(name)
            if old is None:
                kind = "dependency_added" if name in manifest else "unexpected_dependency"
                add(kind, purl, f"{name}@{meta['version']} is new in the lockfile"
                    + ("" if name in manifest else " and is not declared in package.json") + ".",
                    {"change": "added", "in_manifest": name in manifest})
            elif old.get("version") == meta.get("version") and (
                    old.get("integrity") != meta.get("integrity") or old.get("resolved") != meta.get("resolved")):
                add("lockfile_tampering", purl,
                    f"{name}@{meta['version']}: integrity/resolved URL changed in the lockfile without a version change.",
                    {"baseline": {"integrity": (old.get("integrity") or "")[:30], "resolved": old.get("resolved")},
                     "current": {"integrity": (meta.get("integrity") or "")[:30], "resolved": meta.get("resolved")}})
                suspicious.append(purl)

    # ---- lockfile entries not reachable from any declared dependency ----
    from ..graph_paths import all_paths
    for purl, c in comps.items():
        if c.get("ecosystem") == "npm" and not all_paths(comps, state.get("edges", []), purl, max_paths=1):
            add("unexpected_dependency", purl, f"{c['name']} is in the lockfile but no declared dependency pulls it in.",
                {"reachable_from_root": False})

    for d in state.get("discrepancies", []):
        if d["purl"] in comps and comps[d["purl"]].get("scope") != "environment":
            add("unexpected_dependency", d["purl"], f"Component present in one input only: {d['issue']}.", d)

    # ---- correlation: independent signals on one component reinforce each other ----
    by_comp: dict[str, list[str]] = {}
    for fid, f in findings.items():
        if f["type"] not in ("environment_only", "dependency_added"):
            by_comp.setdefault(f["component_purl"], []).append(fid)
    for purl, fids in by_comp.items():
        types = sorted({findings[x]["type"] for x in fids})
        for fid in fids:
            findings[fid]["corroborating_signals"] = len(types) - 1
            findings[fid]["correlated_with"] = [t for t in types if t != findings[fid]["type"]]

    if suspicious:
        requests.append(handoff("reachability", "suspicious packages found; check whether source code imports them",
                                focus=sorted(set(suspicious))))
    kinds = {}
    for f in findings.values():
        kinds[f["type"]] = kinds.get(f["type"], 0) + 1
    return AgentResult(delta={"findings": findings, "evidence": evidence},
                       summary=f"{len(findings)} non-CVE findings: {kinds}"
                               + (f"; name-similarity cleared as established: {', '.join(established[:5])}" if established else ""),
                       requests=requests, metrics=kinds)
