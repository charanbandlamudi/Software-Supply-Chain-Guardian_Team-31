"""GitHub Advisory Database worker (REST global advisories endpoint).

GET https://api.github.com/advisories?ecosystem=pip&affects=werkzeug@2.0.1
60 req/h unauthenticated, 5,000 req/h with GITHUB_TOKEN. Uses only a
read-only token; the token never reaches an LLM prompt.
"""
from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .. import versions as V
from ..evidence import make_evidence

ECOSYSTEM = {"pypi": "pip", "npm": "npm", "maven": "maven", "golang": "go",
             "nuget": "nuget", "gem": "rubygems", "cargo": "rust", "composer": "composer"}


def _http_get(url: str) -> list | dict:
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    if os.getenv("GITHUB_TOKEN"):
        req.add_header("Authorization", f"Bearer {os.environ['GITHUB_TOKEN']}")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read())


def _ranges_from_spec(spec: str) -> list[dict]:
    """'>= 2.0.0, < 2.2.3' -> [{"introduced": "2.0.0", "fixed": "2.2.3"}]"""
    r: dict = {"introduced": "0"}
    for part in (p.strip() for p in (spec or "").split(",")):
        if part.startswith(">="):
            r["introduced"] = part[2:].strip()
        elif part.startswith("<="):
            r["last_affected"] = part[2:].strip()
        elif part.startswith("<"):
            r["fixed"] = part[1:].strip()
        elif part.startswith("="):
            r["introduced"] = r["last_affected"] = part.lstrip("= ").strip()
    return [r]


def _one(purl: str, http_get) -> tuple[list, dict]:
    eco = ECOSYSTEM.get(V.ecosystem_of(purl))
    ver = V.version_of(purl)
    if not eco or not ver:
        return [], {}
    name = V.name_of(purl).replace("%40", "@")
    url = "https://api.github.com/advisories?" + urllib.parse.urlencode(
        {"ecosystem": eco, "affects": f"{name}@{ver}", "per_page": 100})
    data = http_get(url)
    eid, ev = make_evidence("api_response", "ghsa", url, data)
    raw = []
    for adv in data:
        for vuln in adv.get("vulnerabilities", []):
            pkg = (vuln.get("package") or {}).get("name", "")
            if pkg.lower() != name.lower():
                continue
            cvss = (adv.get("cvss_severities") or {}).get("cvss_v4") or {}
            if not cvss.get("score"):
                cvss = (adv.get("cvss_severities") or {}).get("cvss_v3") or adv.get("cvss") or {}
            raw.append({
                "source": "ghsa", "id": adv["ghsa_id"],
                "aliases": [adv["cve_id"]] if adv.get("cve_id") else [],
                "purl": purl,
                "ranges": _ranges_from_spec(vuln.get("vulnerable_version_range", "")),
                "fixed": [vuln["first_patched_version"]] if vuln.get("first_patched_version") else [],
                "cvss": {"vector": cvss.get("vector_string"), "score": cvss.get("score")}
                        if cvss.get("score") else None,
                "severity": adv.get("severity"), "summary": adv.get("summary", ""),
                "evidence_id": eid, "withdrawn": bool(adv.get("withdrawn_at")),
            })
    return raw, {eid: ev}


def collect(purls: list[str], http_get=_http_get, workers: int = 8) -> dict:
    raw, evidence, errors = [], {}, 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for fut in [pool.submit(_one, p, http_get) for p in purls]:
            try:
                r, e = fut.result()
                raw += r
                evidence.update(e)
            except Exception:
                errors += 1
    status = "ok" if not errors else f"partial ({errors}/{len(purls)} lookups failed)"
    return {"raw_advisories": raw, "evidence": evidence, "coverage": {"source:ghsa": status}}
