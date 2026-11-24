"""Package Reputation agent: registry metadata for every component."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from ..tools import npm, pypi
from .base import AgentResult


def _pypi(c):
    data, eid, ev = pypi.project_info(c["name"])
    if data is None:
        return {"registry": {"exists": False}}, {eid: ev}
    rel = pypi.release_list(data)
    cur = next((r for r in rel if r["version"] == c["version"]), None)
    return {"registry_versions": rel, "registry": {
        "exists": True, "version_published": cur is not None, "yanked": bool(cur and cur["yanked"]),
        "uploaded": cur and cur["uploaded"], "latest": data["info"]["version"],
        "repo": (data["info"].get("project_urls") or {}).get("Source")},
        "evidence_ids": [eid]}, {eid: {**ev, "payload": ev["payload"][:2000]}}


def _npm(c):
    data, eid, ev = npm.packument(c["name"])
    if data is None:
        return {"registry": {"exists": False}}, {eid: ev}
    versions = data.get("versions", {})
    meta = versions.get(c["version"], {})
    latest = (data.get("dist-tags") or {}).get("latest")
    rel = [{"version": v, "yanked": bool(m.get("deprecated")), "uploaded": data.get("time", {}).get(v)}
           for v, m in versions.items()]
    scripts = {k: v for k, v in (meta.get("scripts") or {}).items()
               if k in ("preinstall", "install", "postinstall")}
    return {"registry_versions": rel, "registry": {
        "exists": True, "version_published": bool(meta), "latest": latest,
        "security_holding": latest == "0.0.1-security" or "security holding" in (data.get("description") or "").lower(),
        "deprecated": meta.get("deprecated"), "integrity": (meta.get("dist") or {}).get("integrity"),
        "install_scripts": scripts, "maintainers": len(data.get("maintainers") or []),
        "uploaded": data.get("time", {}).get(c["version"])},
        "evidence_ids": [eid]}, {eid: {**ev, "payload": ev["payload"][:2000]}}


def run(state: dict, task: dict) -> AgentResult:
    comps = state.get("components", {})
    # Optional inputs["reputation_focus"] limits the default scope (full packuments for
    # 1000+ packages are too heavy on slow links); explicit handoff focus always wins.
    scope = state.get("inputs", {}).get("reputation_focus")
    focus = set(task.get("focus", [])) or (set(scope) & set(comps) if scope else set(comps))
    out, evidence, errors = {}, {}, []
    def one(c):
        return (_pypi if c["ecosystem"] == "pypi" else _npm)(c)
    with ThreadPoolExecutor(8) as pool:
        futs = {p: pool.submit(one, comps[p]) for p in focus
                if comps[p].get("ecosystem") in ("pypi", "npm")}
        for purl, fut in futs.items():
            try:
                upd, ev = fut.result()
                out[purl] = upd
                evidence.update(ev)
            except Exception as exc:
                errors.append(f"{purl}: {exc}")
    holding = [p for p, u in out.items() if (u.get("registry") or {}).get("security_holding")]
    return AgentResult(delta={"components": out, "evidence": evidence,
                              "coverage": {"reputation": f"{len(out)} ok, {len(errors)} failed"}},
                       summary=f"registry metadata for {len(out)} packages"
                               + (f"; security-holding packages: {holding}" if holding else ""),
                       metrics={"checked": len(out), "errors": len(errors)})
