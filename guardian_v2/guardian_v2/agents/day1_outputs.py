"""Day 1 artefacts: enriched CycloneDX 1.6 SBOM with vulnerabilities, a
dependency-graph diagram, and component origin."""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

SEV = lambda s: "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low" if s > 0 else "unknown"


def origin(c: dict) -> dict:
    """Where the component comes from: registry, download host, source repo."""
    lock, reg = c.get("lock") or {}, c.get("registry") or {}
    if c.get("ecosystem") == "npm":
        host = urlparse(lock.get("resolved") or "").hostname
        return {"registry": "registry.npmjs.org", "download_host": host, "resolved": lock.get("resolved"),
                "trusted_host": host in (None, "registry.npmjs.org")}
    if c.get("ecosystem") == "pypi":
        return {"registry": "pypi.org", "download_host": "files.pythonhosted.org", "repo": reg.get("repo"),
                "trusted_host": True}
    return {}


def cyclonedx(state: dict) -> dict:
    comps, edges, fs = state.get("components", {}), state.get("edges", []), state.get("findings", {})
    children: dict[str, list[str]] = {}
    for e in edges:
        children.setdefault(e["from"], []).append(e["to"])
    root = "guardian-app-root"
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"tools": {"components": [{"type": "application", "name": "supply-chain-guardian",
                                               "version": "2.0"}]},
                     "component": {"type": "application", "name": "analyzed-application", "bom-ref": root}},
        "components": [], "dependencies": [], "vulnerabilities": []}
    for purl, c in sorted(comps.items()):
        entry = {"type": "library", "bom-ref": purl, "name": c.get("name"), "version": c.get("version"),
                 "purl": purl, "scope": "required" if c.get("scope") in ("prod", "runtime") else "optional"}
        o = origin(c)
        props = [{"name": "guardian:direct", "value": str(bool(c.get("direct"))).lower()},
                 {"name": "guardian:discovered_in", "value": ",".join(c.get("sources", []))},
                 {"name": "guardian:reachability", "value": (c.get("reachability") or {}).get("state", "unknown")}]
        if o.get("download_host"):
            props.append({"name": "guardian:download_host", "value": o["download_host"]})
        entry["properties"] = props
        if o.get("repo"):
            entry["externalReferences"] = [{"type": "vcs", "url": o["repo"]}]
        bom["components"].append(entry)
    bom["dependencies"].append({"ref": root, "dependsOn": sorted(p for p, c in comps.items() if c.get("direct"))})
    for purl in sorted(comps):
        bom["dependencies"].append({"ref": purl, "dependsOn": sorted(set(children.get(purl, [])) & set(comps))})
    for fid, f in sorted(fs.items()):
        if f.get("type") != "vulnerability" or f["component_purl"] not in comps:
            continue
        cv = f.get("cvss") or {}
        rating = {"source": {"name": ",".join(f.get("sources", []))}, "severity": SEV(cv.get("score") or 0)}
        if cv.get("score") is not None:
            rating.update(score=cv["score"], method="CVSSv31" if "3.1" in (cv.get("vector") or "") else "other")
            if cv.get("vector"):
                rating["vector"] = cv["vector"]
        vid = f["canonical_id"]
        bom["vulnerabilities"].append({
            "bom-ref": fid, "id": vid,
            "source": {"name": "NVD" if vid.startswith("CVE-") else "GitHub" if vid.startswith("GHSA-") else "OSV"},
            "references": [{"id": a, "source": {"name": "alias"}} for a in f.get("aliases", [])],
            "ratings": [rating], "description": (f.get("summary") or "")[:500],
            "recommendation": f"Fixed in {f['recommended_fix']}" if f.get("recommended_fix") else "No fix published",
            "affects": [{"ref": f["component_purl"]}],
            "properties": [{"name": "guardian:risk_score", "value": str(f.get("score"))},
                           {"name": "guardian:dependency_path",
                            "value": " > ".join((f.get("paths") or [[]])[0])}]})
    return bom


def mermaid_graph(state: dict) -> str:
    """Dependency graph; vulnerable nodes red, anomalous nodes orange."""
    comps, edges, fs = state.get("components", {}), state.get("edges", []), state.get("findings", {})
    vuln = {f["component_purl"] for f in fs.values() if f.get("type") == "vulnerability"}
    anom = {f["component_purl"] for f in fs.values() if f.get("type") not in ("vulnerability", "environment_only",
                                                                            "dependency_added")}
    nid = lambda p: re.sub(r"[^A-Za-z0-9]", "_", p)
    count = {}
    for f in fs.values():
        if f.get("type") == "vulnerability":
            count[f["component_purl"]] = count.get(f["component_purl"], 0) + 1
    lines = ["flowchart LR", '  app(["application"])']
    for p, c in sorted(comps.items()):
        label = f"{c.get('name')}@{c.get('version')}" + (f"<br/>{count[p]} vulns" if p in count else "")
        lines.append(f'  {nid(p)}["{label}"]')
    for p, c in sorted(comps.items()):
        if c.get("direct"):
            lines.append(f"  app --> {nid(p)}")
    for e in edges:
        if e["from"] in comps and e["to"] in comps:
            lines.append(f"  {nid(e['from'])} --> {nid(e['to'])}")
    lines += ["  classDef vuln fill:#fde2e2,stroke:#c0392b", "  classDef anomaly fill:#fdebd0,stroke:#d35400"]
    lines += [f"  class {nid(p)} vuln" for p in sorted(vuln - anom)]
    lines += [f"  class {nid(p)} anomaly" for p in sorted(anom)]
    return "\n".join(lines)
