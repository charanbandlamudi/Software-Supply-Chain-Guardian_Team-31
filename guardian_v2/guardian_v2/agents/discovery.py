"""Discovery agent: SBOM + dependency graphs + lockfiles -> inventory and graph."""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..evidence import make_evidence
from .base import AgentResult

ENV_TOOLS = {"pip", "setuptools", "wheel", "pipdeptree", "distribute"}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _pypi_purl(name: str, version: str) -> str:
    return f"pkg:pypi/{_norm(name)}@{version}"


def _npm_purl(name: str, version: str) -> str:
    return f"pkg:npm/{name.replace('@', '%40')}@{version}"


def _lock_package_name(path: str) -> str:
    """Return the package name represented by an npm lockfile package path."""
    return path.rsplit("node_modules/", 1)[-1]


def _resolve_lock_dependency(package_path: str, dependency: str, packages: dict) -> str | None:
    """Resolve a dependency using npm's node_modules lookup rules.

    A lockfile can contain several versions of the same package. Looking up by
    name alone silently merged those versions and produced incorrect agent
    edges. Prefer the nearest ancestor's nested node_modules entry, then walk
    toward the root, exactly as Node resolution does for a lockfile path.
    """
    parent = package_path
    while True:
        candidate = f"{parent}/node_modules/{dependency}" if parent else f"node_modules/{dependency}"
        if candidate in packages:
            return candidate
        if not parent:
            return None
        if "/node_modules/" in parent:
            parent = parent.rsplit("/node_modules/", 1)[0]
        else:
            parent = ""


def _read(path: str):
    text = Path(path).read_text(encoding="utf-8-sig")
    return json.loads(text), make_evidence("input_file", "input", path, text)


def _manifest_roots(path: str | None) -> set[str]:
    if not path or not Path(path).exists():
        return set()
    roots = set()
    for line in Path(path).read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.\-]+)", line)
        if m:
            roots.add(_norm(m.group(1)))
    return roots


def run(state: dict, task: dict) -> AgentResult:
    inp = state.get("inputs", {})
    comps: dict[str, dict] = {}
    edges: list[dict] = []
    evidence: dict = {}
    notes = []

    def add(purl, **attrs):
        c = comps.setdefault(purl, {"purl": purl, "sources": []})
        for k, v in attrs.items():
            if k == "sources":
                c["sources"] = sorted(set(c["sources"]) | set(v))
            elif v is not None:
                c[k] = v

    # ---- CycloneDX SBOM ----
    if inp.get("sbom"):
        bom, (eid, ev) = _read(inp["sbom"])
        evidence[eid] = ev
        ref_to_purl = {}
        for c in bom.get("components", []):
            if c.get("purl"):
                ref_to_purl[c.get("bom-ref", c["purl"])] = c["purl"]
                eco = c["purl"].split(":")[1].split("/")[0]
                add(c["purl"], name=_norm(c["name"]) if eco == "pypi" else c["name"],
                    version=c.get("version"), ecosystem=eco, sources=["sbom"],
                    licenses=[l.get("license", {}).get("id") for l in c.get("licenses", [])
                              if l.get("license", {}).get("id")], evidence_ids=[eid])
        root = (bom.get("metadata", {}).get("component") or {}).get("bom-ref")
        for d in bom.get("dependencies", []):
            src = ref_to_purl.get(d["ref"])
            for dep in d.get("dependsOn", []):
                dst = ref_to_purl.get(dep)
                if d["ref"] == root and dst:
                    add(dst, direct=True)
                elif src and dst:
                    edges.append({"from": src, "to": dst, "constraint": None, "source": "sbom"})
        notes.append(f"SBOM {bom.get('bomFormat')} {bom.get('specVersion')}: {len(bom.get('components', []))} components")

    # ---- Python graph (pipdeptree --json) ----
    if inp.get("python_graph"):
        tree, (eid, ev) = _read(inp["python_graph"])
        evidence[eid] = ev
        for node in tree:
            p = node["package"]
            purl = _pypi_purl(p["package_name"], p["installed_version"])
            add(purl, name=_norm(p["package_name"]), version=p["installed_version"],
                ecosystem="pypi", sources=["graph"])
            for d in node.get("dependencies", []):
                dst = _pypi_purl(d["package_name"], d["installed_version"])
                req = d.get("required_version")
                edges.append({"from": purl, "to": dst, "source": "pipdeptree",
                              "constraint": None if req in (None, "Any", "any") else req})
        notes.append(f"pipdeptree: {len(tree)} packages")

    roots = _manifest_roots(inp.get("python_manifest"))
    for purl, c in comps.items():
        if c.get("ecosystem") == "pypi":
            if roots:
                c["direct"] = c.get("name") in roots
            if c.get("name") in ENV_TOOLS:
                c["scope"] = "environment"

    # ---- npm package-lock v2/v3 ----
    if inp.get("npm_lock"):
        lock, (eid, ev) = _read(inp["npm_lock"])
        evidence[eid] = ev
        pk = lock.get("packages", {})
        root = pk.get("", {})
        direct = set(root.get("dependencies", {})) | set(root.get("devDependencies", {}))
        dev_roots = set(root.get("devDependencies", {}))
        path_to_purl = {}
        for path, meta in pk.items():
            if not path:
                continue
            if not meta.get("version"):
                continue
            name = _lock_package_name(path)
            purl = _npm_purl(name, meta["version"])
            path_to_purl[path] = purl
            add(purl, name=name, version=meta["version"], ecosystem="npm", sources=["lockfile"],
                direct=path == f"node_modules/{name}" and name in direct,
                scope="dev" if (meta.get("dev") or (path == f"node_modules/{name}" and name in dev_roots)) else "prod",
                lock={"resolved": meta.get("resolved"), "integrity": meta.get("integrity"),
                      "hasInstallScript": bool(meta.get("hasInstallScript")),
                      "spec": root.get("dependencies", {}).get(name)},
                evidence_ids=[eid])
        for path, meta in pk.items():
            if not path:
                continue
            src = path_to_purl.get(path)
            if not src:
                continue
            for dep, spec in (meta.get("dependencies") or {}).items():
                resolved_path = _resolve_lock_dependency(path, dep, pk)
                dst = path_to_purl.get(resolved_path)
                if dst:
                    edges.append({"from": src, "to": dst, "constraint": spec, "source": "npm-lock"})
        notes.append(f"package-lock v{lock.get('lockfileVersion')}: {len(pk) - 1} packages")

    for c in comps.values():
        c.setdefault("scope", "prod")
        c.setdefault("direct", False)

    # Discrepancies between sources feed the anomaly agent.
    discrepancies = []
    for purl, c in comps.items():
        if c["ecosystem"] == "pypi" and inp.get("sbom") and inp.get("python_graph"):
            if set(c["sources"]) != {"sbom", "graph"}:
                discrepancies.append({"purl": purl, "issue": f"only in {c['sources']}"})

    seen, uniq = set(), []
    for e in edges:
        k = (e["from"], e["to"])
        if k not in seen:
            seen.add(k)
            uniq.append(e)

    direct_n = sum(1 for c in comps.values() if c["direct"])
    return AgentResult(
        delta={"components": comps, "edges": uniq, "evidence": evidence,
               "discrepancies": discrepancies, "coverage": {"discovery": "; ".join(notes)}},
        summary=f"{len(comps)} components ({direct_n} direct), {len(uniq)} edges; " + "; ".join(notes),
        metrics={"components": len(comps), "edges": len(uniq), "discrepancies": len(discrepancies)})
