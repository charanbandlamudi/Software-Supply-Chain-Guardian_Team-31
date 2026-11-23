"""Build an interactive dependency graph (NetworkX + PyVis).

Sources, in order of preference:
  1. CycloneDX SBOM from cdxgen (full direct + transitive tree, needs a lockfile)
  2. package.json fallback (direct dependencies only, declared version ranges)

Optionally overlays vulnerabilities from a Grype JSON report.

Usage:
  python graph/build_graph.py --repo data/repos/juice-shop \
      [--bom data/sbom/bom.json] [--grype data/scanner_results/grype.json] \
      [--out data/graphs/dependency_graph.html]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import networkx as nx
from pyvis.network import Network

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"]
SEV_COLOR = {"CRITICAL": "#b71c1c", "HIGH": "#e53935", "MEDIUM": "#fb8c00",
             "LOW": "#fdd835", "NEGLIGIBLE": "#9e9e9e", "UNKNOWN": "#9e9e9e"}
COLOR = {"root": "#263238", "direct": "#1e88e5", "transitive": "#90a4ae"}


def ecosystem_from_purl(purl: str | None) -> str:
    if purl and purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0]
    return "unknown"


# ---------------------------------------------------------------- loaders
def load_bom(path: Path) -> nx.DiGraph | None:
    """Graph from CycloneDX components + dependencies. None if SBOM is empty."""
    bom = json.loads(path.read_text())
    comps = bom.get("components") or []
    if not comps:
        return None
    g = nx.DiGraph(source="cdxgen SBOM", sbom=str(path))
    meta = (bom.get("metadata") or {}).get("component") or {}
    root = meta.get("bom-ref") or "ROOT"
    g.add_node(root, name=meta.get("name", "application"), version=meta.get("version", ""),
               ecosystem=ecosystem_from_purl(meta.get("purl")), purl=meta.get("purl"),
               scope="", kind="root")
    g.graph["root"] = root
    for c in comps:
        ref = c.get("bom-ref") or c.get("purl") or f"{c.get('name')}@{c.get('version')}"
        name = f"{c['group']}/{c['name']}" if c.get("group") else c.get("name")
        g.add_node(ref, name=name, version=c.get("version") or "Evidence unavailable",
                   ecosystem=ecosystem_from_purl(c.get("purl")), purl=c.get("purl"),
                   scope=c.get("scope", "required"), kind="component")
    for d in bom.get("dependencies") or []:
        src = d.get("ref")
        for dst in d.get("dependsOn") or []:
            if src in g and dst in g:  # never invent nodes for unknown refs
                g.add_edge(src, dst)
    # Components with no parent at all: record as unresolved rather than guessing a parent.
    g.graph["unresolved"] = [n for n in g if n != root and g.in_degree(n) == 0]
    return g


def load_package_json(repo: Path) -> nx.DiGraph:
    pkg = json.loads((repo / "package.json").read_text())
    g = nx.DiGraph(source="package.json (manifest only — no lockfile, direct deps only)")
    root = f"pkg:npm/{pkg.get('name', 'app')}@{pkg.get('version', '')}"
    g.add_node(root, name=pkg.get("name", "app"), version=pkg.get("version", ""),
               ecosystem="npm", purl=root, scope="", kind="root")
    g.graph["root"] = root
    for field, scope in (("dependencies", "required"), ("devDependencies", "dev"),
                         ("optionalDependencies", "optional")):
        for name, rng in (pkg.get(field) or {}).items():
            ref = f"npm:{name}"
            g.add_node(ref, name=name, version=f"{rng} (declared range, unresolved)",
                       ecosystem="npm", purl=None, scope=scope, kind="component")
            g.add_edge(root, ref)
    g.graph["unresolved"] = []
    return g


def load_grype(path: Path) -> dict[str, list[dict]]:
    """Map purl and name@version -> list of vulnerability records (scanner facts only)."""
    out: dict[str, list[dict]] = {}
    for m in json.loads(path.read_text()).get("matches", []):
        v, a = m.get("vulnerability", {}), m.get("artifact", {})
        aliases = [r.get("id") for r in m.get("relatedVulnerabilities") or [] if r.get("id")]
        rec = {"id": v.get("id"), "aliases": aliases,
               "severity": (v.get("severity") or "UNKNOWN").upper(),
               "fixed_versions": (v.get("fix") or {}).get("versions") or [],
               "source_tool": "Grype"}
        out.setdefault(f"{a.get('name')}@{a.get('version')}", []).append(rec)
    return out


def load_osv(path: Path) -> dict[str, list[dict]]:
    """Map name@version -> vulnerability records from osv-scanner JSON."""
    sev_map = {"MODERATE": "MEDIUM"}
    out: dict[str, list[dict]] = {}
    for res in json.loads(path.read_text()).get("results", []):
        for p in res.get("packages", []):
            pkg = p["package"]
            for v in p.get("vulnerabilities", []):
                sev = ((v.get("database_specific") or {}).get("severity") or "UNKNOWN").upper()
                fixed = sorted({e["fixed"] for aff in v.get("affected", [])
                                if (aff.get("package") or {}).get("name") == pkg["name"]
                                for r in aff.get("ranges", []) for e in r.get("events", [])
                                if "fixed" in e})
                out.setdefault(f"{pkg['name']}@{pkg['version']}", []).append({
                    "id": v["id"], "aliases": v.get("aliases") or [],
                    "severity": sev_map.get(sev, sev), "fixed_versions": fixed,
                    "source_tool": "OSV-Scanner"})
    return out


def merge_findings(*sources: dict[str, list[dict]]) -> dict[str, list[dict]]:
    """Correlate the same vulnerability across scanners via shared IDs/aliases.
    Disagreements (severity, fixed versions) are kept side by side, not resolved."""
    merged: dict[str, list[dict]] = {}
    for src in sources:
        for key, recs in src.items():
            bucket = merged.setdefault(key, [])
            for r in recs:
                ids = {r["id"], *r["aliases"]}
                hit = next((b for b in bucket if ids & b["ids"]), None)
                if hit is None:
                    hit = {"id": r["id"], "ids": set(), "by_tool": {}}
                    bucket.append(hit)
                hit["ids"] |= ids
                # prefer a CVE identifier for display when one is reported
                cves = sorted(i for i in hit["ids"] if i.startswith("CVE-"))
                hit["id"] = cves[0] if cves else hit["id"]
                hit["by_tool"].setdefault(r["source_tool"], {
                    "severity": r["severity"], "fixed_versions": r["fixed_versions"]})
    for bucket in merged.values():
        for h in bucket:
            sevs = {t["severity"] for t in h["by_tool"].values()}
            h["severity"] = min(sevs, key=lambda s: SEV_ORDER.index(s) if s in SEV_ORDER else 99)
            h["severity_disagreement"] = len(sevs) > 1
            h["source_tools"] = sorted(h["by_tool"])
            h["ids"] = sorted(h["ids"])
    return merged


# ---------------------------------------------------------------- analysis
def annotate(g: nx.DiGraph, vulns: dict[str, list[dict]]) -> None:
    root = g.graph["root"]
    direct = set(g.successors(root))
    paths = nx.single_source_shortest_path(g, root)
    for n, d in g.nodes(data=True):
        if n == root:
            d["dep_type"] = "root"
        elif n in direct:
            d["dep_type"] = "direct"
        elif n in paths:
            d["dep_type"] = "transitive"
        else:
            d["dep_type"] = "unresolved"
        d["path"] = [g.nodes[p]["name"] for p in paths.get(n, [])] or ["Evidence unavailable"]
        d["vulns"] = vulns.get(f"{d['name']}@{d['version']}", [])
        d["max_sev"] = min((r["severity"] for r in d["vulns"] if r["severity"] in SEV_ORDER),
                           key=SEV_ORDER.index, default="UNKNOWN" if d["vulns"] else None)
        d["parents"] = [g.nodes[p]["name"] for p in g.predecessors(n)]
        d["children"] = [g.nodes[c]["name"] for c in g.successors(n)]


# ---------------------------------------------------------------- render
def render(g: nx.DiGraph, out: Path) -> None:
    net = Network(height="100vh", width="100%", directed=True, bgcolor="#fafafa",
                  cdn_resources="in_line")  # self-contained file, works offline
    details = {}
    for n, d in g.nodes(data=True):
        color = SEV_COLOR[d["max_sev"]] if d["max_sev"] else COLOR.get(d["dep_type"], "#bdbdbd")
        size = 30 if d["dep_type"] == "root" else 18 if d["dep_type"] == "direct" else 10
        shape = "star" if d["dep_type"] == "root" else "diamond" if d["vulns"] else "dot"
        net.add_node(n, label=d["name"], color=color, size=size, shape=shape,
                     title=f"{d['name']} {d['version']}")
        details[n] = {k: d[k] for k in ("name", "version", "ecosystem", "purl", "scope",
                                         "dep_type", "path", "vulns", "max_sev",
                                         "parents", "children")}
    for a, b in g.edges():
        net.add_edge(a, b, arrows="to", color="#cfd8dc")
    net.set_options(json.dumps({
        "physics": {"solver": "forceAtlas2Based", "stabilization": {"iterations": 300},
                    "forceAtlas2Based": {"gravitationalConstant": -60, "springLength": 120}},
        "interaction": {"hover": True, "navigationButtons": True},
    }))
    html = net.generate_html()
    stats = {"source": g.graph["source"], "nodes": g.number_of_nodes(),
             "edges": g.number_of_edges(),
             "direct": sum(1 for _, d in g.nodes(data=True) if d["dep_type"] == "direct"),
             "transitive": sum(1 for _, d in g.nodes(data=True) if d["dep_type"] == "transitive"),
             "vulnerable": sum(1 for _, d in g.nodes(data=True) if d["vulns"]),
             "unresolved": len(g.graph.get("unresolved", []))}
    panel = PANEL_HTML.replace("__DETAILS__", json.dumps(details)).replace(
        "__STATS__", json.dumps(stats))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html.replace("</body>", panel + "\n</body>"))
    print(json.dumps(stats, indent=2))
    print(f"Wrote {out}")


PANEL_HTML = r"""
<style>
 #ssg-panel{position:fixed;top:12px;right:12px;width:340px;max-height:92vh;overflow:auto;
   background:#fff;border:1px solid #ddd;border-radius:8px;padding:12px;font:13px system-ui;
   box-shadow:0 2px 10px rgba(0,0,0,.12);z-index:10}
 #ssg-panel h3{margin:0 0 6px;font-size:14px} #ssg-panel input,#ssg-panel select{width:100%;margin:4px 0;padding:5px}
 .lg{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:4px}
 .kv b{display:inline-block;width:90px;color:#555} .vuln{border-left:3px solid #e53935;padding-left:6px;margin:4px 0}
 .muted{color:#888}
</style>
<div id="ssg-panel">
 <h3>SOFTWARE SUPPLY CHAIN GUARDIAN — Dependency Graph</h3>
 <div id="ssg-stats" class="muted"></div>
 <input id="ssg-search" placeholder="Search package name…">
 <select id="ssg-sev"><option value="">All components</option>
  <option value="CRITICAL">Critical only</option><option value="HIGH">High and above</option>
  <option value="MEDIUM">Medium and above</option><option value="LOW">Low and above</option></select>
 <div style="margin:6px 0">
  <span class="lg" style="background:#263238"></span>Root &nbsp;
  <span class="lg" style="background:#1e88e5"></span>Direct &nbsp;
  <span class="lg" style="background:#90a4ae"></span>Transitive<br>
  <span class="lg" style="background:#b71c1c"></span>Critical
  <span class="lg" style="background:#e53935"></span>High
  <span class="lg" style="background:#fb8c00"></span>Medium
  <span class="lg" style="background:#fdd835"></span>Low (◆ = vulnerable)
 </div>
 <hr><div id="ssg-detail" class="muted">Click a node to see its details.</div>
</div>
<script>
const SSG = __DETAILS__, STATS = __STATS__;
const SEV = ["CRITICAL","HIGH","MEDIUM","LOW","NEGLIGIBLE","UNKNOWN"];
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
document.getElementById("ssg-stats").innerHTML =
  `Source: ${esc(STATS.source)}<br>${STATS.nodes} nodes · ${STATS.edges} edges · ${STATS.direct} direct · ` +
  `${STATS.transitive} transitive · ${STATS.vulnerable} vulnerable` + (STATS.unresolved ? ` · ${STATS.unresolved} unresolved` : "");
function show(id){
  const d = SSG[id]; if(!d) return;
  const v = d.vulns.length ? d.vulns.map(x => `<div class="vuln"><b>${esc(x.id)}</b> — ${esc(x.severity)}
     ${x.severity_disagreement ? '<span style="color:#e53935">(scanners disagree on severity)</span>' : ""}<br>
     <span class="muted">IDs: ${esc(x.ids.join(", "))}</span><br>
     ${Object.entries(x.by_tool).map(([t, r]) => `${esc(t)}: ${esc(r.severity)}, fixed in ${
        r.fixed_versions.length ? esc(r.fixed_versions.join(", ")) : "Evidence unavailable"}`).join("<br>")}
     </div>`).join("")
     : `<span class="muted">No scanner findings attached (absence of a finding is not proof of safety).</span>`;
  document.getElementById("ssg-detail").innerHTML = `
   <div class="kv"><b>Package</b>${esc(d.name)}</div><div class="kv"><b>Version</b>${esc(d.version)}</div>
   <div class="kv"><b>Ecosystem</b>${esc(d.ecosystem)}</div><div class="kv"><b>Type</b>${esc(d.dep_type)} (${esc(d.scope||"-")})</div>
   <div class="kv"><b>PURL</b>${esc(d.purl||"Evidence unavailable")}</div>
   <p><b>Path to root</b><br>${d.path.map(esc).join(" → ")}</p>
   <p><b>Parents (${d.parents.length})</b><br>${d.parents.map(esc).join(", ")||"-"}</p>
   <p><b>Dependencies (${d.children.length})</b><br>${d.children.slice(0,40).map(esc).join(", ")||"-"}${d.children.length>40?" …":""}</p>
   <p><b>Vulnerabilities</b></p>${v}`;
}
network.on("click", p => { if(p.nodes.length) show(p.nodes[0]); });
document.getElementById("ssg-search").addEventListener("input", e => {
  const q = e.target.value.trim().toLowerCase(); if(!q){ network.unselectAll(); return; }
  const hits = Object.keys(SSG).filter(k => SSG[k].name.toLowerCase().includes(q));
  network.selectNodes(hits);
  if(hits.length){ network.focus(hits[0], {scale:1.2, animation:true}); show(hits[0]); }
});
document.getElementById("ssg-sev").addEventListener("change", e => {
  const min = e.target.value, lim = min ? SEV.indexOf(min) : 99;
  nodes.update(Object.keys(SSG).map(k => {
    const d = SSG[k], keep = !min || d.dep_type === "root" || (d.max_sev && SEV.indexOf(d.max_sev) <= lim);
    return {id: k, hidden: !keep};
  }));
});
</script>
"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--bom", type=Path, default=Path("data/sbom/bom.json"))
    ap.add_argument("--grype", type=Path, default=Path("data/scanner_results/grype.json"))
    ap.add_argument("--osv", type=Path, default=Path("data/scanner_results/osv.json"))
    ap.add_argument("--out", type=Path, default=Path("data/graphs/dependency_graph.html"))
    a = ap.parse_args()

    g = load_bom(a.bom) if a.bom.exists() else None
    if g is None:
        print(f"[warn] {a.bom} missing or has 0 components — falling back to package.json "
              "(direct dependencies only). Generate a lockfile + rerun cdxgen for the full tree.")
        g = load_package_json(a.repo)
    sources = []
    for name, path, loader in (("Grype", a.grype, load_grype), ("OSV-Scanner", a.osv, load_osv)):
        if path.exists():
            sources.append(loader(path))
            print(f"[info] Loaded {name} results from {path}")
        else:
            print(f"[warn] {name} results not found at {path} — not included in overlay.")
    vulns = merge_findings(*sources)
    annotate(g, vulns)
    render(g, a.out)


if __name__ == "__main__":
    main()
