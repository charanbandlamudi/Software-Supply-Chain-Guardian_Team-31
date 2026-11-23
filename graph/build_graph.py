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
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import networkx as nx
from pyvis.network import Network

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"]
SEV_COLOR = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706",
             "LOW": "#65a30d", "NEGLIGIBLE": "#94a3b8", "UNKNOWN": "#94a3b8"}
COLOR = {"root": "#0f172a", "direct": "#2563eb", "transitive": "#94a3b8", "unresolved": "#9333ea"}


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
    name_counts = Counter(d["name"] for _, d in g.nodes(data=True))
    for n, d in g.nodes(data=True):
        if n == root:
            d["dep_type"] = "root"
        elif n in direct:
            d["dep_type"] = "direct"
        elif n in paths:
            d["dep_type"] = "transitive"
        else:
            d["dep_type"] = "unresolved"
        # Same package name in several versions -> disambiguate the label.
        d["label"] = d["name"] if name_counts[d["name"]] == 1 else f"{d['name']}@{d['version']}"
        d["path_ids"] = paths.get(n, [])  # shortest path root -> node, from the graph only
        d["vulns"] = vulns.get(f"{d['name']}@{d['version']}", [])
        d["max_sev"] = min((r["severity"] for r in d["vulns"] if r["severity"] in SEV_ORDER),
                           key=SEV_ORDER.index, default="UNKNOWN" if d["vulns"] else None)
        d["parent_ids"] = list(g.predecessors(n))
        d["child_ids"] = list(g.successors(n))


# ---------------------------------------------------------------- render
def node_style(d: dict) -> dict:
    dt, vuln = d["dep_type"], bool(d["vulns"])
    base = SEV_COLOR[d["max_sev"]] if vuln else COLOR.get(dt, "#64748b")
    if dt == "root":
        size, font = 34, {"size": 26, "color": "#0f172a", "bold": True}
    elif dt == "direct":
        size, font = (18 if vuln else 13), {"size": 16, "color": "#1e293b"}
    else:
        size, font = (13 if vuln else 6), {"size": 14 if vuln else 11, "color": "#334155"}
    font.update(strokeWidth=3, strokeColor="#ffffff")
    color = {"background": base, "border": base,
             "highlight": {"background": base, "border": "#0f172a"},
             "hover": {"background": base, "border": "#0f172a"}}
    shape = "star" if dt == "root" else "diamond" if vuln else "dot"
    return {"color": color, "size": size, "font": font, "shape": shape}


def export_json(g: nx.DiGraph, out: Path, inputs: dict, scan: dict | None = None) -> None:
    """Machine-readable graph + evidence for agents, reports and the dashboard.
    Same data the HTML embeds: nodes, directed edges, dependency paths, merged scanner findings."""
    node_keys = ("name", "version", "ecosystem", "purl", "scope", "dep_type", "path_ids",
                 "parent_ids", "child_ids", "max_sev", "vulns")
    nodes = [{"id": n, **{k: d[k] for k in node_keys}} for n, d in g.nodes(data=True)]
    sev = Counter(v["severity"] for _, d in g.nodes(data=True) for v in d["vulns"])
    doc = {
        "schema": "ssg-dependency-graph/1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": g.graph["source"],
        "root": g.graph["root"],
        "inputs": inputs,
        "scan": scan,
        "stats": {
            "nodes": g.number_of_nodes(), "edges": g.number_of_edges(),
            "direct": sum(1 for n in nodes if n["dep_type"] == "direct"),
            "transitive": sum(1 for n in nodes if n["dep_type"] == "transitive"),
            "unresolved": len(g.graph.get("unresolved", [])),
            "vulnerable_packages": sum(1 for n in nodes if n["vulns"]),
            "findings": sum(len(n["vulns"]) for n in nodes),
            "findings_by_severity": {s: sev[s] for s in SEV_ORDER if sev[s]},
        },
        "nodes": nodes,
        "edges": [{"from": a, "to": b} for a, b in g.edges()],
        "unresolved": g.graph.get("unresolved", []),
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2))
    print(f"Wrote {out}")


def render(g: nx.DiGraph, out: Path, target: str = "") -> None:
    net = Network(height="100vh", width="100%", directed=True, bgcolor="#f8fafc",
                  font_color="#1e293b", cdn_resources="in_line")  # self-contained, works offline
    # Pre-compute the layout here so the page opens instantly and starts out still
    # (browser-side physics on 1k+ nodes takes ~25s and never fully stops moving).
    pos = nx.forceatlas2_layout(g.to_undirected(), max_iter=300, scaling_ratio=4,
                                gravity=1, seed=7)
    # Components with no link to the root (e.g. CI GitHub Actions) get flung to the edges by
    # the force layout and shrink the whole view; lay them out in a tidy grid beside the tree.
    loose = [n for n, d in g.nodes(data=True) if d["dep_type"] == "unresolved"]
    linked = [n for n in g if n not in set(loose)] or list(g)
    span = max(max(abs(pos[n][0]), abs(pos[n][1])) for n in linked) or 1
    pos = {n: (x / span * 2500, y / span * 2500) for n, (x, y) in pos.items()}
    if loose:
        x0 = max(pos[n][0] for n in linked) + 400
        y0 = min(pos[n][1] for n in linked)
        cols = max(1, int(len(loose) ** 0.5))
        for i, n in enumerate(sorted(loose, key=lambda n: g.nodes[n]["name"])):
            pos[n] = (x0 + (i % cols) * 260, y0 + (i // cols) * 90)
    details = {}
    for n, d in g.nodes(data=True):
        tip = f"{d['name']}@{d['version']} · {d['dep_type']}"
        if d["vulns"]:
            tip += f" · {len(d['vulns'])} vuln(s), worst {d['max_sev']}"
        x, y = pos[n]
        style = node_style(d)
        font = style.pop("font")
        net.add_node(n, label=d["label"], title=tip, x=float(x),
                     y=float(y), **style)
        net.nodes[-1]["font"] = font  # pyvis overwrites a `font` kwarg with font_color only
        details[n] = {k: d[k] for k in ("name", "label", "version", "ecosystem", "purl", "scope",
                                         "dep_type", "path_ids", "vulns", "max_sev",
                                         "parent_ids", "child_ids")}
    for a, b in g.edges():
        net.add_edge(a, b)
    net.set_options(json.dumps({
        "nodes": {"borderWidth": 1, "scaling": {"label": {"drawThreshold": 8}}},
        "edges": {"color": {"color": "rgba(100,116,139,0.22)", "highlight": "#0284c7"},
                  "width": 0.6, "smooth": False,
                  "arrows": {"to": {"enabled": True, "scaleFactor": 0.35}}},
        # physics off at load (layout is pre-computed); "Resume motion" turns it on
        "physics": {"enabled": False, "solver": "forceAtlas2Based",
                    "forceAtlas2Based": {"gravitationalConstant": -70, "springLength": 100,
                                         "avoidOverlap": 0.4},
                    "stabilization": {"enabled": False}, "minVelocity": 1.5},
        "layout": {"improvedLayout": False},
        "interaction": {"hover": True, "tooltipDelay": 120, "hideEdgesOnDrag": True,
                        "hideEdgesOnZoom": True, "navigationButtons": False},
    }))
    html = net.generate_html()
    stats = {"source": g.graph["source"], "target": target, "nodes": g.number_of_nodes(),
             "edges": g.number_of_edges(),
             "direct": sum(1 for _, d in g.nodes(data=True) if d["dep_type"] == "direct"),
             "transitive": sum(1 for _, d in g.nodes(data=True) if d["dep_type"] == "transitive"),
             "vulnerable": sum(1 for _, d in g.nodes(data=True) if d["vulns"]),
             "findings": sum(len(d["vulns"]) for _, d in g.nodes(data=True)),
             "unresolved": len(g.graph.get("unresolved", [])), "root": g.graph["root"]}
    # json in a <script> block: escape "</" so package data can never close the tag
    to_js = lambda o: json.dumps(o).replace("</", "<\\/")
    ui = UI_HTML.replace("__DETAILS__", to_js(details)).replace("__STATS__", to_js(stats))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html.replace("</body>", ui + "\n</body>"))
    print(json.dumps({k: v for k, v in stats.items() if k != "root"}, indent=2))
    print(f"Wrote {out}")


UI_HTML = r"""
<style>
 :root{--bg:#f8fafc;--panel:#ffffff;--panel2:#f1f5f9;--line:#e2e8f0;--text:#0f172a;--muted:#64748b;
   --accent:#2563eb;--path:#d97706;--child:#0891b2}
 html,body{margin:0;background:var(--bg)!important;color:var(--text);font:13px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;overflow:hidden}
 .card{border:none!important;background:transparent!important}
 #mynetwork{position:fixed!important;inset:0;width:100vw!important;height:100vh!important;border:none!important;background:var(--bg)!important}
 #loadingBar{display:none!important}
 div.vis-tooltip{background:#ffffff!important;color:var(--text)!important;border:1px solid var(--line)!important;
   border-radius:6px!important;font:12px system-ui!important;padding:6px 8px!important;box-shadow:0 4px 14px rgba(15,23,42,.12)!important}
 .ssg-panel{position:fixed;top:12px;bottom:12px;background:rgba(255,255,255,.97);border:1px solid var(--line);
   border-radius:10px;box-shadow:0 8px 30px rgba(15,23,42,.10);z-index:20;display:flex;flex-direction:column;backdrop-filter:blur(6px)}
 #ssg-side{left:12px;width:320px}
 #ssg-drawer{right:12px;width:380px;transform:translateX(420px);transition:transform .2s ease}
 #ssg-drawer.open{transform:none}
 .hd{padding:12px 14px;border-bottom:1px solid var(--line)}
 .brand{font-weight:700;letter-spacing:.06em;font-size:12px;color:var(--accent)}
 .sub{color:var(--muted);font-size:12px;margin-top:2px}
 .body{padding:10px 14px;overflow:auto;flex:1}
 .stats{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-top:10px}
 .stat{background:var(--panel2);border-radius:6px;padding:6px 8px}.stat b{display:block;font-size:16px}.stat span{color:var(--muted);font-size:11px}
 .btns{display:flex;gap:6px;flex-wrap:wrap;margin:10px 0}
 button{background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:6px 10px;cursor:pointer;font:inherit}
 button:hover{border-color:var(--accent)} button.active{border-color:var(--accent);color:var(--accent)}
 input[type=text],select{width:100%;box-sizing:border-box;background:#ffffff;color:var(--text);border:1px solid var(--line);
   border-radius:6px;padding:8px 10px;font:inherit;outline:none} input[type=text]:focus,select:focus{border-color:var(--accent)}
 label.chk{display:flex;gap:6px;align-items:center;color:var(--muted);margin:6px 0;cursor:pointer}
 .section{margin:12px 0 4px;font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
 #ssg-results{margin-top:6px}
 .res{display:flex;align-items:center;gap:6px;padding:6px 8px;border-radius:6px;cursor:pointer;border:1px solid transparent}
 .res:hover,.res.act{background:var(--panel2);border-color:var(--line)}
 .res .nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
 .res .vr{font-family:ui-monospace,Menlo,monospace;color:var(--muted);font-size:11px}
 mark{background:rgba(37,99,235,.15);color:inherit;border-radius:2px}
 .chip{display:inline-block;font-size:10px;padding:1px 6px;border-radius:999px;background:#f1f5f9;color:var(--muted);border:1px solid var(--line);white-space:nowrap}
 .badge{display:inline-block;font-size:10px;font-weight:700;padding:1px 6px;border-radius:4px;color:#ffffff;white-space:nowrap}
 .legend div{display:flex;align-items:center;gap:8px;margin:3px 0;color:var(--muted)}
 .sw{width:10px;height:10px;border-radius:50%;display:inline-block}.sw.dia{border-radius:1px;transform:rotate(45deg)}
 .sw.line{width:18px;height:3px;border-radius:2px}
 .kbd{font-family:ui-monospace,monospace;background:#f1f5f9;border:1px solid var(--line);border-radius:4px;padding:0 4px;font-size:11px}
 .ttl{font-size:17px;font-weight:700;word-break:break-all}
 .crumbs{display:flex;flex-wrap:wrap;gap:4px;align-items:center}
 .crumb{padding:2px 8px;border-radius:999px;background:var(--panel2);border:1px solid var(--line);cursor:pointer;font-size:12px}
 .crumb:hover{border-color:var(--path)} .crumb.cur{border-color:var(--path);color:var(--path)}
 .vuln{background:var(--panel2);border-left:3px solid #ef4444;border-radius:6px;padding:8px 10px;margin:6px 0}
 .vuln .ids{color:var(--muted);font-size:11px;word-break:break-all}
 .tool{font-size:12px;margin-top:4px}
 .warn{color:#dc2626;font-size:11px}
 .list{display:flex;flex-wrap:wrap;gap:4px}
 .note{color:var(--muted);font-size:11px;margin-top:8px}
 #ssg-status{color:var(--muted);font-size:11px;margin-top:6px}
 .x{float:right;border:none;background:none;color:var(--muted);font-size:18px;padding:0 4px;line-height:1}
</style>

<div id="ssg-side" class="ssg-panel">
 <div class="hd">
  <div class="brand">SOFTWARE SUPPLY CHAIN GUARDIAN</div>
  <div class="sub">Dependency graph · <span id="ssg-source"></span></div>
  <div class="stats" id="ssg-stats"></div>
  <div class="btns">
   <button id="btn-physics" class="active">⏸ Freeze layout</button>
   <button id="btn-fit">⤢ Fit</button>
   <button id="btn-clear">✕ Clear focus</button>
  </div>
  <div id="ssg-status">Arranging layout…</div>
 </div>
 <div class="body">
  <input id="ssg-search" type="text" placeholder="Search packages, versions, purl…  ( / )" autocomplete="off">
  <label class="chk"><input type="checkbox" id="ssg-vulnonly"> Vulnerable packages only</label>
  <div id="ssg-results"></div>
  <div class="section">Show on graph</div>
  <select id="ssg-sev">
   <option value="">All components</option>
   <option value="CRITICAL">Critical (with paths)</option>
   <option value="HIGH">High and above (with paths)</option>
   <option value="MEDIUM">Medium and above (with paths)</option>
   <option value="LOW">Any vulnerability (with paths)</option>
  </select>
  <div class="section">Legend</div>
  <div class="legend">
   <div><span class="sw" style="background:#0f172a"></span>Root application (★)</div>
   <div><span class="sw" style="background:#2563eb"></span>Direct dependency</div>
   <div><span class="sw" style="background:#94a3b8"></span>Transitive dependency</div>
   <div><span class="sw" style="background:#9333ea"></span>Not linked in SBOM (e.g. CI GitHub Actions)</div>
   <div><span class="sw dia" style="background:#dc2626"></span>Critical · <span class="sw dia" style="background:#ea580c"></span>High · <span class="sw dia" style="background:#d97706"></span>Medium · <span class="sw dia" style="background:#65a30d"></span>Low</div>
   <div><span class="sw line" style="background:var(--path)"></span>Focused path to root</div>
   <div><span class="sw line" style="background:var(--child)"></span>Focused node's dependencies</div>
  </div>
 </div>
</div>

<div id="ssg-drawer" class="ssg-panel">
 <div class="hd"><button class="x" id="ssg-close" title="Close">×</button><div id="ssg-dhead"></div></div>
 <div class="body" id="ssg-dbody"></div>
</div>

<script>
(function(){
const SSG = __DETAILS__, STATS = __STATS__;
const SEV = ["CRITICAL","HIGH","MEDIUM","LOW","NEGLIGIBLE","UNKNOWN"];
const SEVC = {CRITICAL:"#dc2626",HIGH:"#ea580c",MEDIUM:"#d97706",LOW:"#65a30d",NEGLIGIBLE:"#94a3b8",UNKNOWN:"#94a3b8"};
const DIM = "rgba(203,213,225,0.22)", DIM_FONT = "rgba(0,0,0,0)", DIM_EDGE = "rgba(148,163,184,0.06)";
const EDGE_BASE = {color:"rgba(100,116,139,0.22)", width:0.6};
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const sevIdx = s => s ? SEV.indexOf(s) : 99;
const badge = s => s ? `<span class="badge" style="background:${SEVC[s]}">${esc(s)}</span>` : "";

// Snapshot original styling so focus/filters can be undone exactly.
const BASE = {}; nodes.get().forEach(n => BASE[n.id] = {id:n.id, color:n.color, font:n.font, borderWidth:1});
const EDGE_ID = {}; const ALL_EDGES = edges.get().map(e => { EDGE_ID[e.from + "\u0000" + e.to] = e.id; return e.id; });
let focused = null, frozen = false, active = -1, results = [];

// ---- header stats
$("ssg-source").textContent = (STATS.target ? STATS.target + " · " : "") + STATS.source;
const st = [["nodes","Packages"],["direct","Direct"],["transitive","Transitive"],["vulnerable","Vulnerable"],["findings","Findings"],["edges","Edges"]];
$("ssg-stats").innerHTML = st.map(([k,l]) => `<div class="stat"><b>${STATS[k]}</b><span>${l}</span></div>`).join("");

// ---- motion control: auto-freeze once the layout has settled
function setFrozen(f){
  frozen = f; network.setOptions({physics:{enabled:!f}});
  const b = $("btn-physics"); b.textContent = f ? "▶ Resume motion" : "⏸ Freeze layout"; b.classList.toggle("active", !f);
  $("ssg-status").textContent = f ? "Layout frozen — drag nodes to rearrange." : "Layout in motion…";
}
setFrozen(true);  // layout is pre-computed in Python; start still
$("btn-physics").onclick = () => setFrozen(!frozen);
$("btn-clear").onclick = () => clearFocus();
$("ssg-close").onclick = () => clearFocus();

// ---- zoom to a set of nodes inside the area not covered by the side panels
function viewScale(ids, maxScale=1.6){
  const pos = Object.values(network.getPositions(ids)); if(!pos.length) return 1;
  const xs = pos.map(p=>p.x), ys = pos.map(p=>p.y);
  const left = 344, right = $("ssg-drawer").classList.contains("open") ? 404 : 12;
  const bw = Math.max(...xs)-Math.min(...xs)+120, bh = Math.max(...ys)-Math.min(...ys)+120;
  return Math.min(maxScale, (window.innerWidth-left-right)/bw, (window.innerHeight-40)/bh);
}
function fitTo(ids, maxScale=1.6){
  const pos = Object.values(network.getPositions(ids)); if(!pos.length) return;
  const xs = pos.map(p=>p.x), ys = pos.map(p=>p.y);
  const W = window.innerWidth, H = window.innerHeight;
  const left = 344, right = $("ssg-drawer").classList.contains("open") ? 404 : 12;
  const bw = Math.max(...xs)-Math.min(...xs)+120, bh = Math.max(...ys)-Math.min(...ys)+120;
  const scale = Math.min(maxScale, (W-left-right)/bw, (H-40)/bh);
  network.moveTo({position:{x:(Math.max(...xs)+Math.min(...xs))/2, y:(Math.max(...ys)+Math.min(...ys))/2},
                  scale, offset:{x:(left-right)/2, y:0}, animation:{duration:600, easingFunction:"easeInOutQuad"}});
}
$("btn-fit").onclick = () => fitTo(nodes.getIds({filter: n => !n.hidden}), 1);
// Fit once the canvas has real dimensions (embedded iframes size late), and on resize.
network.once("afterDrawing", () => fitTo(nodes.getIds(), 1));
let rz; window.addEventListener("resize", () => { clearTimeout(rz); rz = setTimeout(() => {
  if(!focused) fitTo(nodes.getIds({filter: n => !n.hidden}), 1); }, 150); });

// ---- focus: path to root + direct dependencies, everything else dimmed
function focusNode(id){
  const d = SSG[id]; if(!d) return;
  focused = id;
  const path = d.path_ids.length ? d.path_ids : [id];
  const onPath = new Set(path), kids = new Set(d.child_ids);
  $("ssg-drawer").classList.add("open");
  // size focused labels so they read at the zoom level we are about to show (px on screen)
  const sc = viewScale([...onPath, ...kids, id]);
  nodes.update(Object.keys(BASE).map(k => {
    const b = BASE[k];
    const big = px => ({...b.font, size:Math.min(80, Math.max(b.font.size, px / sc)), color:"#0f172a"});
    if(k === id) return {...b, borderWidth:5, color:{...b.color, border:"#0f172a"}, font:big(16)};
    if(onPath.has(k)) return {...b, borderWidth:3, color:{...b.color, border:"#d97706"}, font:big(13)};
    if(kids.has(k)) return {...b, borderWidth:3, color:{...b.color, border:"#0891b2"}, font:big(12)};
    return {id:k, borderWidth:1, color:{background:DIM, border:DIM}, font:{...b.font, color:DIM_FONT, strokeWidth:0}};
  }));
  const hl = {};
  for(let i=0;i<path.length-1;i++){ const e = EDGE_ID[path[i]+"\u0000"+path[i+1]]; if(e) hl[e] = {color:"#d97706", width:3}; }
  d.child_ids.forEach(c => { const e = EDGE_ID[id+"\u0000"+c]; if(e) hl[e] = {color:"#0891b2", width:2}; });
  edges.update(ALL_EDGES.map(e => hl[e] ? {id:e, color:{color:hl[e].color}, width:hl[e].width}
                                         : {id:e, color:{color:DIM_EDGE}, width:0.4}));
  renderDrawer(id);  // open drawer first so fitTo accounts for it
  fitTo([...onPath, ...kids, id]);
}
function clearFocus(){
  focused = null;
  nodes.update(Object.values(BASE));
  edges.update(ALL_EDGES.map(e => ({id:e, color:{color:EDGE_BASE.color}, width:EDGE_BASE.width})));
  $("ssg-drawer").classList.remove("open");
  applySevFilter();
}
network.on("click", p => p.nodes.length ? focusNode(p.nodes[0]) : (focused && clearFocus()));

// ---- detail drawer
const chipLink = (k, cls="crumb") => `<span class="${cls}" data-id="${esc(k)}" title="${esc(SSG[k].name+'@'+SSG[k].version)}">${esc(SSG[k].label)}${SSG[k].vulns.length?" "+badge(SSG[k].max_sev):""}</span>`;
function renderDrawer(id){
  const d = SSG[id];
  $("ssg-dhead").innerHTML = `<div class="ttl">${esc(d.name)}</div>
    <div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap;align-items:center">
      <span class="chip" style="font-family:ui-monospace,monospace">v${esc(d.version)}</span>
      <span class="chip">${esc(d.dep_type)}</span>${d.scope?`<span class="chip">${esc(d.scope)}</span>`:""}
      <span class="chip">${esc(d.ecosystem)}</span>${badge(d.max_sev)}</div>`;
  const path = d.path_ids.length ? d.path_ids.map(k => k===id ? `<span class="crumb cur">${esc(SSG[k].label)}</span>` : chipLink(k)).join('<span style="color:var(--muted)">›</span>')
                                 : `<span class="warn">Evidence unavailable — no path to root in the SBOM graph</span>`;
  const vulns = d.vulns.length ? [...d.vulns].sort((a,b)=>sevIdx(a.severity)-sevIdx(b.severity)).map(v => `
    <div class="vuln" style="border-left-color:${SEVC[v.severity]||"#94a3b8"}">
      <div style="display:flex;justify-content:space-between;gap:6px"><b>${esc(v.id)}</b>${badge(v.severity)}</div>
      <div class="ids">${esc(v.ids.join(" · "))}</div>
      ${v.severity_disagreement ? '<div class="warn">Scanners disagree on severity</div>' : ""}
      ${v.source_tools.length < 2 ? `<div class="warn">Reported only by ${esc(v.source_tools[0])}</div>` : ""}
      ${Object.entries(v.by_tool).map(([t,r]) => `<div class="tool"><span class="chip">${esc(t)}</span> ${esc(r.severity)} · fixed in
        <b>${r.fixed_versions.length ? esc(r.fixed_versions.join(", ")) : "Evidence unavailable"}</b></div>`).join("")}
    </div>`).join("")
    : `<div class="note">No scanner findings for this version. Absence of a finding is not proof of safety.</div>`;
  const list = (ids, empty) => ids.length ? `<div class="list">${ids.slice(0,80).map(k => chipLink(k)).join("")}${ids.length>80?`<span class="chip">+${ids.length-80} more</span>`:""}</div>` : `<div class="note">${empty}</div>`;
  $("ssg-dbody").innerHTML = `
    <div class="section">Path to root <span style="color:var(--path)">━</span></div><div class="crumbs">${path}</div>
    <div class="section">Vulnerabilities (${d.vulns.length})</div>${vulns}
    <div class="section">Depends on (${d.child_ids.length}) <span style="color:var(--child)">━</span></div>${list(d.child_ids, "No dependencies")}
    <div class="section">Required by (${d.parent_ids.length})</div>${list(d.parent_ids, "—")}
    <div class="section">Package URL</div><div class="ids" style="font-family:ui-monospace,monospace">${esc(d.purl || "Evidence unavailable")}</div>`;
  $("ssg-drawer").classList.add("open");
}
document.addEventListener("click", e => { const t = e.target.closest("[data-id]"); if(t && !t.closest("#mynetwork")) focusNode(t.dataset.id); });

// ---- search: ranked, disambiguated by version, keyboard navigable
const INDEX = Object.entries(SSG).map(([id,d]) => ({id, d, n:d.name.toLowerCase(), hay:(d.name+" "+d.version+" "+(d.purl||"")).toLowerCase()}));
const hlText = (s, q) => { if(!q) return esc(s); const i = s.toLowerCase().indexOf(q); return i<0 ? esc(s) : esc(s.slice(0,i))+"<mark>"+esc(s.slice(i,i+q.length))+"</mark>"+esc(s.slice(i+q.length)); };
function runSearch(){
  const q = $("ssg-search").value.trim().toLowerCase(), vo = $("ssg-vulnonly").checked;
  if(!q && !vo){ $("ssg-results").innerHTML = ""; results = []; return; }
  const rank = x => !q ? 0 : x.n === q ? 0 : x.n.startsWith(q) ? 1 : x.n.includes(q) ? 2 : 3;
  results = INDEX.filter(x => (!vo || x.d.vulns.length) && (!q || x.hay.includes(q)))
    .sort((a,b) => rank(a)-rank(b) || sevIdx(a.d.max_sev)-sevIdx(b.d.max_sev) || a.n.localeCompare(b.n) || a.d.version.localeCompare(b.d.version, undefined, {numeric:true}));
  active = results.length ? 0 : -1;
  const shown = results.slice(0,60);
  $("ssg-results").innerHTML = `<div class="note" style="margin:2px 0 4px">${results.length} match${results.length===1?"":"es"}${results.length>60?" (showing 60)":""}</div>` +
    shown.map((x,i) => `<div class="res${i===active?" act":""}" data-id="${esc(x.id)}" data-i="${i}">
      <span class="nm">${hlText(x.d.name, q)}</span><span class="vr">${esc(x.d.version)}</span>
      <span class="chip">${esc(x.d.dep_type)}</span>${x.d.vulns.length ? badge(x.d.max_sev) : ""}</div>`).join("");
}
function moveActive(delta){
  const rows = [...document.querySelectorAll("#ssg-results .res")]; if(!rows.length) return;
  active = (active + delta + rows.length) % rows.length;
  rows.forEach((r,i) => r.classList.toggle("act", i===active)); rows[active].scrollIntoView({block:"nearest"});
}
$("ssg-search").addEventListener("input", runSearch);
$("ssg-vulnonly").addEventListener("change", runSearch);
$("ssg-search").addEventListener("keydown", e => {
  if(e.key==="ArrowDown"){ e.preventDefault(); moveActive(1); }
  else if(e.key==="ArrowUp"){ e.preventDefault(); moveActive(-1); }
  else if(e.key==="Enter" && results[active]) focusNode(results[active].id);
  else if(e.key==="Escape"){ e.target.value=""; runSearch(); e.target.blur(); }
});
document.addEventListener("keydown", e => {
  if(e.target.tagName === "INPUT") return;
  if(e.key === "/"){ e.preventDefault(); $("ssg-search").focus(); }
  else if(e.key === "Escape") clearFocus();
});

// ---- severity filter: keep matching nodes plus their path to root
function applySevFilter(){
  const min = $("ssg-sev").value;
  edges.update(ALL_EDGES.map(e => ({id:e, color:{color:EDGE_BASE.color}, width:EDGE_BASE.width})));
  if(!min){ nodes.update(Object.keys(BASE).map(k => ({id:k, hidden:false}))); return; }
  const keep = new Set([STATS.root]), pathEdges = new Set();
  for(const [k,d] of Object.entries(SSG))
    if(d.vulns.length && sevIdx(d.max_sev) <= SEV.indexOf(min)) {
      const p = d.path_ids.length ? d.path_ids : [k];
      p.forEach(x => keep.add(x));
      for(let i=0;i<p.length-1;i++){ const e = EDGE_ID[p[i]+"\u0000"+p[i+1]]; if(e) pathEdges.add(e); }
    }
  nodes.update(Object.keys(BASE).map(k => ({id:k, hidden:!keep.has(k)})));
  edges.update([...pathEdges].map(e => ({id:e, color:{color:"rgba(220,38,38,0.6)"}, width:1.5})));
  fitTo([...keep], 1.2);
}
$("ssg-sev").addEventListener("change", () => focused ? clearFocus() : applySevFilter());  // clearFocus re-applies the filter
})();
</script>
"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", type=Path, required=True)
    ap.add_argument("--bom", type=Path, default=Path("data/sbom/bom.json"))
    ap.add_argument("--grype", type=Path, default=Path("data/scanner_results/grype.json"))
    ap.add_argument("--osv", type=Path, default=Path("data/scanner_results/osv.json"))
    ap.add_argument("--out", type=Path, default=Path("data/graphs/dependency_graph.html"))
    ap.add_argument("--json", type=Path, default=Path("data/graphs/graph.json"))
    a = ap.parse_args()

    build(a.repo, a.bom, a.grype, a.osv, a.out, a.json)


def build(repo: Path, bom: Path, grype: Path | None, osv: Path | None, out_html: Path,
          out_json: Path, target: str = "", scan: dict | None = None) -> dict:
    """Build graph.json + interactive HTML from an SBOM and optional scanner reports.
    Returns graph statistics. Missing scanner files are skipped and reported, never faked."""
    g = load_bom(bom) if bom.exists() else None
    if g is None:
        if not (repo / "package.json").exists():
            raise ValueError(f"SBOM {bom} has no components and there is no package.json "
                             "fallback — cannot build a dependency graph.")
        print(f"[warn] {bom} missing or has 0 components — falling back to package.json "
              "(direct dependencies only).")
        g = load_package_json(repo)
    sources, scanners_used = [], []
    for name, path, loader in (("Grype", grype, load_grype), ("OSV-Scanner", osv, load_osv)):
        if path and path.exists():
            sources.append(loader(path))
            scanners_used.append(name)
        else:
            print(f"[warn] {name} results not available — not included in overlay.")
    annotate(g, merge_findings(*sources))
    export_json(g, out_json, {"sbom": str(bom), "repo": str(repo),
                              "scanner_results": {"Grype": str(grype), "OSV-Scanner": str(osv)},
                              "scanners_used": scanners_used}, scan)
    render(g, out_html, target)
    return json.loads(out_json.read_text())["stats"]


if __name__ == "__main__":
    main()
