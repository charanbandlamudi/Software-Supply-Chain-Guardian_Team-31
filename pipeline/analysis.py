"""Blast radius + attack path analysis for a scan folder.

Thin wrapper around the team's `ssg_analysis.py` (standard library only): it feeds the scan's
graph.json and raw Grype / OSV-Scanner / Trivy output to `ssg_analysis.analyse()`, writes the two
Markdown reports, and saves a structured analysis.json that the UI's "Blast radius & attack paths"
tab reads. Every package, path and score comes from the dependency graph and scanner data.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
import ssg_analysis as A  # noqa: E402


def compute(scan_dir: Path, max_paths: int = 50) -> dict:
    scan_dir = Path(scan_dir)
    res = scan_dir / "scanner_results"
    graph = A.load(str(scan_dir / "graphs" / "graph.json"))
    if not graph:
        raise FileNotFoundError("graph.json not found for this scan")
    trivy = A.load(str(res / "trivy.json"))
    indexes = [A.index_grype(A.load(str(res / "grype.json"))), A.index_trivy(trivy), A.index_osv(A.load(str(res / "osv.json")))]
    nodes, root, pkgs = A.analyse(graph, indexes, max_paths)
    sec, mis, iac = A.environment(trivy)

    # chokepoints: intermediate packages on the paths to several vulnerable packages
    choke = defaultdict(set)
    for p in pkgs:
        for path in p["paths"]:
            for mid in path[1:-1]:
                choke[mid].add(p["id"])
    byid = {p["id"]: p for p in pkgs}
    chokepoints = sorted(({"package": A.short(m), "vulnerable_targets": len(t),
                           "findings_behind": sum(len(byid[x]["cves"]) for x in t),
                           "targets": sorted(byid[x]["label"] for x in t)} for m, t in choke.items()),
                         key=lambda r: (-r["findings_behind"], -r["vulnerable_targets"]))
    entry_points = [{"direct_dependency": e, "findings": n, "worst": w, "vulnerable_packages": [p["label"] for p in ps]}
                    for e, n, w, ps in A.fix_plan(pkgs)]
    classes = defaultdict(list)
    for p in pkgs:
        for cls in {c["cls"] for c in p["cves"]}:
            hits = [c for c in p["cves"] if c["cls"] == cls]
            classes[cls].append({"package": p["label"], "score": p["score"], "findings": len(hits),
                                 "worst": max(hits, key=lambda c: c["cvss"] or 0)["id"]})
    # attack-path edges for a Sankey diagram (how many distinct paths use each dependency edge)
    edge_use = defaultdict(int)
    for p in pkgs:
        for path in p["paths"]:
            for a, b in zip(path, path[1:]):
                edge_use[(A.short(a), A.short(b))] += 1
    packages = [{k: p[k] for k in ("id", "label", "name", "ver", "sev", "tier", "score", "components", "dep_type",
                                   "scope", "hops", "max_cvss", "max_epss", "entry", "dependents", "subtree", "trunc")}
                | {"findings": p["cves"], "paths": [[A.short(x) for x in path] for path in p["paths"]]} for p in pkgs]
    return {
        "schema": "ssg-blast-radius/1", "root": A.short(root),
        "weights": A.W, "tiers": A.TIERS, "epss_saturation": A.EPSS_SATURATION,
        "packages": packages, "entry_points": entry_points, "chokepoints": chokepoints,
        "exposure_classes": {k: sorted(v, key=lambda x: -x["score"]) for k, v in classes.items()},
        "path_edges": [{"from": a, "to": b, "paths": n} for (a, b), n in edge_use.items()],
        "environment": {"secrets": [{"file": f, "type": t, "severity": s_} for f, t, s_ in sec],
                        "dockerfile_misconfigurations": [{"file": f, "issue": i, "severity": s_} for f, i, s_ in mis],
                        "iac_misconfigurations": dict(iac)},
        "totals": {"vulnerable_packages": len(pkgs), "attack_paths": sum(len(p["paths"]) for p in pkgs),
                   "entry_points": len(entry_points), "chokepoints": len(chokepoints),
                   "by_tier": {t: sum(1 for p in pkgs if p["tier"] == t) for _, t in A.TIERS},
                   "max_hops": max((p["hops"] for p in pkgs), default=0)},
        "_markdown": {"blast_radius_report.md": A.blast_report(graph, pkgs, sec, mis, iac, 10) if pkgs else "",
                      "attack_path_report.md": A.attack_report(graph, root, pkgs, sec) if pkgs else ""},
    }


def run_analysis(scan_dir: Path) -> dict:
    """Compute and save analysis/{analysis.json, blast_radius_report.md, attack_path_report.md}."""
    out = Path(scan_dir) / "analysis"
    out.mkdir(exist_ok=True)
    r = compute(scan_dir)
    for name, text in r.pop("_markdown").items():
        (out / name).write_text(text, encoding="utf-8")
    (out / "analysis.json").write_text(json.dumps(r, indent=2, default=str), encoding="utf-8")
    return r


def load_or_run(scan_dir: Path) -> dict:
    f = Path(scan_dir) / "analysis" / "analysis.json"
    g = Path(scan_dir) / "graphs" / "graph.json"
    if f.exists() and g.exists() and f.stat().st_mtime >= g.stat().st_mtime:
        return json.loads(f.read_text(encoding="utf-8"))
    return run_analysis(scan_dir)
