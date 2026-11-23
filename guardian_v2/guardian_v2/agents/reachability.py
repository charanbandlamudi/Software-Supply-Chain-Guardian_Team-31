"""Reachability/Usage agent: does the application's source import each package?"""
from __future__ import annotations

import ast
import re
from collections import defaultdict
from pathlib import Path

from ..evidence import make_evidence
from .base import AgentResult

MODULE_TO_PYPI = {"yaml": "pyyaml", "PIL": "pillow", "bs4": "beautifulsoup4", "jwt": "pyjwt",
                  "dateutil": "python-dateutil", "sklearn": "scikit-learn", "cv2": "opencv-python"}
JS_IMPORT = re.compile(r"""(?:require\(\s*['"]([^'"]+)['"]\s*\)|from\s+['"]([^'"]+)['"]|import\s+['"]([^'"]+)['"])""")


def _norm(n: str) -> str:
    return re.sub(r"[-_.]+", "-", n).lower()


def _scan(dirs):
    hits = defaultdict(list)  # (eco, pkg) -> ["file:line"]
    for d in dirs:
        for f in Path(d).rglob("*"):
            if "node_modules" in f.parts or not f.is_file():
                continue
            if f.suffix == ".py":
                try:
                    tree = ast.parse(f.read_text())
                except SyntaxError:
                    continue
                for node in ast.walk(tree):
                    mods = []
                    if isinstance(node, ast.Import):
                        mods = [a.name for a in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                        mods = [node.module]
                    for m in mods:
                        top = m.split(".")[0]
                        hits[("pypi", _norm(MODULE_TO_PYPI.get(top, top)))].append(f"{f}:{node.lineno}")
            elif f.suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"):
                for i, line in enumerate(f.read_text().splitlines(), 1):
                    for m in JS_IMPORT.finditer(line):
                        spec = next(g for g in m.groups() if g)
                        if spec.startswith("."):
                            continue
                        parts = spec.split("/")
                        name = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
                        hits[("npm", name)].append(f"{f}:{i}")
    return hits


def run(state: dict, task: dict) -> AgentResult:
    comps, edges = state.get("components", {}), state.get("edges", [])
    hits = _scan(state.get("inputs", {}).get("source_dirs", []))
    children = defaultdict(set)
    for e in edges:
        children[e["from"]].add(e["to"])
    out, evidence, imported = {}, {}, set()
    for purl, c in comps.items():
        locs = hits.get((c.get("ecosystem"), c.get("name")), [])
        if locs:
            eid, ev = make_evidence("tool_output", "ast-import-scan", purl, {"imports": locs})
            evidence[eid] = ev
            out[purl] = {"reachability": {"state": "imported", "locations": locs[:5], "evidence_ids": [eid],
                                          "method": "import analysis (not call-graph)"}}
            imported.add(purl)
    stack, transitive = list(imported), set()          # walk the graph from imported packages
    while stack:
        for nxt in children.get(stack.pop(), ()):
            if nxt not in imported and nxt not in transitive:
                transitive.add(nxt)
                stack.append(nxt)
    for purl in transitive:
        out[purl] = {"reachability": {"state": "used_transitively", "evidence_ids": [],
                                      "method": "graph walk from imported packages"}}
    for purl, c in comps.items():
        if purl in out:
            continue
        state_ = "not_in_runtime" if c.get("scope") == "environment" else "not_imported"
        out[purl] = {"reachability": {"state": state_, "evidence_ids": [], "method": "import analysis"}}

    focus = task.get("focus") or []
    focus_msg = ""
    if focus:
        used = [p.split("/")[-1] for p in focus if out.get(p, {}).get("reachability", {}).get("state") == "imported"]
        focus_msg = f"; handoff check on {len(focus)} suspicious packages: imported by source = {used or 'none'}"
    counts = defaultdict(int)
    for v in out.values():
        counts[v["reachability"]["state"]] += 1
    return AgentResult(delta={"components": out, "evidence": evidence},
                       summary=f"reachability: {dict(counts)}{focus_msg}", metrics=dict(counts))
