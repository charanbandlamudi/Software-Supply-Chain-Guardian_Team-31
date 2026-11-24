"""Bridge: run the guardian_v2 multi-agent investigation on a finished scan.

The scan pipeline has already cloned the repo, built the SBOM and run the scanners.
This module turns that scan folder into guardian_v2 inputs, runs the LangGraph
supervisor in the unattended "analysis" stage (every agent except the human
approval gate and sandbox validation), and saves the agent conversation next to
the scan as agents/investigation.json plus guardian_v2's own reports.
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
GUARDIAN_V2 = ROOT / "guardian_v2"
# Shared HTTP cache for registry/OSV/KEV responses, reused across scans (set before import).
os.environ.setdefault("GUARDIAN_CACHE_DIR", str(ROOT / "data" / "agent_cache"))
if str(GUARDIAN_V2) not in sys.path:
    sys.path.insert(0, str(GUARDIAN_V2))

SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build"}


def _find(repo: Path, patterns: list[str], max_depth: int = 4) -> list[str]:
    out = []
    for pat in patterns:
        for p in repo.rglob(pat):
            rel = p.relative_to(repo)
            if p.is_file() and len(rel.parts) <= max_depth and not SKIP_DIRS & set(rel.parts):
                out.append(str(p))
    return sorted(set(out))


def _reputation_focus(bom_path: Path, graph_json: Path | None) -> list[str]:
    """Direct dependencies + every package a scanner flagged, as SBOM purls.
    Registry metadata for all 1000+ packages is too heavy on slow connections."""
    bom = json.loads(bom_path.read_text())
    ref_to_purl = {c.get("bom-ref", c.get("purl")): c["purl"] for c in bom.get("components", []) if c.get("purl")}
    root = ((bom.get("metadata") or {}).get("component") or {}).get("bom-ref")
    focus = set()
    for d in bom.get("dependencies", []):
        if d.get("ref") == root:
            focus |= {ref_to_purl[r] for r in d.get("dependsOn", []) if r in ref_to_purl}
    if graph_json and graph_json.exists():
        for n in json.loads(graph_json.read_text()).get("nodes", []):
            if n.get("vulns") and n["id"] in ref_to_purl:
                focus.add(ref_to_purl[n["id"]])
    return sorted(focus)


def build_inputs(scan_dir: Path, repo: Path) -> dict:
    sbom = scan_dir / "sbom" / "bom.json"
    grype = scan_dir / "scanner_results" / "grype.json"
    graph_json = scan_dir / "graphs" / "graph.json"
    inputs = {
        "sbom": str(sbom),
        "source_dirs": [str(repo)],
        "dockerfiles": _find(repo, ["Dockerfile", "Dockerfile.*", "*.Dockerfile"]),
        "workflows": _find(repo, [".github/workflows/*.yml", ".github/workflows/*.yaml"], max_depth=3),
        "out_dir": str(scan_dir / "agents"),
        "stage": "analysis",
        "reputation_focus": _reputation_focus(sbom, graph_json),
    }
    if (repo / "package.json").exists():
        inputs["npm_manifest"] = str(repo / "package.json")
    if (repo / "package-lock.json").exists():
        inputs["npm_lock"] = str(repo / "package-lock.json")
    if (repo / "requirements.txt").exists():
        inputs["python_manifest"] = str(repo / "requirements.txt")
    if grype.exists():
        inputs["grype_report"] = str(grype)
    return inputs


def run_agents(scan_dir: Path, repo: Path, on_message: Callable[[dict], None] = lambda m: None) -> dict:
    """Run the agents; returns a summary dict. Raises on fatal errors (caller records them)."""
    from guardian_v2.orchestrator import build_orchestrator
    from guardian_v2.providers import default_chain

    inputs = build_inputs(scan_dir, repo)
    llm_call, providers = default_chain()          # API keys from env/.env; None -> templates
    app, catalog = build_orchestrator(context={"exposure": "internet", "mission": "medium"},
                                      llm_call=llm_call, providers=providers, stage="analysis")
    cfg = {"configurable": {"thread_id": str(uuid.uuid4())}, "recursion_limit": 200}
    t0, messages = time.monotonic(), []
    for chunk in app.stream({"run_id": cfg["configurable"]["thread_id"][:8], "inputs": inputs},
                            cfg, stream_mode="updates"):
        for delta in chunk.values():
            for m in (delta or {}).get("messages", []) if isinstance(delta, dict) else []:
                messages.append(m)
                on_message(m)
    values = app.get_state(cfg).values

    findings = values.get("findings", {})
    by_type: dict[str, int] = {}
    for f in findings.values():
        by_type[f.get("type", "?")] = by_type.get(f.get("type", "?"), 0) + 1
    critic = values.get("critic") or {}
    summary = {
        "agents": [a.name for a in catalog],
        "llm": providers or None,
        "turns": values.get("turn"),
        "seconds": round(time.monotonic() - t0, 1),
        "findings": len(findings),
        "by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
        "handoffs": sum(1 for m in messages if str(m.get("text", "")).startswith("handoff:")),
        "critic": {"accepted": len(critic.get("accepted", [])), "rejected": len(critic.get("rejected", []))},
        "remediation_plans": len(values.get("remediation_plans", {})),
        "coverage": values.get("coverage", {}),
        "reputation_focus": len(inputs["reputation_focus"]),
        "report_dir": (values.get("report") or {}).get("dir"),
    }
    out = scan_dir / "agents"
    out.mkdir(exist_ok=True)
    (out / "investigation.json").write_text(json.dumps({
        "summary": summary, "inputs": inputs, "messages": messages,
        "plan_log": values.get("plan_log", []), "critic": critic}, indent=2, default=str))
    return summary
