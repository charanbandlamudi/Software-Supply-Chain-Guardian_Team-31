# guardian_v2: orchestration layer for the Supply Chain Guardian

```bash
pip install langgraph univers packaging pytest
python -m pytest -q tests   # Werkzeug 2.0.1 end-to-end scenario, no network needed
```

Wiring your v1 nodes:

```python
from dataclasses import asdict
from guardian_v2.adapters import adapt
from guardian_v2.workflow import GuardianDeps, build_workflow
from guardian_v2.sources import grype, ghsa, kev
from your_agent.state import GuardianState as V1State  # your dataclass

to_v1 = lambda d: V1State(**d)   # or your from_dict
deps = GuardianDeps(
    ingestion=adapt(v1.ingestion, to_v1, asdict),
    dependency_graph=adapt(v1.graph_builder, to_v1, asdict),
    reputation=adapt(v1.package_reputation, to_v1, asdict),
    anomaly=adapt(v1.supply_chain_anomaly, to_v1, asdict),
    container_cicd=adapt(v1.container_cicd, to_v1, asdict),
    reachability=adapt(v1.reachability, to_v1, asdict),
    sources={
        "grype": lambda p: grype.collect(p["inputs"]["grype_report"]),
        "ghsa": lambda p: ghsa.collect(p["purls"]),
        "osv": your_osv_batch_worker,   # map results with sources/osv.normalize
    },
    kev_catalog=lambda: kev.load_catalog("data/mirrors/kev.json"),
    epss_lookup=your_epss_fn,          # cves -> {cve: {"epss", "percentile"}}
    llm_call=groq_then_gemini,         # messages -> raw text
    validator=None,                    # sandbox build/test/rescan, add on Day 2
)
app = build_workflow(deps)
```

See ARCHITECTURE_v2.md for the contracts each node must follow.

## Multi-agent mode

```bash
pip install langgraph univers packaging cvss pytest
cd demo-app && PYTHONPATH=.. python ../run_guardian.py --config guardian.json --auto-approve
```

The terminal shows the live agent conversation. Reports go to
`demo-app/guardian-out/` as `guardian-report.json`, `guardian-report.md` and
`guardian.sarif`.

Open [`ARCHITECTURE.html`](ARCHITECTURE.html) for the interactive visual
architecture, agent hierarchy and innovation showcase.

| Key | Effect |
|---|---|
| `GITHUB_TOKEN` | Enables the GHSA source |
| `ANTHROPIC_API_KEY` / `GROQ_API_KEY` / `GEMINI_API_KEY` | Enable LLM explanations; add `--llm-planner` for LLM routing |

## Architecture controls

- Every agent turn is appended to a SHA-256 hash-chained audit trail (`guardian-out/audit.jsonl`).
- Tool calls are evaluated by the deterministic policy firewall in `guardian_v2/policy.py`; merge, publish, deploy, and public egress actions remain human-only.
- Reports include claim provenance, OpenVEX statements, an in-toto statement, audit-head integrity, and the enriched CycloneDX SBOM.
- Day 2 validation and remediation require Gate 1; change-set/report approval requires Gate 2. No GitHub PR or merge operation is created.
