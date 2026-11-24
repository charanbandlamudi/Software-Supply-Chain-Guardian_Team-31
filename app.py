"""Software Supply Chain Guardian — Streamlit UI.

Run:  .venv/bin/streamlit run app.py

Scans run in a background thread on the server (pipeline/scan.py); this page only
starts them and polls their scan.json, so closing or refreshing the tab is safe.
"""
from __future__ import annotations

import json
from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components

from pipeline.scan import list_scans, load_scan, parse_target, start_scan

st.set_page_config(page_title="Software Supply Chain Guardian", page_icon="🛡️", layout="wide")

ICON = {"pending": "⚪", "running": "🔄", "ok": "✅", "warn": "⚠️", "failed": "❌", "skipped": "⏭️"}
STATUS_BADGE = {"complete": ("✅ Complete", "green"), "incomplete": ("⚠️ Incomplete", "orange"),
                "failed": ("❌ Failed", "red"), "running": ("🔄 Running", "blue"),
                "interrupted": ("⛔ Interrupted", "gray")}


def steps_md(meta: dict) -> str:
    rows = ["| | Step | Result | Time |", "|---|---|---|---|"]
    for s in meta["steps"].values():
        t = f"{s['seconds']}s" if s["seconds"] is not None else ""
        rows.append(f"| {ICON.get(s['status'], '')} | {s['label']} | {s['detail']} | {t} |")
    return "\n".join(rows)


# ---------------------------------------------------------------- sidebar: history
with st.sidebar:
    st.markdown("### Scans")
    scans = list_scans()
    if not scans:
        st.caption("No scans yet.")
    for m in scans[:25]:
        label, _ = STATUS_BADGE.get(m["status"], (m["status"], "gray"))
        if st.button(f"{m['repo_name']}  \n{m['started_at'][:16].replace('T', ' ')} UTC · {label}",
                     key=f"open-{m['scan_id']}", width="stretch"):
            st.session_state.scan_id = m["scan_id"]

# ---------------------------------------------------------------- header + input
st.markdown("## 🛡️ SOFTWARE SUPPLY CHAIN GUARDIAN")
st.caption("Clone → SBOM (cdxgen) → scan (Grype + OSV-Scanner + Trivy) → interactive dependency graph → multi-agent investigation → Final Guardian Report. "
           "The target repository is treated as untrusted: none of its code or scripts are executed.")

with st.form("scan"):
    c1, c2 = st.columns([5, 1])
    target = c1.text_input("GitHub repository URL", value="https://github.com/juice-shop/juice-shop",
                           label_visibility="collapsed", placeholder="https://github.com/owner/repo")
    go = c2.form_submit_button("Run scan", type="primary", width="stretch")

if go:
    try:
        parse_target(target)
        with st.spinner("Starting scan…"):
            st.session_state.scan_id = start_scan(target)
        st.rerun()
    except (ValueError, RuntimeError) as e:
        st.error(str(e))

scan_id = st.session_state.get("scan_id")
if not scan_id:
    st.info("Enter a GitHub repository URL and press **Run scan**, or open a scan from the sidebar.")
    st.stop()


# ---------------------------------------------------------------- live progress
@st.fragment(run_every=2)
def progress() -> None:
    m = load_scan(scan_id)
    if m is None:
        return
    if m["status"] != "running":
        st.rerun()  # scan finished: redraw the full page with results
    st.markdown(f"### {m['repo_name']} &nbsp; :blue[🔄 Scanning…]")
    st.caption("The scan runs on the server — you can refresh or close this tab and come back.")
    st.markdown(steps_md(m))


current = load_scan(scan_id)
if current is None:
    st.error("Scan not found.")
    st.stop()
if current["status"] == "running":
    progress()
    st.stop()

# ---------------------------------------------------------------- results
label, color = STATUS_BADGE.get(current["status"], (current["status"], "gray"))
st.markdown(f"### {current['repo_name']} &nbsp; :{color}[{label}]")
st.caption(f"Scanned {current['started_at'].replace('T', ' ')} UTC · commit `{(current.get('commit') or 'n/a')[:12]}` "
           f"· scan id `{current['scan_id']}`")

if current["status"] != "complete":
    bad = [s for s in current["steps"].values() if s["status"] in ("failed", "warn", "skipped", "pending", "running")]
    st.warning("This scan is **not complete** — results below may be partial:\n\n" +
               "\n".join(f"- {ICON.get(s['status'], '⛔')} **{s['label']}**: {s['detail'] or s['status']}" for s in bad))

stats = current.get("stats")
if stats:
    sev = stats.get("findings_by_severity", {})
    cols = st.columns(8)
    for col, (lbl, val) in zip(cols, [("Packages", stats["nodes"]), ("Direct", stats["direct"]),
                                      ("Transitive", stats["transitive"]),
                                      ("Vulnerable pkgs", stats["vulnerable_packages"]),
                                      ("Critical", sev.get("CRITICAL", 0)), ("High", sev.get("HIGH", 0)),
                                      ("Medium", sev.get("MEDIUM", 0)), ("Low", sev.get("LOW", 0))]):
        col.metric(lbl, val)

tab_graph, tab_report, tab_agents, tab_repo, tab_steps, tab_files = st.tabs(
    ["Dependency graph", "Final report", "Agent investigation", "Misconfigurations & secrets",
     "Scan steps & tools", "Artifacts"])

with tab_graph:
    html = current["artifacts"].get("graph_html")
    if html and Path(html).exists():
        components.html(Path(html).read_text(encoding="utf-8"), height=860, scrolling=False)
        st.caption("Click a node to focus its path and dependencies · `/` to search · `Esc` to clear.")
    else:
        st.error("No graph was produced for this scan.")

with tab_report:
    rdir = Path(current["scan_dir"]) / "report"
    rj, rh, rpdf = rdir / "guardian-report.json", rdir / "guardian-report.html", rdir / "guardian-report.pdf"
    if not rj.exists():
        st.info("No Final Guardian Report for this scan "
                f"({current['steps'].get('report', {}).get('detail') or 'scan predates the report step'}).")
    else:
        rep = json.loads(rj.read_text())
        ex = rep["executive_summary"]
        c = st.columns(5)
        c[0].metric("Validated findings", ex["total_findings"])
        for col, sev in zip(c[1:], ("CRITICAL", "HIGH", "MEDIUM", "LOW")):
            col.metric(sev.title(), ex["by_severity"].get(sev, 0))
        st.caption(f"{rep['validation']['accepted']} findings passed the evidence validator, "
                   f"{len(rep['validation']['rejected'])} rejected · AI: {ex['ai']['llm_explanations']} LLM explanations "
                   f"verified by the critic, {ex['ai']['template_explanations']} templates")
        d1, d2, d3 = st.columns(3)
        d1.download_button("⬇️ Report (PDF)", rpdf.read_bytes() if rpdf.exists() else b"", file_name="guardian-report.pdf",
                           disabled=not rpdf.exists(), key="rep-pdf", width="stretch")
        d2.download_button("⬇️ Report (HTML)", rh.read_bytes(), file_name="guardian-report.html", key="rep-html", width="stretch")
        d3.download_button("⬇️ Report (JSON)", rj.read_bytes(), file_name="guardian-report.json", key="rep-json", width="stretch")
        components.html(rh.read_text(), height=1100, scrolling=True)

with tab_agents:
    adir = Path(current["artifacts"].get("agents_dir") or Path(current["scan_dir"]) / "agents")
    inv_p, rep_p = adir / "investigation.json", adir / "guardian-report.json"
    if not inv_p.exists():
        st.info("The multi-agent investigation has not run for this scan "
                f"({current['steps'].get('agents', {}).get('detail') or 'scan predates the agent step'}).")
    else:
        inv = json.loads(inv_p.read_text())
        rep = json.loads(rep_p.read_text()) if rep_p.exists() else {}
        sm = inv["summary"]
        cols = st.columns(6)
        for col, (lbl, val) in zip(cols, [("Agents", len(sm["agents"])), ("Supervisor turns", sm["turns"]),
                                          ("Handoffs", sm["handoffs"]), ("Findings", sm["findings"]),
                                          ("Remediation plans", sm["remediation_plans"]),
                                          ("Claims verified", f"{sm['critic']['accepted']}/"
                                                              f"{sm['critic']['accepted'] + sm['critic']['rejected']}")]):
            col.metric(lbl, val)
        st.caption(f"LLM: {', '.join(sm['llm']) if sm['llm'] else 'none configured — explanations are deterministic templates'}"
                   f" · ran in {sm['seconds']}s · registry metadata checked for {sm['reputation_focus']} packages "
                   "(direct dependencies + scanner-flagged)")

        st.markdown("#### Agent conversation")
        st.caption("The supervisor picks which agents run each turn from data readiness and the handoff requests "
                   "agents send each other. Every decision is logged.")
        st.dataframe([{"Turn": m.get("turn"), "From": m.get("from"),
                       "To": ", ".join(m["to"]) if isinstance(m.get("to"), list) else m.get("to"),
                       "Message": m.get("text")} for m in inv["messages"]],
                     width="stretch", hide_index=True, height=420)

        fs = rep.get("findings", [])
        st.markdown(f"#### Prioritised findings ({len(fs)})")
        st.caption("Score, confidence and SSVC are deterministic and explainable; reachability comes from source "
                   "import analysis. Non-CVE types (typosquats, install scripts, unpinned images…) come from the "
                   "anomaly and CI/CD agents.")
        st.dataframe([{"Score": f.get("score"), "Type": f.get("type"), "ID": f.get("canonical_id"),
                       "Component": (f.get("component_purl") or "").replace("pkg:", ""),
                       "SSVC": (f.get("ssvc") or {}).get("decision"), "Confidence": f.get("confidence"),
                       "Reachability": f.get("reachability_state"), "KEV": f.get("kev"),
                       "EPSS": (f.get("epss") or {}).get("epss") if isinstance(f.get("epss"), dict) else f.get("epss"),
                       "Status": f.get("resolution")} for f in fs], width="stretch", hide_index=True)

        explained = [(f, a) for f in fs for a in (f.get("ai_inferences") or [])]
        st.markdown(f"#### Evidence-checked explanations ({len(explained)})")
        st.caption("Each claim cites evidence IDs and passed the critic agent (no invented IDs, scores or versions). "
                   "'template' = deterministic text because no LLM key is set; 'inference' = LLM-written.")
        for f, a in explained[:25]:
            with st.expander(f"[{a.get('kind')}] {f.get('canonical_id')} · {(f.get('component_purl') or '').replace('pkg:', '')}"):
                st.write(a.get("statement"))
                st.caption(f"Next step: {a.get('next_step')} · evidence: {', '.join(a.get('evidence_ids', [])[:3])}")

        plans = rep.get("remediation_plans", {})
        if plans:
            st.markdown(f"#### Proposed remediation ({len(plans)})")
            st.caption("Proposed only — nothing is changed. The human approval gate and sandbox validation run "
                       "in the CLI (`guardian_v2/run_guardian.py`), not in this unattended web run.")
            st.dataframe([{"Component": (p.get("component") or "").replace("pkg:", ""), "Action": p.get("action"),
                           "Target": p.get("target_version"), "Status": p.get("status"),
                           "Rationale": p.get("rationale")} for p in plans.values()],
                         width="stretch", hide_index=True)

        with st.expander("Source coverage"):
            st.json(sm["coverage"])

with tab_repo:
    gj = current["artifacts"].get("graph_json")
    rf = json.loads(Path(gj).read_text(encoding="utf-8")).get("repo_findings") if gj and Path(gj).exists() else None
    if current["steps"].get("trivy", {}).get("status") != "ok" or rf is None:
        st.info("Trivy did not run successfully for this scan, so there are no misconfiguration or "
                "secret results. This is not evidence that there are none.")
    else:
        mis, sec = rf.get("misconfigurations", []), rf.get("secrets", [])
        c1, c2 = st.columns(2)
        c1.metric("Misconfigurations (failed checks)", len(mis))
        c2.metric("Secrets detected", len(sec))
        st.markdown("#### Misconfigurations")
        st.caption("Trivy checks on Dockerfiles, CI workflows, Kubernetes/Terraform and other config files. "
                   "Files are read as data, never built or run.")
        if mis:
            st.dataframe([{"Severity": m["severity"], "Check": m["id"], "Title": m["title"],
                           "File": m["file"], "Line": m["start_line"], "Message": m["message"],
                           "Fix": m["resolution"]} for m in mis], width="stretch", hide_index=True)
        else:
            st.caption("No failed checks reported.")
        st.markdown("#### Secrets")
        st.caption("Secret values are never shown or stored by the Guardian — only the rule, file and line. "
                   "A match is a candidate: verify before treating it as a real credential.")
        if sec:
            st.dataframe([{"Severity": x["severity"], "Rule": x["rule_id"], "Title": x["title"],
                           "File": x["file"], "Line": x["start_line"], "Value": "•••• redacted"}
                          for x in sec], width="stretch", hide_index=True)
        else:
            st.caption("No secrets reported.")

with tab_steps:
    st.markdown(steps_md(current))
    st.markdown("**Tool versions & vulnerability database**")
    st.json(current["tools"], expanded=True)

with tab_files:
    st.caption(f"Folder: `{current['scan_dir']}`")
    names = {"sbom": "CycloneDX SBOM (bom.json)", "grype": "Grype raw results (grype.json)",
             "osv": "OSV-Scanner raw results (osv.json)", "trivy": "Trivy raw results (trivy.json)", "graph_json": "Graph + evidence (graph.json)",
             "graph_html": "Interactive graph (dependency_graph.html)"}
    adir = Path(current["scan_dir"]) / "agents"
    for fname, title in (("guardian-report.md", "Agent report (Markdown)"), ("guardian-report.json", "Agent report (JSON)"),
                         ("guardian.sarif", "Agent findings (SARIF)"), ("investigation.json", "Agent conversation (investigation.json)")):
        if (adir / fname).exists():
            st.download_button(f"⬇️ {title}", (adir / fname).read_bytes(), file_name=fname, key=f"dl-ag-{fname}")
    for key, title in names.items():
        p = current["artifacts"].get(key)
        if p and Path(p).exists():
            st.download_button(f"⬇️ {title}", Path(p).read_bytes(), file_name=Path(p).name, key=f"dl-{key}")
    st.download_button("⬇️ Scan metadata (scan.json)", json.dumps(current, indent=2),
                       file_name="scan.json", key="dl-scan")
