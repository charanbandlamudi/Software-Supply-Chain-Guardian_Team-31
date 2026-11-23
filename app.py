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
                     key=f"open-{m['scan_id']}", use_container_width=True):
            st.session_state.scan_id = m["scan_id"]

# ---------------------------------------------------------------- header + input
st.markdown("## 🛡️ SOFTWARE SUPPLY CHAIN GUARDIAN")
st.caption("Clone → SBOM (cdxgen) → vulnerability scan (Grype + OSV-Scanner) → interactive dependency graph. "
           "The target repository is treated as untrusted: none of its code or scripts are executed.")

with st.form("scan"):
    c1, c2 = st.columns([5, 1])
    target = c1.text_input("GitHub repository URL", value="https://github.com/juice-shop/juice-shop",
                           label_visibility="collapsed", placeholder="https://github.com/owner/repo")
    go = c2.form_submit_button("Run scan", type="primary", use_container_width=True)

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

tab_graph, tab_steps, tab_files = st.tabs(["Dependency graph", "Scan steps & tools", "Artifacts"])

with tab_graph:
    html = current["artifacts"].get("graph_html")
    if html and Path(html).exists():
        components.html(Path(html).read_text(), height=860, scrolling=False)
        st.caption("Click a node to focus its path and dependencies · `/` to search · `Esc` to clear.")
    else:
        st.error("No graph was produced for this scan.")

with tab_steps:
    st.markdown(steps_md(current))
    st.markdown("**Tool versions & vulnerability database**")
    st.json(current["tools"], expanded=True)

with tab_files:
    st.caption(f"Folder: `{current['scan_dir']}`")
    names = {"sbom": "CycloneDX SBOM (bom.json)", "grype": "Grype raw results (grype.json)",
             "osv": "OSV-Scanner raw results (osv.json)", "graph_json": "Graph + evidence (graph.json)",
             "graph_html": "Interactive graph (dependency_graph.html)"}
    for key, title in names.items():
        p = current["artifacts"].get(key)
        if p and Path(p).exists():
            st.download_button(f"⬇️ {title}", Path(p).read_bytes(), file_name=Path(p).name, key=f"dl-{key}")
    st.download_button("⬇️ Scan metadata (scan.json)", json.dumps(current, indent=2),
                       file_name="scan.json", key="dl-scan")
