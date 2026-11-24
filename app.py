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
from remediation.approval import record_decision, save_approved_plan
from remediation.planner import generate_plan, save_plan
from remediation.npm_resolver import resolve_plan

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
st.caption("Clone → SBOM (cdxgen) → scan (Grype + OSV-Scanner + Trivy) → interactive dependency graph. "
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

tab_graph, tab_repo, tab_remediation, tab_steps, tab_files = st.tabs(
    ["Dependency graph", "Misconfigurations & secrets", "Remediation", "Scan steps & tools", "Artifacts"])

with tab_graph:
    html = current["artifacts"].get("graph_html")
    if html and Path(html).exists():
        components.html(Path(html).read_text(), height=860, scrolling=False)
        st.caption("Click a node to focus its path and dependencies · `/` to search · `Esc` to clear.")
    else:
        st.error("No graph was produced for this scan.")

with tab_repo:
    gj = current["artifacts"].get("graph_json")
    rf = json.loads(Path(gj).read_text()).get("repo_findings") if gj and Path(gj).exists() else None
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
                           "Fix": m["resolution"]} for m in mis], use_container_width=True, hide_index=True)
        else:
            st.caption("No failed checks reported.")
        st.markdown("#### Secrets")
        st.caption("Secret values are never shown or stored by the Guardian — only the rule, file and line. "
                   "A match is a candidate: verify before treating it as a real credential.")
        if sec:
            st.dataframe([{"Severity": x["severity"], "Rule": x["rule_id"], "Title": x["title"],
                           "File": x["file"], "Line": x["start_line"], "Value": "•••• redacted"}
                          for x in sec], use_container_width=True, hide_index=True)
        else:
            st.caption("No secrets reported.")

with tab_remediation:
    st.markdown("#### Remediation actions")
    st.caption("These decisions are recorded only in the plan. They do not run npm or modify a repository.")

    plans_dir = Path("data/remediation/plans")
    plans_dir.mkdir(parents=True, exist_ok=True)
    remediation_plan = plans_dir / f"{current['scan_id']}.json"
    latest_plan = plans_dir / "latest_plan.json"
    scan_dir = Path("data/scans") / current["scan_id"]
    grype_path = scan_dir / "scanner_results" / "grype.json"
    graph_path = scan_dir / "graphs" / "graph.json"

    c_generate, c_resolve = st.columns(2)
    if c_generate.button("Generate remediation plan", use_container_width=True):
        if not grype_path.exists() or not graph_path.exists():
            st.error("This scan does not contain both graph.json and grype.json.")
        else:
            try:
                graph = json.loads(graph_path.read_text())
                plan = generate_plan(graph, grype_path)
                save_approved_plan(plan, remediation_plan)
                save_approved_plan(plan, latest_plan)
                st.success(f"Generated {len(plan['changes'])} package-level remediation actions.")
                st.rerun()
            except Exception as exc:
                st.error(f"Could not generate the plan: {type(exc).__name__}: {exc}")

    if c_resolve.button("Investigate npm dependencies", use_container_width=True):
        if not remediation_plan.exists():
            st.error("Generate a remediation plan first.")
        else:
            repository = scan_dir / "repo"
            if not repository.exists() or not (repository / "package-lock.json").exists():
                st.warning(
                    "Dependency investigation needs the scanned repository and package-lock.json. "
                    "The current snapshot does not contain one."
                )
            else:
                plan = json.loads(remediation_plan.read_text())
                resolved = resolve_plan(repository, plan)
                save_approved_plan(resolved, remediation_plan)
                save_approved_plan(resolved, latest_plan)
                st.success("Dependency investigation added to the plan.")
                st.rerun()

    if not remediation_plan.exists():
        st.info("No plan exists for this scan. Generate one above.")
    else:
        plan = json.loads(remediation_plan.read_text())
        reviewer = st.text_input("Reviewer name", value="anonymous", key="remediation-reviewer")
        actions = plan.get("changes", [])
        if not actions:
            st.info("The plan has no remediation actions.")
        else:
            for action in actions:
                action_id = action["action_id"]
                with st.container(border=True):
                    c1, c2, c3 = st.columns([3, 2, 2])
                    c1.markdown(f"**{action['package']}**  \n"
                                f"`{action['current_version']}` -> `{action['recommended_version'] or 'none'}`")
                    c2.markdown(f"**Severity:** {action['severity']}  \n"
                                f"**Findings:** {action['vulnerability_count']}")
                    c3.markdown(f"**Status:** `{action['status']}`")

                    st.caption(
                        f"Vulnerabilities: {', '.join(action.get('vulnerability_ids', []))}"
                    )
                    st.caption(
                        f"Dependency: {action['dependency_type']} · "
                        f"Parents: {', '.join(action.get('parent_ids', [])) or 'none'}"
                    )

                    b1, b2 = st.columns(2)
                    if b1.button("Approve", key=f"approve-{action_id}", use_container_width=True):
                        current_plan = json.loads(remediation_plan.read_text())
                        updated = record_decision(current_plan, action_id, "approve", reviewer)
                        save_approved_plan(updated, remediation_plan)
                        st.success(f"Approved {action['package']}")
                        st.rerun()
                    if b2.button("Reject", key=f"reject-{action_id}", use_container_width=True):
                        current_plan = json.loads(remediation_plan.read_text())
                        updated = record_decision(current_plan, action_id, "reject", reviewer)
                        save_approved_plan(updated, remediation_plan)
                        st.warning(f"Rejected {action['package']}")
                        st.rerun()

            approved = [a for a in actions if a["status"] == "approved"]
            rejected = [a for a in actions if a["status"] == "rejected"]
            st.caption(f"{len(approved)} approved · {len(rejected)} rejected")
            st.download_button(
                "Download approved plan",
                remediation_plan.read_bytes(),
                file_name="latest_plan.json",
                mime="application/json",
            )

with tab_steps:
    st.markdown(steps_md(current))
    st.markdown("**Tool versions & vulnerability database**")
    st.json(current["tools"], expanded=True)

with tab_files:
    st.caption(f"Folder: `{current['scan_dir']}`")
    names = {"sbom": "CycloneDX SBOM (bom.json)", "grype": "Grype raw results (grype.json)",
             "osv": "OSV-Scanner raw results (osv.json)", "trivy": "Trivy raw results (trivy.json)", "graph_json": "Graph + evidence (graph.json)",
             "graph_html": "Interactive graph (dependency_graph.html)"}
    for key, title in names.items():
        p = current["artifacts"].get(key)
        if p and Path(p).exists():
            st.download_button(f"⬇️ {title}", Path(p).read_bytes(), file_name=Path(p).name, key=f"dl-{key}")
    st.download_button("⬇️ Scan metadata (scan.json)", json.dumps(current, indent=2),
                       file_name="scan.json", key="dl-scan")
