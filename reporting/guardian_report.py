"""Final Guardian Report: evidence-validated findings -> JSON, HTML and PDF.

Inputs (all from one scan folder): scan.json, sbom/bom.json, graphs/graph.json (dependency
graph + merged Grype/OSV-Scanner/Trivy evidence), scanner_results/*.json (raw tool output)
and agents/guardian-report.json (agent scores, explanations, remediation plans).

Every finding is a Pydantic model (the schema in the problem statement plus problem /
remediation fields) and passes EvidenceValidator before it can appear in the report:
  - vulnerability identifiers must exist in raw scanner output or an authoritative source
    the agents queried (OSV.dev / npm audit), never only in LLM text;
  - package versions must exist in the SBOM;
  - dependency paths must be real edges in the dependency graph;
  - fixed versions must be ones a scanner or advisory reported;
  - secret findings must not carry a value.
Rejected findings are listed in the report's validation section, never silently dropped.
"""
from __future__ import annotations

import html
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

SEV = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
Verification = Literal["multi_scanner_confirmed", "scanner_confirmed", "authoritative_source",
                       "registry_confirmed", "static_check", "suspicious_indicator", "potential_risk",
                       "unverified_hypothesis"]
OUR_SCANNERS = {"grype": "Grype", "osv-scanner": "OSV-Scanner", "trivy": "Trivy"}
LIVE_SOURCES = {"osv": "OSV.dev API", "npm-audit": "npm audit API", "pypi-osv": "PyPI/OSV API", "ghsa": "GitHub Advisory API"}

# Segment definitions: (key, title, what-the-risk-is). Order = report order.
SEGMENTS = [
    ("vulnerability", "Known vulnerabilities (CVE / GHSA)",
     "The installed version of a dependency falls inside the affected range of a published security advisory. "
     "The flaw is in third-party code shipped with the application; whether it is exploitable depends on how "
     "the vulnerable code is used, which the scanners do not determine."),
    ("malicious", "Malicious packages",
     "The registry has removed this package version as malicious (replaced by a security holding package). "
     "Malicious packages typically steal credentials or run code at install time."),
    ("typosquat", "Typosquat candidates",
     "The package name is within two edits of a popular package, a common way to trick developers into "
     "installing a look-alike. Name similarity alone does not prove malicious intent: these are unverified "
     "hypotheses until a person confirms the package is the one intended. Long-established packages are "
     "automatically cleared."),
    ("integrity", "Lockfile, integrity and source risks",
     "The lockfile entry does not match the official registry (different integrity hash, unexpected download "
     "host, or a name that could be resolved from a public registry instead of a private one). This can mean "
     "tampering or dependency confusion."),
    ("install_script", "Install-time scripts",
     "The package declares preinstall/install/postinstall scripts, so it runs code on every developer machine "
     "and CI runner that installs it. This is how most npm supply-chain attacks execute, so these packages "
     "deserve extra scrutiny even when they are legitimate."),
    ("suspicious_update", "Suspiciously recent releases",
     "The locked version was published inside the 14-day cooling-off window. Hijacked releases are usually "
     "detected and pulled within days, so very new versions carry elevated risk."),
    ("deprecated", "Deprecated, yanked or unpublished versions",
     "The registry marks this version as deprecated or yanked (or it is no longer published). It will not get "
     "security fixes and often has known problems."),
    ("cicd", "CI/CD workflow risks",
     "GitHub Actions referenced by a tag or branch instead of a commit SHA, or workflows with risky triggers or "
     "permissions. A re-pointed tag runs attacker code with the pipeline's secrets (as in the "
     "tj-actions/changed-files compromise, CVE-2025-30066)."),
    ("container", "Container image risks",
     "Base images referenced by a mutable tag instead of an immutable digest. The tag can be re-pointed to a "
     "different (possibly vulnerable or malicious) image without any change in the repository."),
    ("misconfiguration", "Infrastructure & configuration misconfigurations",
     "Trivy policy checks failed on Dockerfiles, Terraform, Kubernetes or other configuration files (for example "
     "plain HTTP listeners or open security groups). Files are read as data; nothing is built or deployed."),
    ("secret", "Exposed secrets",
     "Credential-like values (private keys, tokens) are committed to the repository. Anyone with read access, and "
     "anyone who ever cloned it, has them. Values are redacted in this report; each match is a candidate to verify."),
]
SEGMENT_TITLE = {k: t for k, t, _ in SEGMENTS}

# type -> (segment, default severity for non-CVE findings, verification status)
TYPE_INFO = {
    "vulnerability": ("vulnerability", None, None),
    "malicious_package": ("malicious", "CRITICAL", "registry_confirmed"),
    "typosquat_suspect": ("typosquat", "MEDIUM", "unverified_hypothesis"),
    "dependency_confusion": ("integrity", "HIGH", "suspicious_indicator"),
    "integrity_mismatch": ("integrity", "HIGH", "suspicious_indicator"),
    "lockfile_tampering": ("integrity", "HIGH", "suspicious_indicator"),
    "untrusted_resolved_url": ("integrity", "HIGH", "suspicious_indicator"),
    "unexpected_dependency": ("integrity", "MEDIUM", "suspicious_indicator"),
    "install_script": ("install_script", "MEDIUM", "potential_risk"),
    "suspicious_update": ("suspicious_update", "MEDIUM", "suspicious_indicator"),
    "yanked_or_deprecated": ("deprecated", "LOW", "registry_confirmed"),
    "unpublished_version": ("deprecated", "HIGH", "registry_confirmed"),
    "unpinned_action": ("cicd", "MEDIUM", "static_check"),
    "dangerous_workflow": ("cicd", "HIGH", "static_check"),
    "excessive_permissions": ("cicd", "MEDIUM", "static_check"),
    "unpinned_base_image": ("container", "LOW", "static_check"),
    "misconfiguration": ("misconfiguration", None, "scanner_confirmed"),
    "exposed_secret": ("secret", None, "scanner_confirmed"),
}
DETECTOR = {"cicd": "Guardian CI/CD agent", "container": "Guardian CI/CD agent"}


# ------------------------------------------------------------------ schema
class Remediation(BaseModel):
    action: str
    target_version: str | None = None
    rationale: str | None = None
    blocker: str | None = None
    status: str = "proposed"
    source: Literal["agent_plan", "scanner_fix"] = "agent_plan"
    requires_human_approval: bool = True


class Finding(BaseModel):
    """Problem-statement schema + problem/remediation context. Scanner facts and agent analysis are
    separate fields; ai_assessment is always labelled with how it was produced."""
    finding_id: str
    category: str
    segment: str
    finding_type: str
    component: str
    installed_version: str | None
    identifier: str
    aliases: list[str] = Field(default_factory=list)
    severity: Severity
    severity_basis: str
    source_tool: list[str]
    dependency_type: Literal["direct", "transitive", "unresolved", "root", "n/a"]
    dependency_path: list[str] = Field(default_factory=list)
    dependency_path_ids: list[str] = Field(default_factory=list, exclude=True)
    location: str | None = None
    evidence_reference: list[str]
    fixed_version: str | None
    reported_fixed_versions: list[str] = Field(default_factory=list, exclude=True)
    problem: str
    ai_assessment: str | None
    ai_assessment_kind: Literal["llm_inference_critic_verified", "deterministic_template", "none"]
    remediation: Remediation | None
    risk_score: float | None
    ssvc: str | None
    reachability: str | None
    kev: bool | None = None
    epss: float | None = None
    confidence: Literal["high", "medium", "low"]
    verification_status: Verification
    scanner_views: dict = Field(default_factory=dict)
    severity_disagreement: bool = False


# ------------------------------------------------------------------ validation
class EvidenceValidator:
    def __init__(self, scan_dir: Path, graph: dict, agent_report: dict):
        bom = json.loads((scan_dir / "sbom" / "bom.json").read_text())
        self.sbom_versions = {(f"{c['group']}/{c['name']}" if c.get("group") else c["name"], c.get("version"))
                              for c in bom.get("components", [])}
        self.lock_purls = {c["purl"] for c in agent_report.get("inventory", {}).get("components", [])}
        self.edges = {(e["from"], e["to"]) for e in graph.get("edges", [])}
        ids: set[str] = set()
        res = scan_dir / "scanner_results"
        if (res / "grype.json").exists():
            for m in json.loads((res / "grype.json").read_text()).get("matches", []):
                ids.add(m["vulnerability"]["id"])
                ids |= {r["id"] for r in m.get("relatedVulnerabilities", []) if r.get("id")}
        if (res / "osv.json").exists():
            for r in json.loads((res / "osv.json").read_text()).get("results", []):
                for p in r.get("packages", []):
                    for v in p.get("vulnerabilities", []):
                        ids |= {v["id"], *(v.get("aliases") or [])}
        if (res / "trivy.json").exists():
            for r in json.loads((res / "trivy.json").read_text()).get("Results") or []:
                for v in r.get("Vulnerabilities") or []:
                    ids |= {v["VulnerabilityID"], *(v.get("VendorIDs") or [])}
        self.scanner_ids = {i.upper() for i in ids}
        # Advisories the agents fetched from authoritative APIs (OSV.dev, npm audit), with evidence records.
        self.authoritative_ids = {i.upper() for f in agent_report.get("findings", []) if f.get("type") == "vulnerability"
                                  and set(f.get("sources", [])) & set(LIVE_SOURCES) and f.get("evidence_ids")
                                  for i in [f.get("canonical_id"), *(f.get("aliases") or [])] if i}

    def check(self, f: Finding) -> list[str]:
        reasons = []
        if f.finding_type == "vulnerability":
            ids = {f.identifier.upper(), *(a.upper() for a in f.aliases)}
            if not ids & (self.scanner_ids | self.authoritative_ids):
                reasons.append(f"identifier {f.identifier} not found in scanner output or an authoritative source")
            if f.fixed_version and f.fixed_version not in f.reported_fixed_versions:
                reasons.append(f"fixed version {f.fixed_version} was not reported by any source")
        if f.installed_version is not None and (f.component, f.installed_version) not in self.sbom_versions:
            purl = f"pkg:npm/{f.component.replace('@', '%40')}@{f.installed_version}"
            if purl not in self.lock_purls:
                reasons.append(f"{f.component}@{f.installed_version} is not in the SBOM or lockfile")
        for a, b in zip(f.dependency_path_ids, f.dependency_path_ids[1:]):
            if (a, b) not in self.edges:
                reasons.append(f"dependency path edge {a} -> {b} is not in the dependency graph")
                break
        if f.finding_type == "exposed_secret" and "redacted" not in f.problem.lower():
            reasons.append("secret finding must not carry a value")
        return reasons


# ------------------------------------------------------------------ assembly
def _short(purl: str) -> str:
    return purl.split("/", 1)[-1].replace("%40", "@") if purl.startswith("pkg:") else purl


def _sev_band_from_cvss(score: float | None) -> str | None:
    if score is None:
        return None
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"


def build_report(scan_dir: Path) -> dict:
    scan_dir = Path(scan_dir)
    meta = json.loads((scan_dir / "scan.json").read_text())
    graph = json.loads((scan_dir / "graphs" / "graph.json").read_text())
    rep_path = scan_dir / "agents" / "guardian-report.json"
    rep = json.loads(rep_path.read_text()) if rep_path.exists() else {"findings": [], "remediation_plans": {}}
    inv_path = scan_dir / "agents" / "investigation.json"
    inv = json.loads(inv_path.read_text()) if inv_path.exists() else {}
    bom = json.loads((scan_dir / "sbom" / "bom.json").read_text())
    purl_to_ref = {c["purl"]: c.get("bom-ref", c["purl"]) for c in bom.get("components", []) if c.get("purl")}
    nodes = {n["id"]: n for n in graph["nodes"]}
    label = lambda nid: f"{nodes[nid]['name']}@{nodes[nid]['version']}" if nid in nodes else nid
    repo_prefix = str(scan_dir / "repo") + "/"
    rel = lambda p: (p or "").replace(repo_prefix, "").replace(str(scan_dir.relative_to(scan_dir.parents[2])) + "/repo/", "") \
        if p else p
    plans = rep.get("remediation_plans", {})
    validator = EvidenceValidator(scan_dir, graph, rep)

    drafts: list[Finding] = []
    for f in rep.get("findings", []):
        ftype = f.get("type", "vulnerability")
        seg, default_sev, verification = TYPE_INFO.get(ftype, ("integrity", "MEDIUM", "potential_risk"))
        purl = f.get("component_purl") or ""
        node = nodes.get(purl_to_ref.get(purl) or purl.replace("%40", "@"))
        loc = f.get("location") or {}
        location = f"{rel(loc.get('file'))}:{loc.get('line')}" if loc.get("file") else None
        if node:
            component, version, dep_type = node["name"], node["version"], node["dep_type"]
            path_ids = node.get("path_ids", [])
        elif purl.startswith("pkg:"):
            name_ver = _short(purl)
            component, version = name_ver.rsplit("@", 1) if "@" in name_ver[1:] else (name_ver, None)
            dep_type, path_ids = "unresolved", []
        else:
            component, version, dep_type, path_ids = rel(loc.get("file") or purl.replace("file:", "")), None, "n/a", []

        sources = f.get("sources", [])
        views, disagreement, reported_fixed = {}, False, []
        if ftype == "vulnerability":
            ids = {i.upper() for i in [f.get("canonical_id"), *(f.get("aliases") or [])] if i}
            match = next((v for v in (node or {}).get("vulns", []) if ids & {i.upper() for i in v["ids"]}), None)
            if match:
                views = match["by_tool"]
                disagreement = match.get("severity_disagreement", False)
                reported_fixed = sorted({fv for t in views.values() for fv in t["fixed_versions"]})
                severity, basis = match["severity"], "worst severity reported by the scanners"
            else:
                severity = _sev_band_from_cvss((f.get("cvss") or {}).get("score")) or "UNKNOWN"
                basis = "CVSS band from advisory data (not reported by Grype/OSV-Scanner/Trivy)"
            if f.get("recommended_fix"):
                reported_fixed = sorted(set(reported_fixed) | {f["recommended_fix"]})
            fixed = f.get("recommended_fix") or (reported_fixed[0] if reported_fixed else None)
            ours = sorted({OUR_SCANNERS[s] for s in sources if s in OUR_SCANNERS})
            tools = ours + sorted({LIVE_SOURCES[s] for s in sources if s in LIVE_SOURCES})
            verification = ("multi_scanner_confirmed" if len(ours) >= 2 else
                            "scanner_confirmed" if ours else "authoritative_source")
            title = (f.get("summary") or "").strip().split("\n")[0][:200]
            cvss = (f.get("cvss") or {}).get("score")
            problem = (f"{title or f.get('canonical_id')} in {component}@{version}."
                       + (f" CVSS {cvss}." if cvss is not None else "")
                       + (f" Reached via {' → '.join(label(p) for p in path_ids)}." if len(path_ids) > 1 else ""))
        else:
            fixed = None
            if ftype in ("misconfiguration", "exposed_secret"):
                severity = (f.get("tool_severity") or "UNKNOWN").upper()
                basis, tools = "severity reported by Trivy", ["Trivy"]
            else:
                severity, basis = default_sev, "Guardian heuristic for this risk type (no CVSS exists)"
                tools = [DETECTOR.get(seg, "Guardian anomaly agent")] + (
                    ["npm registry metadata"] if ftype in ("install_script", "suspicious_update", "yanked_or_deprecated",
                                                           "malicious_package", "unpublished_version") else [])
            problem = (f.get("summary") or f.get("canonical_id") or ftype).strip()
            if location and location.rsplit(":", 1)[0] not in problem:
                problem += f" ({location})"

        ai = next(iter(f.get("ai_inferences") or []), None)
        plan = plans.get(f"PLAN::{purl}")
        if plan and plan.get("action"):
            remediation = Remediation(action=plan["action"], target_version=plan.get("target_version"),
                                      rationale=plan.get("rationale"), blocker=plan.get("compatibility_blocker"),
                                      status=plan.get("status", "proposed"))
        elif ftype == "vulnerability" and fixed:
            remediation = Remediation(action="upgrade", target_version=fixed, source="scanner_fix",
                                      rationale="Upgrade to the first fixed version reported by the advisory sources.")
        elif f.get("recommended_action"):
            remediation = Remediation(action="fix_config", rationale=f["recommended_action"], source="scanner_fix")
        else:
            remediation = None
        drafts.append(Finding(
            finding_id="", category=SEGMENT_TITLE[seg], segment=seg, finding_type=ftype,
            component=component, installed_version=version, identifier=f.get("canonical_id") or ftype.upper(),
            aliases=[a for a in (f.get("aliases") or []) if a != f.get("canonical_id")],
            severity=severity if severity in SEV else "UNKNOWN", severity_basis=basis, source_tool=tools,
            dependency_type=dep_type, dependency_path=[label(p) for p in path_ids], dependency_path_ids=path_ids,
            location=location, evidence_reference=f.get("evidence_ids", [])[:6] + [
                f"scanner_results/{n}" for n in ("grype.json", "osv.json", "trivy.json")
                if OUR_SCANNERS.get(n.split(".")[0].replace("osv", "osv-scanner")) in tools],
            fixed_version=fixed, reported_fixed_versions=reported_fixed, problem=problem,
            ai_assessment=ai.get("statement") if ai else None,
            ai_assessment_kind=("llm_inference_critic_verified" if ai and ai.get("kind") == "inference"
                                else "deterministic_template" if ai else "none"),
            remediation=remediation, risk_score=f.get("score"), ssvc=(f.get("ssvc") or {}).get("decision"),
            reachability=f.get("reachability_state"), kev=f.get("kev"),
            epss=(f.get("epss") or {}).get("epss") if isinstance(f.get("epss"), dict) else None,
            confidence=(f.get("confidence") or "Low").lower() if (f.get("confidence") or "").lower() in ("high", "medium", "low") else "low",
            verification_status=verification, scanner_views=views, severity_disagreement=disagreement))

    order = {k: i for i, (k, _, _) in enumerate(SEGMENTS)}
    drafts.sort(key=lambda x: (order[x.segment], SEV.index(x.severity), -(x.risk_score or 0), x.component))
    accepted, rejected = [], []
    for d in drafts:
        reasons = validator.check(d)
        (rejected.append({"identifier": d.identifier, "component": d.component, "reasons": reasons})
         if reasons else accepted.append(d))
    for i, d in enumerate(accepted, 1):
        d.finding_id = f"F-{i:03d}"

    stats = graph.get("stats", {})
    by_seg = Counter(d.segment for d in accepted)
    by_sev = Counter(d.severity for d in accepted)
    depth = Counter(len(n.get("path_ids", [])) - 1 for n in graph["nodes"] if n.get("path_ids"))
    introducers = Counter(label(d.dependency_path_ids[1]) for d in accepted
                          if d.finding_type == "vulnerability" and len(d.dependency_path_ids) > 1)
    vuln_nodes = [n for n in graph["nodes"] if n.get("vulns")]
    combos = Counter(" + ".join(sorted(v["source_tools"])) for n in vuln_nodes for v in n["vulns"])
    disagreements = [{"component": f"{n['name']}@{n['version']}", "identifier": v["id"],
                      "views": {t: r["severity"] for t, r in v["by_tool"].items()},
                      "kind": "severity" if v.get("severity_disagreement") else "reported by one scanner only"}
                     for n in vuln_nodes for v in n["vulns"]
                     if v.get("severity_disagreement") or len(v["source_tools"]) < len(stats.get("scanners", [])) >= 2]
    critic = (inv.get("summary") or {}).get("critic") or {}
    llm = (inv.get("summary") or {}).get("llm")
    steps = {k: {"label": s["label"], "status": s["status"], "detail": s["detail"]}
             for k, s in meta["steps"].items() if k != "report"}
    status = meta.get("status")
    if status == "running":   # the report is written as the last step, before the scan's final status is set
        status = "complete" if all(s["status"] in ("ok", "skipped") for s in steps.values()) else "incomplete"

    return {
        "schema": "ssg-guardian-report/1",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": {"repository": meta.get("target"), "name": meta.get("repo_name"), "commit": meta.get("commit"),
                   "scanned_at": meta.get("started_at"), "scan_id": meta.get("scan_id"),
                   "scan_status": status},
        "executive_summary": {
            "total_findings": len(accepted), "by_severity": {s: by_sev[s] for s in SEV if by_sev[s]},
            "by_category": {SEGMENT_TITLE[k]: by_seg[k] for k, _, _ in SEGMENTS if by_seg[k]},
            "packages": stats.get("nodes"), "vulnerable_packages": stats.get("vulnerable_packages"),
            "anomalous_packages": sum(1 for n in graph["nodes"] if ((n.get("agent") or {}).get("suspicious"))),
            "top_risks": [d.finding_id for d in sorted(accepted, key=lambda d: -(d.risk_score or 0))[:8]],
            "ai": {"provider": llm, "llm_explanations": sum(1 for d in accepted if d.ai_assessment_kind.startswith("llm")),
                   "template_explanations": sum(1 for d in accepted if d.ai_assessment_kind == "deterministic_template"),
                   "critic_accepted": critic.get("accepted"), "critic_rejected": critic.get("rejected")},
        },
        "methodology": {"pipeline_steps": steps, "tools": meta.get("tools", {}),
                        "agents": (inv.get("summary") or {}).get("agents", []),
                        "agent_turns": (inv.get("summary") or {}).get("turns"),
                        "agent_coverage": (inv.get("summary") or {}).get("coverage", {})},
        "sbom": {"components": stats.get("nodes"), "direct": stats.get("direct"), "transitive": stats.get("transitive"),
                 "not_linked": stats.get("unresolved"), "edges": stats.get("edges"),
                 "ecosystems": dict(Counter(n.get("ecosystem") for n in graph["nodes"]).most_common())},
        "dependency_analysis": {"depth_distribution": dict(sorted(depth.items())),
                                "vulnerable_via_direct_dependency": dict(introducers.most_common(10)),
                                "shared_vulnerable_packages": sorted(
                                    [{"package": f"{n['name']}@{n['version']}", "parents": len(n.get("parent_ids", [])),
                                      "vulnerabilities": len(n["vulns"])} for n in vuln_nodes],
                                    key=lambda x: -x["parents"])[:10]},
        "scanner_agreement": {"by_scanner_combination": dict(combos.most_common()), "disagreements": disagreements},
        "findings": [d.model_dump() for d in accepted],
        "remediation_summary": dict(Counter(d.remediation.action for d in accepted if d.remediation)),
        "validation": {"accepted": len(accepted), "rejected": rejected, "rules": [
            "vulnerability identifiers must exist in raw scanner output or an authoritative advisory source",
            "component versions must exist in the SBOM or lockfile", "dependency paths must be graph edges",
            "fixed versions must be reported by a scanner or advisory", "secret values are never included"]},
        "limitations": [
            "Findings show that a version contains a known flaw or risk signal; exploitability and runtime "
            "reachability are not proven (reachability is import-based).",
            "Repositories without a committed lockfile are resolved at scan time; versions can differ from deployments.",
            "Registry metadata (install scripts, deprecation, release age) is fetched for direct dependencies and "
            "scanner-flagged packages only.",
            "AI explanations are generated from structured evidence and checked by the critic agent; they are "
            "summaries, not new evidence.",
            "Secret matches are pattern-based candidates and must be confirmed before rotation.",
        ],
    }


# ------------------------------------------------------------------ rendering
CSS = """
*{box-sizing:border-box} body{font:13px/1.55 -apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#0f172a;
 margin:0;background:#fff} .page{max-width:1000px;margin:0 auto;padding:36px 40px}
h1{font-size:26px;margin:0 0 4px} h2{font-size:19px;margin:34px 0 10px;padding-bottom:6px;border-bottom:2px solid #e2e8f0}
h3{font-size:15px;margin:22px 0 6px} .muted{color:#64748b} .small{font-size:11.5px}
.brand{color:#2563eb;font-weight:700;letter-spacing:.08em;font-size:12px}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:14px 0} .kpi{border:1px solid #e2e8f0;border-radius:8px;padding:10px 12px}
.kpi b{display:block;font-size:22px} .kpi span{color:#64748b;font-size:11.5px}
table{width:100%;border-collapse:collapse;margin:8px 0 14px;font-size:12px} th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #e2e8f0;vertical-align:top}
th{background:#f8fafc;font-weight:600;color:#334155}
.sev{display:inline-block;padding:1px 7px;border-radius:4px;color:#fff;font-weight:700;font-size:10.5px}
.CRITICAL{background:#dc2626}.HIGH{background:#ea580c}.MEDIUM{background:#d97706}.LOW{background:#65a30d}.INFO,.UNKNOWN{background:#94a3b8}
.chip{display:inline-block;padding:1px 7px;border-radius:999px;background:#f1f5f9;border:1px solid #e2e8f0;font-size:10.5px;color:#334155;margin:1px 2px 1px 0}
.seg{border:1px solid #e2e8f0;border-radius:10px;padding:14px 16px;margin:14px 0;page-break-inside:auto}
.seg .what{background:#f8fafc;border-left:4px solid #2563eb;padding:8px 12px;border-radius:4px;margin:6px 0 12px}
.card{border:1px solid #e2e8f0;border-radius:8px;padding:10px 12px;margin:10px 0;page-break-inside:avoid}
.card h4{margin:0 0 4px;font-size:13.5px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.lbl{font-weight:600;color:#334155;font-size:11.5px;text-transform:uppercase;letter-spacing:.04em;margin-top:6px}
.ai{background:#f5f3ff;border-left:3px solid #7c3aed;padding:6px 10px;border-radius:4px;margin:4px 0}
.fix{background:#f0fdf4;border-left:3px solid #16a34a;padding:6px 10px;border-radius:4px;margin:4px 0}
.warn{color:#b91c1c} code{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;background:#f1f5f9;padding:0 4px;border-radius:3px}
.toc a{color:#2563eb;text-decoration:none} .toc li{margin:2px 0}
@media print{.page{padding:0 6px} h2{page-break-after:avoid} .seg{border:none;padding:0}}
"""


def _e(x) -> str:
    return html.escape("" if x is None else str(x))


def _sev(s: str) -> str:
    return f'<span class="sev {_e(s)}">{_e(s)}</span>'


def _finding_card(d: dict) -> str:
    rem = d.get("remediation")
    rem_html = ""
    if rem:
        rem_html = (f'<div class="lbl">Agent remediation ({_e(rem["status"])} — requires human approval)</div>'
                    f'<div class="fix"><b>{_e(rem["action"])}</b>'
                    + (f' → <code>{_e(rem["target_version"])}</code>' if rem.get("target_version") else "")
                    + (f' — {_e(rem["rationale"])}' if rem.get("rationale") else "")
                    + (f'<div class="warn small">Compatibility blocker: {_e(rem["blocker"])}</div>' if rem.get("blocker") else "")
                    + ('<div class="small muted">Source: scanner-reported fix (no agent plan)</div>' if rem.get("source") == "scanner_fix" else "")
                    + "</div>")
    ai = ""
    if d.get("ai_assessment"):
        kind = "AI analysis (LLM, verified by the critic agent)" if d["ai_assessment_kind"].startswith("llm") else "Agent analysis (deterministic template)"
        ai = f'<div class="lbl">{kind}</div><div class="ai">{_e(d["ai_assessment"])}</div>'
    views = ""
    if d.get("scanner_views"):
        views = '<div class="small">' + " · ".join(
            f'<span class="chip">{_e(t)}: {_e(v["severity"])}, fixed in {_e(", ".join(v["fixed_versions"]) or "Evidence unavailable")}</span>'
            for t, v in d["scanner_views"].items()) + (' <span class="warn">scanners disagree on severity</span>' if d.get("severity_disagreement") else "") + "</div>"
    facts = [f'<span class="chip">{_e(d["verification_status"].replace("_", " "))}</span>',
             f'<span class="chip">source: {_e(", ".join(d["source_tool"]))}</span>']
    if d.get("risk_score") is not None:
        facts.append(f'<span class="chip">agent risk score {_e(d["risk_score"])}/100</span>')
    if d.get("ssvc"):
        facts.append(f'<span class="chip">SSVC: {_e(d["ssvc"])}</span>')
    if d.get("reachability"):
        facts.append(f'<span class="chip">reachability: {_e(d["reachability"])}</span>')
    if d.get("epss") is not None:
        facts.append(f'<span class="chip">EPSS {_e(round(d["epss"], 4))}</span>')
    if d.get("kev"):
        facts.append('<span class="chip warn">CISA KEV: actively exploited</span>')
    comp = f'{d["component"]}{"@" + d["installed_version"] if d.get("installed_version") else ""}'
    return (f'<div class="card"><h4>{_sev(d["severity"])} <span>{_e(d["finding_id"])}</span> <code>{_e(d["identifier"])}</code>'
            f' <span>{_e(comp)}</span></h4>'
            f'<div class="small muted">{_e(d["dependency_type"])}'
            + (f' · path: {_e(" → ".join(d["dependency_path"]))}' if len(d.get("dependency_path", [])) > 1 else "")
            + (f' · {_e(d["location"])}' if d.get("location") else "")
            + (f' · fixed version: <b>{_e(d["fixed_version"])}</b>' if d.get("fixed_version") else
               (" · fixed version: Evidence unavailable" if d["finding_type"] == "vulnerability" else "")) + "</div>"
            f'<div class="lbl">Problem</div><div>{_e(d["problem"])}</div>{views}'
            f'<div style="margin-top:6px">{"".join(facts)}</div>{ai}{rem_html}</div>')


def render_html(r: dict) -> str:
    t, ex, fs = r["target"], r["executive_summary"], r["findings"]
    by_seg = defaultdict(list)
    for d in fs:
        by_seg[d["segment"]].append(d)
    fid = {d["finding_id"]: d for d in fs}
    out = [f"<!doctype html><html><head><meta charset='utf-8'>"
           "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
           f"<title>Guardian Report — {_e(t['name'])}</title>"
           f"<style>{CSS}</style></head><body><div class='page'>",
           "<div class='brand'>SOFTWARE SUPPLY CHAIN GUARDIAN</div>",
           f"<h1>Final Guardian Report — {_e(t['name'])}</h1>",
           f"<div class='muted'>{_e(t['repository'])} · commit <code>{_e((t.get('commit') or 'n/a')[:12])}</code> · "
           f"scanned {_e((t.get('scanned_at') or '').replace('T', ' '))} UTC · scan status <b>{_e(t['scan_status'])}</b></div>"]

    toc = [("summary", "Executive summary"), ("method", "Scope & methodology"), ("sbom", "SBOM statistics"),
           ("deps", "Dependency analysis"), ("priority", "Risk prioritisation")]
    toc += [(f"seg-{k}", f"{title} ({len(by_seg[k])})") for k, title, _ in SEGMENTS if by_seg.get(k)]
    toc += [("agree", "Scanner agreement & disagreements"), ("remed", "Remediation plan"),
            ("valid", "Evidence validation"), ("limits", "Limitations")]
    out.append("<h2>Contents</h2><ol class='toc'>" + "".join(f"<li><a href='#{a}'>{_e(b)}</a></li>" for a, b in toc) + "</ol>")

    # executive summary
    out.append("<h2 id='summary'>1. Executive summary</h2><div class='grid'>"
               + "".join(f"<div class='kpi'><b>{_e(v)}</b><span>{_e(k)}</span></div>" for k, v in [
                   ("Total findings", ex["total_findings"]), ("Packages analysed", ex["packages"]),
                   ("Packages with known vulnerabilities", ex["vulnerable_packages"]),
                   ("Packages with supply-chain anomalies", ex["anomalous_packages"])]) + "</div>")
    out.append("<p>" + " ".join(f"{_sev(s)} {n}" for s, n in ex["by_severity"].items()) + "</p>")
    out.append("<table><tr><th>Risk category</th><th>Findings</th></tr>" + "".join(
        f"<tr><td>{_e(k)}</td><td>{v}</td></tr>" for k, v in ex["by_category"].items()) + "</table>")
    out.append("<h3>Highest-priority risks</h3><table><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Component</th><th>Risk score</th><th>Agent remediation</th></tr>"
               + "".join(f"<tr><td>{_e(i)}</td><td>{_sev(fid[i]['severity'])}</td><td>{_e(fid[i]['identifier'])}<div class='small muted'>{_e(fid[i]['category'])}</div></td>"
                         f"<td>{_e(fid[i]['component'])}{'@' + _e(fid[i]['installed_version']) if fid[i].get('installed_version') else ''}</td>"
                         f"<td>{_e(fid[i]['risk_score'])}</td><td>{_e((fid[i]['remediation'] or {}).get('action', '—'))}"
                         f"{' → ' + _e(fid[i]['remediation']['target_version']) if (fid[i]['remediation'] or {}).get('target_version') else ''}</td></tr>"
                         for i in ex["top_risks"]) + "</table>")
    ai = ex["ai"]
    out.append(f"<p class='small muted'>AI usage: {_e(ai['llm_explanations'])} explanations written by an LLM "
               f"({_e(', '.join(ai['provider']) if ai['provider'] else 'none configured')}) and verified by the critic agent "
               f"({_e(ai['critic_accepted'])} accepted, {_e(ai['critic_rejected'])} rejected); {_e(ai['template_explanations'])} deterministic templates. "
               "Scanner facts, agent analysis and AI text are labelled separately throughout.</p>")

    # methodology
    m = r["methodology"]
    out.append("<h2 id='method'>2. Scope & methodology</h2><p>The repository is treated as untrusted input: it is cloned "
               "read-only with git hooks disabled, nothing from it is executed (lockfiles are resolved with "
               "<code>--ignore-scripts</code>, cdxgen runs with <code>--no-install-deps</code>), and tools run with a "
               "minimal environment. Three scanners run in parallel; a LangGraph supervisor then coordinates specialist "
               "agents over the evidence, and an evidence validator gates every finding in this report.</p>")
    out.append("<table><tr><th>Step</th><th>Status</th><th>Result</th></tr>" + "".join(
        f"<tr><td>{_e(s['label'])}</td><td>{_e(s['status'])}</td><td>{_e(s['detail'])}</td></tr>" for s in m["pipeline_steps"].values()) + "</table>")
    ansi = re.compile(r"\x1b\[[0-9;]*m|\[[0-9;]*m")
    tools = {k: ansi.sub("", json.dumps(v) if isinstance(v, dict) else str(v)) for k, v in m["tools"].items()}
    out.append("<table><tr><th>Tool / database</th><th>Version</th></tr>" + "".join(
        f"<tr><td>{_e(k)}</td><td><code>{_e(v)}</code></td></tr>" for k, v in tools.items()) + "</table>")
    if m["agents"]:
        out.append(f"<p>Agents ({len(m['agents'])}, {m['agent_turns']} supervisor turns): "
                   + " ".join(f"<span class='chip'>{_e(a)}</span>" for a in m["agents"]) + "</p>")

    # sbom
    s = r["sbom"]
    out.append("<h2 id='sbom'>3. SBOM statistics</h2><div class='grid'>" + "".join(
        f"<div class='kpi'><b>{_e(v)}</b><span>{_e(k)}</span></div>" for k, v in [
            ("Components", s["components"]), ("Direct dependencies", s["direct"]),
            ("Transitive dependencies", s["transitive"]), ("Dependency edges", s["edges"])]) + "</div>"
               f"<p class='small muted'>Ecosystems: {_e(', '.join(f'{k} ({v})' for k, v in s['ecosystems'].items()))}. "
               f"{_e(s['not_linked'])} SBOM components are not linked to the dependency tree (e.g. GitHub Actions).</p>")

    # dependency analysis
    da = r["dependency_analysis"]
    out.append("<h2 id='deps'>4. Dependency analysis</h2><h3>Dependency depth</h3><table><tr><th>Depth from application</th><th>Packages</th></tr>"
               + "".join(f"<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>" for k, v in da["depth_distribution"].items()) + "</table>"
               + "<h3>Direct dependencies that pull in vulnerable code</h3><table><tr><th>Direct dependency</th><th>Vulnerability findings below it</th></tr>"
               + "".join(f"<tr><td>{_e(k)}</td><td>{_e(v)}</td></tr>" for k, v in da["vulnerable_via_direct_dependency"].items()) + "</table>"
               + "<h3>Vulnerable packages shared across dependency paths</h3><table><tr><th>Package</th><th>Parents</th><th>Vulnerabilities</th></tr>"
               + "".join(f"<tr><td>{_e(x['package'])}</td><td>{x['parents']}</td><td>{x['vulnerabilities']}</td></tr>" for x in da["shared_vulnerable_packages"]) + "</table>")

    # prioritisation
    top = sorted(fs, key=lambda d: -(d.get("risk_score") or 0))[:15]
    out.append("<h2 id='priority'>5. Risk prioritisation</h2><p class='small muted'>Ordered by the scoring agent's explainable "
               "risk score (base severity, exploit signals such as KEV/EPSS, import-based reachability, scope and exposure) "
               "with a simplified SSVC decision. This is agent analysis, not scanner output.</p><table><tr><th>ID</th><th>Score</th><th>SSVC</th>"
               "<th>Finding</th><th>Component</th><th>Reachability</th><th>Confidence</th></tr>" + "".join(
        f"<tr><td>{_e(d['finding_id'])}</td><td>{_e(d['risk_score'])}</td><td>{_e(d['ssvc'])}</td><td>{_e(d['identifier'])}</td>"
        f"<td>{_e(d['component'])}</td><td>{_e(d['reachability'])}</td><td>{_e(d['confidence'])}</td></tr>" for d in top) + "</table>")

    # segments
    n = 6
    for key, title, what in SEGMENTS:
        items = by_seg.get(key)
        if not items:
            continue
        out.append(f"<h2 id='seg-{key}'>{n}. {_e(title)} ({len(items)})</h2><div class='seg'>"
                   f"<div class='what'><b>The problem:</b> {_e(what)}</div>")
        sc = Counter(d["severity"] for d in items)
        out.append("<p>" + " ".join(f"{_sev(s_)} {c}" for s_, c in sorted(sc.items(), key=lambda x: SEV.index(x[0]))) + "</p>")
        detailed = items if len(items) <= 25 else items[:15]
        out.extend(_finding_card(d) for d in detailed)
        if len(items) > len(detailed):
            out.append(f"<h3>All {len(items)} findings</h3><table><tr><th>ID</th><th>Severity</th><th>Check</th><th>Problem</th><th>Location</th><th>Fix</th></tr>"
                       + "".join(f"<tr><td>{_e(d['finding_id'])}</td><td>{_sev(d['severity'])}</td><td><code>{_e(d['identifier'])}</code></td>"
                                 f"<td>{_e(d['problem'][:160])}</td><td>{_e(d['location'] or d['component'])}</td>"
                                 f"<td>{_e(((d.get('remediation') or {}).get('rationale') or '')[:140])}</td></tr>" for d in items) + "</table>")
        out.append("</div>")
        n += 1

    # agreement
    ag = r["scanner_agreement"]
    out.append(f"<h2 id='agree'>{n}. Scanner agreement & disagreements</h2><p class='small muted'>Disagreements are reported, "
               "not resolved: each scanner's view is kept. A finding reported by fewer scanners is not less real, and a "
               "package with no finding is not proven safe.</p><table><tr><th>Reported by</th><th>Vulnerability findings</th></tr>"
               + "".join(f"<tr><td>{_e(k)}</td><td>{v}</td></tr>" for k, v in ag["by_scanner_combination"].items()) + "</table>")
    if ag["disagreements"]:
        out.append("<table><tr><th>Component</th><th>Identifier</th><th>Disagreement</th><th>Scanner views</th></tr>" + "".join(
            f"<tr><td>{_e(x['component'])}</td><td>{_e(x['identifier'])}</td><td>{_e(x['kind'])}</td>"
            f"<td>{_e(', '.join(f'{k}: {v}' for k, v in x['views'].items()))}</td></tr>" for x in ag["disagreements"]) + "</table>")
    n += 1

    # remediation
    rem_rows = [d for d in fs if d.get("remediation")]
    out.append(f"<h2 id='remed'>{n}. Remediation plan</h2><p class='small muted'>Proposed by the remediation agent "
               "(verified-clean target versions, co-upgrades and compatibility blockers) or taken from scanner fix data. "
               "Nothing is applied automatically; every plan requires human approval and can be validated in the sandbox "
               "(CLI).</p><p>" + " ".join(f"<span class='chip'>{_e(k)}: {v}</span>" for k, v in r["remediation_summary"].items()) + "</p>")
    seen, rows = set(), []
    for d in sorted(rem_rows, key=lambda d: -(d.get("risk_score") or 0)):
        rk = (d["component"], d["remediation"]["action"], d["remediation"].get("target_version"))
        if rk in seen:
            continue
        seen.add(rk)
        rm = d["remediation"]
        rows.append(f"<tr><td>{_e(d['component'])}{'@' + _e(d['installed_version']) if d.get('installed_version') else ''}</td>"
                    f"<td>{_e(rm['action'])}</td><td>{_e(rm.get('target_version') or '—')}</td>"
                    f"<td>{_e((rm.get('rationale') or '')[:180])}{'<div class=warn>' + _e(rm['blocker']) + '</div>' if rm.get('blocker') else ''}</td>"
                    f"<td>{_e(rm['status'])}</td></tr>")
    out.append("<table><tr><th>Component</th><th>Action</th><th>Target</th><th>Rationale</th><th>Status</th></tr>" + "".join(rows[:60]) + "</table>")
    n += 1

    v = r["validation"]
    out.append(f"<h2 id='valid'>{n}. Evidence validation</h2><p>{v['accepted']} findings passed validation; "
               f"{len(v['rejected'])} were rejected.</p><ul>" + "".join(f"<li>{_e(x)}</li>" for x in v["rules"]) + "</ul>")
    if v["rejected"]:
        out.append("<table><tr><th>Identifier</th><th>Component</th><th>Reasons</th></tr>" + "".join(
            f"<tr><td>{_e(x['identifier'])}</td><td>{_e(x['component'])}</td><td>{_e('; '.join(x['reasons']))}</td></tr>" for x in v["rejected"]) + "</table>")
    n += 1
    out.append(f"<h2 id='limits'>{n}. Limitations</h2><ul>" + "".join(f"<li>{_e(x)}</li>" for x in r["limitations"]) + "</ul>")
    out.append(f"<p class='small muted'>Generated {_e(r['generated_at'])} by Software Supply Chain Guardian.</p></div></body></html>")
    return "\n".join(out)


def _browser() -> str | None:
    cands = [os.environ.get("GUARDIAN_PDF_BROWSER"),
             "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
             "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
             "/Applications/Chromium.app/Contents/MacOS/Chromium",
             "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
             shutil.which("google-chrome"), shutil.which("chromium"), shutil.which("chromium-browser")]
    return next((c for c in cands if c and Path(c).exists()), None)


def render_pdf(html_path: Path, pdf_path: Path) -> str:
    """Print the HTML report with a headless Chromium browser (throwaway profile). The report's CSP
    blocks scripts and network access; (--blink-settings=scriptEnabled=false silently breaks printing)."""
    browser = _browser()
    pdf_path = pdf_path.resolve()          # Chrome resolves relative paths from its own working dir
    if not browser:
        return "skipped: no Chromium-based browser found (set GUARDIAN_PDF_BROWSER)"
    with tempfile.TemporaryDirectory(prefix="guardian-pdf-") as profile:
        try:
            p = subprocess.run([browser, "--headless=new", "--disable-gpu", "--no-first-run",
                                "--no-default-browser-check", f"--user-data-dir={profile}",
                                "--no-pdf-header-footer",
                                f"--print-to-pdf={pdf_path}", html_path.resolve().as_uri()],
                               capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return "failed: browser timed out"
    return "ok" if pdf_path.exists() and pdf_path.stat().st_size > 0 else f"failed: exit {p.returncode}"


def write_reports(scan_dir: Path) -> dict:
    """Build + validate the report and write report/guardian-report.{json,html,pdf}."""
    scan_dir = Path(scan_dir)
    out = scan_dir / "report"
    out.mkdir(exist_ok=True)
    report = build_report(scan_dir)
    (out / "guardian-report.json").write_text(json.dumps(report, indent=2, default=str))
    (out / "guardian-report.html").write_text(render_html(report))
    pdf_status = render_pdf(out / "guardian-report.html", out / "guardian-report.pdf")
    return {"dir": str(out), "findings": len(report["findings"]), "rejected": len(report["validation"]["rejected"]),
            "pdf": pdf_status, "by_category": report["executive_summary"]["by_category"]}


if __name__ == "__main__":
    import sys
    print(json.dumps(write_reports(Path(sys.argv[1])), indent=2))
