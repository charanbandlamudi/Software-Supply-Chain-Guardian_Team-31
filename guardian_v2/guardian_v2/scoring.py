"""Explainable, deterministic risk score + confidence + simplified SSVC label.
Weights are hackathon heuristics: calibrate them on labelled findings.

Three risk classes are scored differently, because "is it imported?" only
matters for one of them:
  runtime    vulnerable code that must be called to be exploited (CVEs)
  install    code that runs during `npm install` / `pip install` (malicious
             packages, install scripts, tampered lockfiles): import-based
             reachability does not reduce this risk
  pipeline   CI/CD and container configuration: no package reachability
"""
from __future__ import annotations

REACH = {"reachable": 1.0, "imported": 0.9, "used_transitively": 0.8, "imported_not_reached": 0.6,
         "unknown": 0.7, "not_imported": 0.3, "not_in_runtime": 0.2}
SCOPE = {"prod": 1.0, "runtime": 1.0, "build": 0.6, "dev": 0.4, "test": 0.4, "environment": 0.3}
EXPOSURE = {"internet": 1.0, "internal": 0.7, "offline": 0.4}

INSTALL_TIME = {"malicious_package", "typosquat_suspect", "install_script", "integrity_mismatch",
                "untrusted_resolved_url", "unpublished_version", "dependency_confusion",
                "lockfile_tampering", "suspicious_update"}
PIPELINE = {"unpinned_action", "dangerous_workflow", "excessive_permissions", "unpinned_base_image"}
# Exploitation status implied by the finding itself (SSVC "Exploitation").
IMPLIED_EXPLOITATION = {"malicious_package": "active", "integrity_mismatch": "poc",
                        "lockfile_tampering": "poc", "dependency_confusion": "poc",
                        "dangerous_workflow": "poc"}
# Non-CVE findings: (automatable, technical impact) for SSVC.
IMPLIED_IMPACT = {"malicious_package": (True, "total"), "integrity_mismatch": (True, "total"),
                  "lockfile_tampering": (True, "total"), "untrusted_resolved_url": (True, "total"),
                  "dependency_confusion": (True, "total"), "dangerous_workflow": (True, "total"),
                  "typosquat_suspect": (True, "total"), "install_script": (True, "partial"),
                  "unpinned_action": (False, "total"), "suspicious_update": (True, "partial")}


def risk_class(ftype: str) -> str:
    if ftype in INSTALL_TIME:
        return "install"
    if ftype in PIPELINE:
        return "pipeline"
    return "runtime"


def _vector_has(vector: str | None, *parts: str) -> bool:
    return bool(vector) and all(p in vector for p in parts)


def ssvc(exploitation: str, automatable: bool, total: bool, mission: str) -> dict:
    """Simplified mapping of CISA SSVC (Exploitation, Automatable, Technical
    Impact, Mission & Well-being) -> Track / Track* / Attend / Act."""
    high = mission == "high"
    if exploitation == "active":
        decision = "Act" if (high or (automatable and total)) else "Attend"
    elif exploitation == "poc":
        decision = "Attend" if (automatable and total) else "Track*"
    else:
        decision = "Track*" if (automatable and total and high) else "Track"
    return {"decision": decision, "exploitation": exploitation, "automatable": automatable,
            "technical_impact": "total" if total else "partial", "mission": mission,
            "note": "simplified SSVC mapping"}


def score(finding: dict, component: dict, ctx: dict) -> dict:
    ftype = finding.get("type", "vulnerability")
    klass = risk_class(ftype)
    cvss = (finding.get("cvss") or {}).get("score")
    if cvss is not None:
        base_src, base10 = "cvss", float(cvss)
    elif finding.get("calibrated_base") is not None:
        base_src, base10 = "calibrated detector base", float(finding["calibrated_base"])
    else:
        base_src, base10 = "default 5.0: no CVSS from reachable sources", 5.0
    base = base10 / 10 * 40

    kev = bool(finding.get("kev"))
    pct = float((finding.get("epss") or {}).get("percentile") or 0.0)
    implied = IMPLIED_EXPLOITATION.get(ftype)
    exploitation = "active" if (kev or implied == "active") else "poc" if (
        finding.get("public_poc") or implied == "poc") else "none"
    exploit = max(30.0 if exploitation == "active" else 0.0, pct * 20,
                  15.0 if exploitation == "poc" else 0.0)

    reach_state = (component.get("reachability") or {}).get("state", "unknown")
    scope = component.get("scope", "prod")
    if klass == "install":
        r, reach_label = 1.0, f"executes at install time (import status: {reach_state})"
        s = 1.0 if scope != "environment" else SCOPE["environment"]   # dev deps install too
    elif klass == "pipeline":
        r, reach_label, s = 1.0, "n/a: CI/container configuration", 1.0
    else:
        r, reach_label, s = REACH.get(reach_state, 0.7), reach_state, SCOPE.get(scope, 1.0)
    exposure = ctx.get("exposure", "internet") if klass == "runtime" else "internet"
    x = EXPOSURE.get(exposure, 1.0)
    depth = 1.0 if (component.get("direct") or klass != "runtime") else 0.9

    # Correlation: independent detector signals on the same component reinforce each other.
    corroboration = int(finding.get("corroborating_signals", 0))
    corr_bonus = min(15.0, 5.0 * corroboration)
    fix_bonus = 5.0 if finding.get("recommended_fix") else 0.0
    total_score = round(min(100.0, (base + exploit) * r * s * x * depth + fix_bonus + corr_bonus), 1)

    pts = 2 if len(finding.get("sources", [])) >= 2 or corroboration else 1
    pts -= 1 if finding.get("source_conflicts") else 0
    pts += 1 if (klass != "runtime" or reach_state in ("reachable", "imported", "not_imported",
                                                      "not_in_runtime")) else 0
    pts += 1 if finding.get("match_quality", "purl") == "purl" else -1
    pts -= 1 if base_src.startswith("default") else 0
    confidence = "High" if pts >= 4 else "Medium" if pts >= 2 else "Low"

    vector = (finding.get("cvss") or {}).get("vector")
    if ftype in IMPLIED_IMPACT:
        automatable, impact = IMPLIED_IMPACT[ftype]
        total = impact == "total"
    else:
        automatable, total = _vector_has(vector, "AV:N", "PR:N", "UI:N"), _vector_has(vector, "C:H", "I:H")
    return {
        "score": total_score, "confidence": confidence, "risk_class": klass,
        "score_breakdown": {"base": round(base, 1), "base_source": base_src, "exploit": round(exploit, 1),
                            "exploitation": exploitation, "reachability": [reach_label, r],
                            "scope": [scope, s], "exposure": [exposure, x], "depth": depth,
                            "corroboration": [corroboration, corr_bonus], "fix_bonus": fix_bonus},
        "ssvc": ssvc(exploitation, automatable, total, ctx.get("mission", "medium")),
    }
