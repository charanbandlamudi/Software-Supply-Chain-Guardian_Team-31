"""Remediation agent: answers "is there a safe version?" and "will it break?".

Strategy per attempt:
  1 minimal      smallest version that a live registry re-scan shows as clean
  2 latest_safe  newest clean version (used after a sandbox build/test failure)
  3+             give up on auto-upgrade, escalate to security review
A small resolver pass checks every dependency edge against the *planned*
versions' declared requirements and co-upgrades parents or children.
"""
from __future__ import annotations

import re

from packaging.requirements import InvalidRequirement, Requirement
from univers import version_range as vr

from .. import versions as V
from ..tools import npm, pypi
from .base import AgentResult

MAX_ATTEMPTS = 3
MAX_LOOKUPS = 20
ANOMALY_ACTIONS = {
    "malicious_package": ("remove", "Remove the package; it was taken down as malicious."),
    "typosquat_suspect": ("remove", "Remove or replace with the intended package after review."),
    "unpublished_version": ("remove", "Version no longer exists on the registry; remove or replace."),
    "integrity_mismatch": ("regenerate_lock_entry", "Regenerate the lock entry from the official registry."),
    "lockfile_tampering": ("regenerate_lock_entry", "Restore the lock entry from the official registry and find who changed it."),
    "dependency_confusion": ("pin", "Scope internal names to the private registry (.npmrc / index-url) and reserve them publicly."),
    "suspicious_update": ("pin", "Pin to the previous release until the new one passes the cooling-off window."),
    "unexpected_dependency": ("request_review", "Find out why this package entered the lockfile before keeping it."),
    "untrusted_resolved_url": ("regenerate_lock_entry", "Re-resolve from the official registry."),
    "unpinned_action": ("pin", "Pin the action to a full 40-character commit SHA."),
    "unpinned_base_image": ("pin", "Pin the base image by @sha256 digest (and move off EOL tags)."),
    "dangerous_workflow": ("request_review", "Use pull_request, or never check out PR head with secrets."),
    "excessive_permissions": ("pin", "Set least-privilege `permissions:` (e.g. contents: read)."),
}


def _norm(n):
    return re.sub(r"[-_.]+", "-", n).lower()


def _clean(c: dict, version: str, evidence: dict) -> tuple[bool, list[str]]:
    """Live re-scan of a candidate version (the deterministic 'is it safe' oracle)."""
    if c["ecosystem"] == "pypi":
        raw, ev = pypi.advisories_for(c["name"], version, f"pkg:pypi/{c['name']}@{version}")
    else:
        data, eid, e = npm.bulk_advisories({c["name"]: [version]})
        raw, ev = npm.to_raw(c["name"], version, "", (data or {}).get(c["name"], []), eid), {eid: e}
        raw = [r for r in raw if V.is_affected("npm", version, [{"native": r["npm_range"]}])]
    evidence.update({k: {**v, "payload": v["payload"][:1500]} for k, v in ev.items()})
    return not raw, sorted({r["id"] for r in raw})


def _candidates(c: dict, floor: str | None) -> list[str]:
    eco, cur = c["ecosystem"], V.parse(c["ecosystem"], c["version"])
    out = []
    for r in c.get("registry_versions", []):
        try:
            v = V.parse(eco, r["version"])
        except Exception:
            continue
        if r.get("yanked") or V.is_prerelease(eco, r["version"]) or v <= cur:
            continue
        if floor and v < V.parse(eco, floor):
            continue
        out.append(r["version"])
    return sorted(out, key=lambda x: V.parse(eco, x))


def _find_clean(c, cands, strategy, evidence, must=None):
    order = cands if strategy == "minimal" else list(reversed(cands))
    for i, v in enumerate(order):
        if i >= MAX_LOOKUPS:
            break
        if must and not must(v):
            continue
        ok, _ = _clean(c, v, evidence)
        if ok:
            return v
    return None


def _requires(c: dict, version: str) -> dict[str, str]:
    """Declared runtime requirements of name@version: {dep_name: specifier}."""
    if c["ecosystem"] == "pypi":
        data, _, _ = pypi.version_info(c["name"], version)
        out = {}
        for s in ((data or {}).get("info", {}).get("requires_dist") or []):
            try:
                r = Requirement(s)
            except InvalidRequirement:
                continue
            if r.marker and "extra" in str(r.marker):
                continue
            out[_norm(r.name)] = str(r.specifier)
        return out
    data, _, _ = npm.packument(c["name"])
    return dict(((data or {}).get("versions", {}).get(version, {}) or {}).get("dependencies", {}))


def _satisfies(eco: str, version: str, spec: str | None) -> bool:
    if not spec:
        return True
    cls = {"pypi": vr.PypiVersionRange, "npm": vr.NpmVersionRange}.get(eco)
    try:
        return V.parse(eco, version) in cls.from_native(spec)
    except Exception:
        return True  # unparsable spec: leave it to the sandbox resolver


def run(state: dict, task: dict) -> AgentResult:
    comps, findings = state.get("components", {}), state.get("findings", {})
    prior = state.get("remediation_plans", {})
    strategy_for = {p: task.get("strategy", "minimal") for p in task.get("components", [])}
    evidence, plans, notes = {}, {}, []

    by_comp: dict[str, list[dict]] = {}
    for fid, f in findings.items():
        if f.get("status") in ("open", "failed_validation"):
            by_comp.setdefault(f["component_purl"], []).append({**f, "id": fid})

    # Only re-plan what the handoff asks for; keep other plans as they are.
    targets = list(task.get("components") or by_comp)
    planned: dict[str, str] = {}          # purl -> target version (for the resolver pass)
    for purl in targets:
        fs = by_comp.get(purl, [])
        c = comps.get(purl)
        prev = prior.get(f"PLAN::{purl}", {})
        replan = purl in strategy_for                      # handoff after a failed validation
        attempt = prev.get("attempt", 0) + 1 if (replan or not prev) else prev["attempt"]
        vulns = [f for f in fs if f["type"] == "vulnerability"]
        others = [f for f in fs if f["type"] in ANOMALY_ACTIONS]
        plan = {"component": purl, "attempt": attempt, "requires_human_approval": True, "merge": False,
                "status": "proposed", "finding_ids": [f["id"] for f in fs], "evidence_ids": [],
                "rollback": "revert the manifest/lockfile commit; previous lockfile hash is in the evidence store"}
        removal = next((f for f in others if ANOMALY_ACTIONS[f["type"]][0] == "remove"), None)
        if removal:
            reach = ((c or {}).get("reachability") or {}).get("state")
            impact = (" Source code does not import it, so removal has no functional impact."
                      if reach == "not_imported" else
                      " Source code imports it: replace it with the intended package." if reach == "imported" else "")
            signals = sorted({f["type"] for f in fs if f["type"] != "vulnerability"})
            plan.update(action="remove", target_version=None,
                        rationale=ANOMALY_ACTIONS[removal["type"]][1] + impact + f" Signals: {', '.join(signals)}.")
        elif vulns and c and c.get("ecosystem") in ("pypi", "npm"):
            if attempt > MAX_ATTEMPTS:
                plan.update(action="request_review", status="needs_review",
                            rationale=f"{MAX_ATTEMPTS} sandbox attempts failed; needs a human decision")
            else:
                strategy = strategy_for.get(purl, prev.get("strategy") or "minimal")
                floor = max((f["recommended_fix"] for f in vulns if f.get("recommended_fix")),
                            key=lambda v: V.parse(c["ecosystem"], v), default=None)
                cands = _candidates(c, floor if strategy == "minimal" else None)
                target = _find_clean(c, cands, strategy, evidence)
                if target:
                    planned[purl] = target
                    plan.update(action="upgrade", target_version=target, strategy=strategy,
                                clears=sorted({f["canonical_id"] for f in vulns}),
                                rationale=f"{strategy}: {c['name']} {target} re-scanned clean on the registry "
                                          f"(0 known advisories)",
                                evidence_ids=sorted(evidence)[-3:])
                else:
                    plan.update(action="request_review", status="needs_review",
                                rationale="no clean, non-yanked release found within the lookup budget")
        elif others:
            act, why = ANOMALY_ACTIONS[others[0]["type"]]
            plan.update(action=act, target_version=None, rationale=why,
                        status="proposed" if act != "request_review" else "needs_review")
        else:
            continue
        if others:
            plan["also_resolves"] = sorted({f["type"] for f in others})
        if (not replan and prev and prev.get("action") == plan.get("action")
                and prev.get("target_version") == plan.get("target_version")):
            plan["status"] = prev.get("status", plan["status"])   # an upstream re-run must not reset a decision
        plans[f"PLAN::{purl}"] = plan

    # Keep earlier upgrade targets for components not re-planned this round.
    for pid, p in prior.items():
        if p.get("action") == "upgrade" and p["component"] not in planned and p.get("status") != "rejected":
            planned[p["component"]] = p["target_version"]

    # ---- resolver pass: planned parents vs children, both directions ----
    def version_of(purl):
        return planned.get(purl) or comps[purl]["version"]

    for _ in range(3):
        changed = False
        for e in state.get("edges", []):
            parent, child = comps.get(e["from"]), comps.get(e["to"])
            if not parent or not child or parent["ecosystem"] not in ("pypi", "npm"):
                continue
            if e["from"] not in planned and e["to"] not in planned:
                continue
            spec = _requires(parent, version_of(e["from"])).get(
                _norm(child["name"]) if child["ecosystem"] == "pypi" else child["name"], e.get("constraint"))
            if _satisfies(child["ecosystem"], version_of(e["to"]), spec):
                continue
            if e["to"] in planned or e["from"] in planned:
                # child must move into the parent's declared range
                cands = [v for v in _candidates(child, None) if _satisfies(child["ecosystem"], v, spec)]
                new = _find_clean(child, cands, "minimal", evidence)
                pid = f"PLAN::{e['to']}"
                if new:
                    planned[e["to"]] = new
                    base = plans.get(pid) or prior.get(pid) or {
                        "component": e["to"], "attempt": 1, "requires_human_approval": True, "merge": False,
                        "finding_ids": [], "evidence_ids": [], "rollback": "revert lockfile commit"}
                    plans[pid] = {**base, "action": "upgrade", "target_version": new, "status": "proposed",
                                  "rationale": f"co-upgrade: {parent['name']} {version_of(e['from'])} "
                                               f"requires {child['name']} {spec}"}
                    notes.append(f"{child['name']} -> {new} to satisfy {parent['name']} {spec}")
                    changed = True
                else:
                    pid_p = f"PLAN::{e['from']}"
                    plans.setdefault(pid_p, prior.get(pid_p, {"component": e["from"]}))
                    plans[pid_p]["compatibility_blocker"] = f"{parent['name']} needs {child['name']} {spec}; no clean match"
        if not changed:
            break

    for pid, p in plans.items():
        if p.get("action") == "upgrade":
            c = comps[p["component"]]
            major = str(V.parse(c["ecosystem"], p["target_version"])).split(".")[0] != \
                str(V.parse(c["ecosystem"], c["version"])).split(".")[0]
            p["compatibility"] = {"major_version_bump": major,
                                  "verdict": "needs_sandbox_tests" if major else "patch_or_minor"}
    ups = [f"{comps[p['component']]['name']} {comps[p['component']]['version']}->{p['target_version']}"
           for p in plans.values() if p.get("action") == "upgrade"]
    other = {}
    for p in plans.values():
        if p.get("action") != "upgrade":
            other[p["action"]] = other.get(p["action"], 0) + 1
    return AgentResult(delta={"remediation_plans": plans, "evidence": evidence},
                       summary=f"{len(plans)} plans (strategy={task.get('strategy', 'minimal')}): upgrades "
                               f"[{', '.join(ups)}]; other actions {other}"
                               + (f"; resolver: {'; '.join(notes)}" if notes else ""),
                       metrics={"plans": len(plans)})
