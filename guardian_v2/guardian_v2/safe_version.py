"""Answers Q4 (is there a safe version?) and Q5 (will it break?) deterministically."""
from __future__ import annotations

from univers import version_range as vr

from . import versions as V

_RANGE = {"pypi": vr.PypiVersionRange, "npm": vr.NpmVersionRange, "maven": vr.MavenVersionRange}


def _clears(eco: str, candidate: str, advisory: dict) -> bool:
    """A candidate is safe for an advisory only if EVERY source agrees."""
    for src, ranges in advisory.get("ranges_by_source", {}).items():
        if V.is_affected(eco, candidate, ranges):
            return False
    for src in advisory.get("sources", []):
        if src in advisory.get("ranges_by_source", {}):
            continue
        fix = advisory.get("fix_by_source", {}).get(src)
        if fix is None or V.parse(eco, candidate) < V.parse(eco, fix):
            return False  # range-less source with no/higher fix: cannot prove safe
    return True


def _constraint_ok(eco: str, constraint: str, candidate: str) -> bool | None:
    cls = _RANGE.get(eco)
    if not cls or not constraint:
        return None
    try:
        return V.parse(eco, candidate) in cls.from_native(constraint)
    except Exception:
        return None


def plan_for_component(purl: str, advisories: list[dict], available: list[dict],
                       edges: list[dict]) -> dict:
    """available: [{"version": "3.1.3", "yanked": False}, ...] from registry metadata."""
    eco, current = V.ecosystem_of(purl), V.version_of(purl)
    cur = V.parse(eco, current)
    candidates = sorted(
        (a["version"] for a in available
         if not a.get("yanked") and not V.is_prerelease(eco, a["version"])
         and V.parse(eco, a["version"]) > cur),
        key=lambda v: V.parse(eco, v))
    safe = [c for c in candidates if all(_clears(eco, c, adv) for adv in advisories)]
    target = safe[0] if safe else None

    blockers = []
    if target:
        for e in edges:
            if V.base_purl(e["to"]) == V.base_purl(purl) and e.get("constraint"):
                ok = _constraint_ok(eco, e["constraint"], target)
                if ok is False:
                    blockers.append({"parent": e["from"], "constraint": e["constraint"]})

    major_bump = bool(target) and str(V.parse(eco, target)).split(".")[0] != str(cur).split(".")[0]
    plan = {
        "component": purl,
        "action": "upgrade" if target else "request_review",
        "target_version": target,
        "latest_safe": safe[-1] if safe else None,
        "clears": [a["canonical_id"] for a in advisories] if target else [],
        "compatibility": {
            "major_version_bump": major_bump,
            "parent_constraint_blockers": blockers,
            "co_upgrade_required": [b["parent"] for b in blockers],
            "verdict": ("needs_co_upgrade" if blockers else "major_bump_needs_tests"
                        if major_bump else "patch_or_minor"),
        },
        "rollback": "revert manifest and lockfile to the pre-change commit; lockfile hash recorded as evidence",
        "requires_human_approval": True,
        "merge": False,
    }
    if not target:
        plan["reason"] = "no published non-yanked version clears every advisory per every source"
    return plan
