from __future__ import annotations


def select_version(finding: dict) -> dict:
    fixed = finding.get("fixed_versions") or []
    suggested = finding.get("suggested_versions") or []

    for version in suggested:
        if version in fixed:
            return {
                "recommended_version": version,
                "candidates": fixed,
                "status": "candidate",
            }
    if len(fixed) == 1:
        return {
            "recommended_version": fixed[0],
            "candidates": fixed,
            "status": "candidate",
        }
    if len(fixed) > 1:
        return {
            "recommended_version": None,
            "candidates": fixed,
            "status": "needs_review",
        }
    return {
        "recommended_version": None,
        "candidates": [],
        "status": "no_fix_available",
    }

