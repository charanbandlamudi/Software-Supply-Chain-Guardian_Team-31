"""Maintainer, ownership, cadence and publish-hour anomaly analysis."""
from __future__ import annotations

from datetime import datetime


def analyze_release_history(entries: list[dict]) -> dict:
    findings = []
    maintainers = {m for entry in entries for m in entry.get("maintainers", [])}
    ownership_changes = []
    previous = None
    publish_hours = []
    for entry in entries:
        current = set(entry.get("maintainers", []))
        if previous is not None and current != previous:
            ownership_changes.append({"from": sorted(previous), "to": sorted(current),
                                      "version": entry.get("version")})
        previous = current
        if entry.get("published"):
            try:
                published = datetime.fromisoformat(entry["published"].replace("Z", "+00:00"))
                publish_hours.append(published.hour)
            except (TypeError, ValueError):
                pass
    if ownership_changes:
        findings.append({"type": "maintainer_change", "count": len(ownership_changes),
                         "changes": ownership_changes[-10:]})
    if len(entries) >= 3:
        times = []
        for entry in entries:
            try:
                times.append(datetime.fromisoformat(entry["published"].replace("Z", "+00:00")))
            except (AttributeError, TypeError, ValueError):
                pass
        times.sort()
        if len(times) >= 3:
            gaps = [(b - a).total_seconds() / 86400 for a, b in zip(times, times[1:])]
            if gaps and min(gaps) < 1:
                findings.append({"type": "release_cadence_burst", "minimum_gap_days": round(min(gaps), 3)})
    unusual_hours = sorted({hour for hour in publish_hours if hour < 6 or hour >= 22})
    if unusual_hours:
        findings.append({"type": "publish_hour_anomaly", "hours": unusual_hours})
    return {"maintainer_count": len(maintainers), "findings": findings}
