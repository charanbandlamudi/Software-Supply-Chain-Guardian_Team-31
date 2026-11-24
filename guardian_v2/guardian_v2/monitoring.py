"""Dependency-Track and feed-freshness integration hooks."""
from __future__ import annotations

import json
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def upload_dependency_track(endpoint: str, api_key: str, bom_path: Path, project_name: str) -> dict:
    if not endpoint or not api_key:
        return {"status": "unavailable", "reason": "Dependency-Track endpoint/API key not configured"}
    url = endpoint.rstrip("/") + "/api/v1/bom"
    bom = Path(bom_path).read_bytes()
    payload = json.dumps({"projectName": project_name, "bom": bom.decode("utf-8")}).encode()
    req = urllib.request.Request(url, data=payload, method="PUT",
                                 headers={"X-Api-Key": api_key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return {"status": "ok", "http_status": response.status}
    except Exception as exc:
        return {"status": "failed", "reason": f"{type(exc).__name__}: {exc}"}


def freshness(feed_timestamps: dict, max_age_minutes: int = 240) -> dict:
    now = datetime.now(timezone.utc)
    stale = {}
    for name, timestamp in feed_timestamps.items():
        try:
            age = (now - datetime.fromisoformat(timestamp.replace("Z", "+00:00"))).total_seconds() / 60
            stale[name] = {"age_minutes": round(age, 1), "stale": age > max_age_minutes}
        except (TypeError, ValueError):
            stale[name] = {"age_minutes": None, "stale": True}
    return {"stale": stale, "any_stale": any(v["stale"] for v in stale.values())}
