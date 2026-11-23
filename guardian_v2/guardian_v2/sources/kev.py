"""CISA Known Exploited Vulnerabilities. Mirror the feed once per run (or
daily) so the demo works offline:
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load_catalog(mirror_path: str | None = None) -> dict[str, dict]:
    if mirror_path and Path(mirror_path).exists():
        data = json.loads(Path(mirror_path).read_text())
    else:
        with urllib.request.urlopen(KEV_URL, timeout=30) as resp:
            data = json.loads(resp.read())
        if mirror_path:
            Path(mirror_path).write_text(json.dumps(data))
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}
