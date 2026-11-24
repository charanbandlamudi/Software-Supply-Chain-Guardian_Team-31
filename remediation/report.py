from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def write_remediation_report(plan: dict, output: str | Path) -> Path:
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "plan_id": plan.get("plan_id"),
        "status": plan.get("status"),
        "changes": plan.get("changes", []),
    }
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return output
