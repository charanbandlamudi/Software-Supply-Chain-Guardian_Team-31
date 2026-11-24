from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def record_decision(plan: dict, action_id: str, decision: str, reviewer: str) -> dict:
    if decision not in ("approve", "reject"):
        raise ValueError("decision must be 'approve' or 'reject'")

    found = False
    changes = []
    for action in plan.get("changes", []):
        if action.get("action_id") == action_id:
            found = True
            action = dict(action)
            action["status"] = "approved" if decision == "approve" else "rejected"
            action["approval"] = {
                "decision": decision,
                "reviewer": reviewer,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        changes.append(action)
    if not found:
        raise KeyError(f"Unknown action: {action_id}")
    return {**plan, "changes": changes}


def record_decisions(plan: dict, decisions: dict[str, str], reviewer: str) -> dict:
    updated = plan
    for action_id, decision in decisions.items():
        updated = record_decision(updated, action_id, decision, reviewer)
    return updated


def save_approved_plan(plan: dict, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--approve", action="append", default=[], metavar="ACTION_ID")
    parser.add_argument("--reject", action="append", default=[], metavar="ACTION_ID")
    parser.add_argument("--reviewer", default="anonymous")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    decisions = {action_id: "approve" for action_id in args.approve}
    decisions.update({action_id: "reject" for action_id in args.reject})
    if not decisions:
        parser.error("provide at least one --approve or --reject action")
    updated = record_decisions(plan, decisions, args.reviewer)
    output = args.out or args.plan
    save_approved_plan(updated, output)
    print(f"Approval recorded:\n{output}")


if __name__ == "__main__":
    main()
