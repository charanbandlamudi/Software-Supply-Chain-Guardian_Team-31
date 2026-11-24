from __future__ import annotations

import argparse
import json
import uuid
from collections import defaultdict
from hashlib import sha1
from datetime import datetime, timezone
from pathlib import Path

from remediation.analyzer import extract_grype_findings
from remediation.dependency_resolver import find_dependency
from remediation.version_selector import select_version


ROOT = Path(__file__).resolve().parent.parent
PLANS_DIR = ROOT / "data" / "remediation" / "plans"


def aggregate_remediation_actions(changes: list[dict]) -> list[dict]:
    grouped: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for change in changes:
        key = (
            change.get("ecosystem") or "unsupported",
            change.get("purl") or "",
            str(change.get("current_version") or ""),
        )
        grouped[key].append(change)

    severity_rank = {"UNKNOWN": 0, "NEGLIGIBLE": 1, "LOW": 2,
                     "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
    actions = []
    for (ecosystem, purl, current_version), findings in grouped.items():
        recommendations = [item.get("recommended_version") for item in findings]
        valid_recommendation = (
            bool(recommendations)
            and all(recommendations)
            and len(set(recommendations)) == 1
        )
        recommended = recommendations[0] if valid_recommendation else None
        first = findings[0]
        aliases = sorted({
            alias
            for item in findings
            for alias in item.get("aliases", [])
            if alias
        })
        vulnerability_ids = sorted({
            item.get("vulnerability_id")
            for item in findings
            if item.get("vulnerability_id")
        })
        worst = max(
            (item.get("severity", "UNKNOWN").upper() for item in findings),
            key=lambda severity: severity_rank.get(severity, 0),
        )
        action_key = f"{ecosystem}|{purl}|{current_version}"
        action_id = "ACTION-" + sha1(action_key.encode("utf-8")).hexdigest()[:12]
        status = (
            "requires_review"
            if first.get("dependency_type") in ("unresolved", "unknown")
            or not valid_recommendation
            else (
                "requires_dependency_review"
                if first.get("dependency_type") == "transitive"
                else "pending_approval"
            )
        )
        actions.append({
            "action_id": action_id,
            "package": first["package"],
            "ecosystem": ecosystem,
            "purl": purl,
            "current_version": current_version,
            "recommended_version": recommended,
            "candidate_versions": sorted({
                candidate
                for item in findings
                for candidate in item.get("candidate_versions", [])
            }),
            "severity": worst,
            "vulnerability_count": len(findings),
            "vulnerability_ids": vulnerability_ids,
            "aliases": aliases,
            "dependency_type": first.get("dependency_type", "unresolved"),
            "path_ids": first.get("path_ids", []),
            "parent_ids": sorted({
                parent
                for item in findings
                for parent in item.get("parent_ids", [])
            }),
            "strategy": "transitive_review" if status == "requires_dependency_review"
                        else first.get("strategy", "manual_review"),
            "status": status,
        })

    return sorted(actions, key=lambda action: action["package"])


def generate_plan(graph, grype_path: str | Path) -> dict:
    plan = {
        "plan_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "awaiting_approval",
        "changes": [],
    }

    for finding in extract_grype_findings(grype_path):
        version_info = select_version(finding)
        dependency = find_dependency(graph, finding)
        dep_type = dependency.get("dependency_type", "unresolved")
        recommended = version_info["recommended_version"]

        if dependency.get("status") != "resolved":
            strategy = "manual_review"
        elif version_info["status"] == "no_fix_available":
            strategy = "manual_review"
        elif version_info["status"] == "needs_review":
            strategy = "manual_review"
        elif dep_type == "direct":
            strategy = "direct_upgrade"
        elif dep_type == "transitive":
            strategy = "transitive_review"
        else:
            strategy = "manual_review"

        requires_review = strategy == "manual_review"
        plan["changes"].append({
            "package": finding["package"],
            "ecosystem": finding["ecosystem"],
            "purl": finding["purl"],
            "current_version": finding["current_version"],
            "recommended_version": recommended,
            "candidate_versions": version_info["candidates"],
            "severity": finding["severity"],
            "vulnerability_id": finding["vulnerability_id"],
            "aliases": finding["aliases"],
            "dependency_type": dep_type,
            "path_ids": dependency.get("path_ids", []),
            "parent_ids": dependency.get("parent_ids", []),
            "strategy": strategy,
            "status": "requires_review" if requires_review else "pending_approval",
        })

    plan["changes"] = aggregate_remediation_actions(plan["changes"])
    plan["status"] = "awaiting_approval"
    return plan


def resolve_latest_scan() -> tuple[dict, Path, Path]:
    scans_dir = ROOT / "data" / "scans"
    scan_records = sorted(scans_dir.glob("*/scan.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for scan_record in scan_records:
        meta = json.loads(scan_record.read_text(encoding="utf-8"))
        local_dir = scans_dir / meta["scan_id"]
        grype = local_dir / "scanner_results" / "grype.json"
        graph = local_dir / "graphs" / "graph.json"
        if grype.exists() and graph.exists():
            return meta, graph, grype
    raise FileNotFoundError("No scan with a local Grype report and graph.json was found")


def save_plan(plan: dict) -> Path:
    PLANS_DIR.mkdir(parents=True, exist_ok=True)
    plan_path = PLANS_DIR / "latest_plan.json"
    plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    return plan_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a conservative remediation plan")
    parser.add_argument("--graph", type=Path)
    parser.add_argument("--grype", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    if bool(args.graph) != bool(args.grype):
        parser.error("--graph and --grype must be provided together")
    if args.graph:
        graph_path, grype_path = args.graph, args.grype
    else:
        _, graph_path, grype_path = resolve_latest_scan()

    plan = generate_plan(json.loads(graph_path.read_text(encoding="utf-8")), grype_path)
    output = args.out or PLANS_DIR / "latest_plan.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    print(f"Remediation plan saved:\n{output}")


if __name__ == "__main__":
    main()
