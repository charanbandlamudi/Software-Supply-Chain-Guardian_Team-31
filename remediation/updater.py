from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def _git(repository: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repository,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"git {' '.join(args)} exited {result.returncode}")
    return result.stdout.strip()


def apply_approved_npm_plan(repository: str | Path, plan: dict) -> dict:
    repo = Path(repository).resolve()
    if not (repo / ".git").exists():
        raise RuntimeError("Refusing to update: repository is not a Git checkout")
    if _git(repo, "status", "--porcelain"):
        raise RuntimeError("Refusing to update: repository has existing working-tree changes")

    approved = [action for action in plan.get("changes", [])
                if action.get("status") == "approved"
                and action.get("ecosystem") == "npm"]
    if not approved:
        raise RuntimeError("No approved npm actions found")

    invalid = [action["action_id"] for action in approved
               if not action.get("recommended_version") or not action.get("approval")]
    if invalid:
        raise RuntimeError(f"Approved actions lack a fixed version or approval record: {invalid}")

    original_branch = _git(repo, "branch", "--show-current")
    branch = f"guardian/remediation-{plan['plan_id'][:8]}"
    _git(repo, "switch", "-c", branch)

    manifest_path = repo / "package.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    overrides = manifest.setdefault("overrides", {})
    applied = []
    for action in approved:
        package = action["package"]
        fixed = action["recommended_version"]
        existing = overrides.get(package)
        if existing not in (None, fixed):
            _git(repo, "switch", original_branch)
            raise RuntimeError(
                f"Refusing to overwrite existing override for {package}: {existing}"
            )
        overrides[package] = fixed
        applied.append({
            "action_id": action["action_id"],
            "package": package,
            "from": action["current_version"],
            "to": fixed,
            "method": "npm_override",
        })

    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    install = subprocess.run(
        ["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund"],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    if install.returncode != 0:
        raise RuntimeError(install.stderr.strip() or f"npm install exited {install.returncode}")

    applied_result = []
    for item in applied:
        action = next(a for a in approved if a["action_id"] == item["action_id"])
        action = {**action, "status": "applied", "changes_made": item}
        applied_result.append(action)

    return {
        "branch": branch,
        "original_branch": original_branch,
        "applied": applied_result,
        "changes_made": applied,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    args = parser.parse_args()
    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    result = apply_approved_npm_plan(args.repository, plan)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
