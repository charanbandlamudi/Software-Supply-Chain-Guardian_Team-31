from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _npm_json(args: list[str], cwd: Path) -> tuple[bool, dict | list | str]:
    try:
        result = subprocess.run(
            ["npm", *args],
            cwd=cwd,
            env=_safe_npm_env(),
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if result.returncode != 0:
            return False, result.stderr.strip() or f"npm exited {result.returncode}"
        return True, json.loads(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _safe_npm_env() -> dict:
    import os

    env = dict(os.environ)
    env.pop("NPM_TOKEN", None)
    env.pop("NODE_AUTH_TOKEN", None)
    env["npm_config_audit"] = "false"
    env["npm_config_fund"] = "false"
    env["npm_config_ignore_scripts"] = "true"
    return env


def read_installed_tree(repository: str | Path) -> dict:
    repo = Path(repository).resolve()
    ok, data = _npm_json(["ls", "--all", "--json"], repo)
    if not ok:
        return {"status": "unavailable", "reason": str(data), "dependencies": {}}
    return {"status": "ok", "dependencies": data.get("dependencies", {}) if isinstance(data, dict) else {}}


def inspect_package(repository: str | Path, package: str) -> dict:
    repo = Path(repository).resolve()
    ok, data = _npm_json(["view", package, "version", "dependencies", "engines", "--json"], repo)
    if not ok:
        return {"status": "unavailable", "reason": str(data)}
    return {"status": "ok", "registry": data}


def resolve_action(repository: str | Path, action: dict) -> dict:
    repo = Path(repository).resolve()
    if action.get("ecosystem") != "npm":
        return {**action, "status": "requires_dependency_review",
                "resolver": {"status": "unsupported", "reason": "npm resolver only supports npm packages"}}

    lockfile = repo / "package-lock.json"
    if not lockfile.exists():
        return {**action, "status": "requires_dependency_review",
                "resolver": {"status": "unavailable", "reason": "package-lock.json not found"}}

    lock = json.loads(lockfile.read_text(encoding="utf-8"))
    current = action["current_version"]
    fixed = action.get("recommended_version")
    parents = action.get("parent_ids") or []
    installed = read_installed_tree(repo)

    parent_constraints = {}
    parent_registry = {}
    for parent in sorted(set(parents)):
        parent_name = Path(str(parent)).name
        parent_constraints[parent_name] = {}
        packages = lock.get("packages") or {}
        parent_info = packages.get(f"node_modules/{parent_name}") or {}
        parent_constraints[parent_name] = {
            "resolved_installed": parent_info.get("version"),
            "lockfile_dependencies": parent_info.get("dependencies") or {},
            "lockfile_optional_dependencies": parent_info.get("optionalDependencies") or {},
        }
        parent_registry[parent_name] = inspect_package(repo, parent_name)

    package_registry = inspect_package(repo, action["package"])
    return {
        **action,
        "resolver": {
            "status": "investigation_required",
            "repository": str(repo),
            "parents": sorted(set(parents)),
            "parent_constraints": parent_constraints,
            "parent_registry": parent_registry,
            "package_registry": package_registry,
            "installed_tree": installed,
            "fixed_version": fixed,
            "override_possible": fixed is not None,
            "parent_upgrade": None,
            "recommended_strategy": "upgrade_parent" if parent_registry else "override",
        },
        "status": "requires_dependency_review",
    }


def resolve_plan(repository: str | Path, plan: dict) -> dict:
    changes = [resolve_action(repository, action) for action in plan.get("changes", [])]
    return {**plan, "status": "awaiting_approval", "changes": changes}


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Investigate npm transitive dependency remediation")
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    plan = json.loads(args.plan.read_text(encoding="utf-8"))
    resolved = resolve_plan(args.repository, plan)
    output = args.out or args.plan
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(resolved, indent=2), encoding="utf-8")
    print(f"Dependency investigation saved:\n{output}")


if __name__ == "__main__":
    main()
