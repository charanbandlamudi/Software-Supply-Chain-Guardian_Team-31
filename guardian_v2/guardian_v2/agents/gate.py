"""Human Approval gate and Sandbox Validation agent."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from langgraph.types import interrupt

from ..evidence import make_evidence
from ..tools import npm, pypi
from .base import AgentResult, handoff


def run_approval(state: dict, task: dict) -> AgentResult:
    plans = {pid: p for pid, p in state.get("remediation_plans", {}).items() if p.get("status") == "proposed"}
    validated = {pid: p for pid, p in state.get("remediation_plans", {}).items()
                 if p.get("status") == "validated"}
    if validated:
        decision = interrupt({"question": "Approve the validated remediation report? Nothing is published.",
                              "gate": 2, "plans": validated})
        choices = decision.get("decisions", {})
        default = decision.get("all")
        updates, approvals = {}, []
        for pid, plan in validated.items():
            choice = choices.get(pid, default)
            if choice not in ("approve", "reject"):
                continue
            status = "approved" if choice == "approve" else "rejected"
            updates[pid] = {"status": status}
            approvals.append({"plan_id": pid, "decision": status, "gate": 2,
                              "reviewer": decision.get("reviewer", "unknown")})
        return AgentResult(delta={"remediation_plans": updates, "approvals": approvals},
                           summary=f"Gate 2: {sum(a['decision'] == 'approved' for a in approvals)} approved")
    if not plans:
        return AgentResult(summary="no plans awaiting approval")
    comps = state.get("components", {})
    brief = {pid: {"component": p["component"], "action": p["action"],
                   "from": (comps.get(p["component"]) or {}).get("version"),
                   "to": p.get("target_version"), "attempt": p.get("attempt"),
                   "rationale": p.get("rationale")} for pid, p in plans.items()}
    decision = interrupt({"question": "Approve these remediation plans? Nothing is merged automatically.",
                          "plans": brief})
    choices = decision.get("decisions", {})
    default = decision.get("all")
    updates, approvals = {}, []
    for pid in plans:
        choice = choices.get(pid, default)
        if choice not in ("approve", "reject"):
            continue
        status = "approved" if choice == "approve" else "rejected"
        updates[pid] = {"status": status}
        approvals.append({"plan_id": pid, "decision": status, "reviewer": decision.get("reviewer", "unknown"),
                          "attempt": plans[pid].get("attempt")})
    n = sum(1 for a in approvals if a["decision"] == "approved")
    return AgentResult(delta={"remediation_plans": updates, "approvals": approvals},
                       summary=f"human reviewer {decision.get('reviewer', 'unknown')}: {n} approved, "
                               f"{len(approvals) - n} rejected")




def _sandbox_runtime() -> str | None:
    configured = os.getenv("GUARDIAN_SANDBOX_RUNTIME")
    candidates = ([configured] if configured else []) + ["podman", "docker"]
    for runtime in candidates:
        if not runtime:
            continue
        try:
            p = subprocess.run(
                [runtime, "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=10,
                env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")},
            )
            if p.returncode == 0:
                return runtime
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return None


def _container_args(runtime: str, work: Path, image: str, command: list[str]) -> list[str]:
    del runtime
    return [
        "run", "--rm",
        "--network=none",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
        "--pids-limit", "128",
        "--memory", "1g",
        "--cpus", "1",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user", "65532:65532",
        "--mount", f"type=bind,src={work.resolve()},dst=/work,rw",
        "--workdir", "/work",
        "--env", "PYTHONNOUSERSITE=1",
        "--env", "PIP_DISABLE_PIP_VERSION_CHECK=1",
        "--env", "NPM_CONFIG_IGNORE_SCRIPTS=true",
        "--env", "HOME=/tmp",
        image,
        *command,
    ]


def _run_sandbox(work: Path, image: str, command: list[str], timeout: int = 600) -> tuple[int, str]:
    runtime = _sandbox_runtime()
    if not runtime:
        return 127, "No disposable container runtime available"
    try:
        p = subprocess.run(
            [runtime, *_container_args(runtime, work, image, command)],
            capture_output=True,
            text=True,
            timeout=timeout,
            env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")},
        )
        return p.returncode, (p.stdout + p.stderr)[-3000:]
    except (subprocess.TimeoutExpired, OSError) as exc:
        return 124, f"Sandbox execution failed: {type(exc).__name__}: {exc}"


def _safe_copy_file(source: Path, work: Path, project_root: Path) -> Path | None:
    try:
        source = source.resolve(strict=True)
        project_root = project_root.resolve(strict=True)
        relative = source.relative_to(project_root)
        destination = (work / "smoke" / relative).resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return None
    if work.resolve() not in destination.parents:
        return None
    if not source.is_file():
        return None
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    destination.chmod(0o400)
    return destination


def _safe_copy_directory(project_root: Path, work: Path, relative: str) -> bool:
    if not relative or Path(relative).is_absolute() or ".." in Path(relative).parts:
        return False
    try:
        source = (project_root / relative).resolve(strict=True)
        destination = (work / relative).resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    project_root = project_root.resolve(strict=True)
    work_root = work.resolve()
    if project_root not in source.parents or work_root not in destination.parents:
        return False
    if not source.is_dir():
        return False
    if destination.exists():
        shutil.rmtree(destination)
    shutil.copytree(source, destination, symlinks=False)
    return True


def _validate_python(state, plans, evidence):
    comps, inp = state["components"], state["inputs"]
    target = {p["component"]: p["target_version"] for p in plans if p["action"] == "upgrade"}
    removed = {p["component"] for p in plans if p["action"] == "remove"}
    pins = []
    for purl, c in comps.items():
        if c.get("ecosystem") != "pypi" or c.get("scope") == "environment" or purl in removed:
            continue
        if c.get("direct") or purl in target:
            pins.append(f"{c['name']}=={target.get(purl, c['version'])}")
    work = Path(tempfile.mkdtemp(prefix="guardian-py-", dir=tempfile.gettempdir()))
    work.chmod(0o700)
    steps = {}
    (work / "requirements.txt").write_text("\n".join(pins) + ("\n" if pins else ""), encoding="utf-8")
    code, out = _run_sandbox(
        work,
        "python:3.12-slim",
        ["python", "-m", "pip", "install", "-q", "--disable-pip-version-check",
         "--only-binary=:all:", "-r", "requirements.txt"],
    )
    steps["build"] = {"cmd": "sandbox pip install --only-binary=:all:", "ok": code == 0, "log": out[-1500:]}
    if code == 0 and inp.get("smoke_test"):
        smoke_project_root = Path(inp["smoke_test"]).resolve().parents[1]
        smoke = _safe_copy_file(Path(inp["smoke_test"]), work, smoke_project_root)
        if smoke is None:
            code, out = 1, "Unsafe smoke-test path outside project"
            smoke_rel = "smoke_test.py"
        else:
            smoke_rel = smoke.relative_to(work).as_posix()
            code, out = _run_sandbox(work, "python:3.12-slim", ["python", smoke_rel])
        steps["tests"] = {"cmd": f"python {smoke_rel}", "ok": code == 0, "log": out[-1500:]}
    after = {}
    if all(s["ok"] for s in steps.values()):
        for purl, c in comps.items():
            if c.get("ecosystem") == "pypi" and c.get("scope") != "environment":
                version = target.get(purl, c["version"])
                after[f"pkg:pypi/{c['name']}@{version}"] = {"name": c["name"], "version": version}
    shutil.rmtree(work, ignore_errors=True)
    return steps, after


def _validate_npm(state, plans, evidence):
    comps, inp = state["components"], state["inputs"]
    manifest = json.loads(Path(inp["npm_manifest"]).read_text())
    deps = manifest.setdefault("dependencies", {})
    overrides = {}
    for p in plans:
        name = comps[p["component"]]["name"]
        if p["action"] == "remove":
            deps.pop(name, None)
        elif p["action"] == "upgrade":
            if name in deps:
                deps[name] = p["target_version"]
            else:
                overrides[name] = p["target_version"]   # transitive: force via overrides
    if overrides:
        manifest["overrides"] = overrides
    work = Path(tempfile.mkdtemp(prefix="guardian-npm-", dir=tempfile.gettempdir()))
    work.chmod(0o700)
    (work / "package.json").write_text(json.dumps(manifest, indent=2))
    src = Path(inp["npm_manifest"]).parent
    for d in inp.get("npm_copy", []):
        _safe_copy_directory(src, work, d)
    steps = {}
    code, out = _run_sandbox(
        work,
        "node:20-slim",
        ["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--offline"],
    )
    steps["build"] = {"cmd": "npm install --ignore-scripts", "ok": code == 0, "log": out[-1500:]}
    if code == 0 and inp.get("npm_smoke"):
        smoke_project_root = src
        smoke = _safe_copy_file(Path(inp["npm_smoke"]), work, smoke_project_root)
        if smoke is None:
            code, out = 1, "Unsafe npm smoke-test path outside project"
            smoke_rel = "smoke/index.js"
        else:
            smoke_rel = smoke.relative_to(work).as_posix()
            code, out = _run_sandbox(work, "node:20-slim", ["node", smoke_rel])
        steps["tests"] = {"cmd": f"node {smoke_rel}", "ok": code == 0, "log": out[-800:]}
    after = {}
    if all(s["ok"] for s in steps.values()):
        lock = json.loads((work / "package-lock.json").read_text())
        for path, meta in lock.get("packages", {}).items():
            if path:
                name = path.split("node_modules/")[-1]
                after[f"pkg:npm/{name}@{meta['version']}"] = {"resolved": meta.get("resolved")}
    shutil.rmtree(work, ignore_errors=True)
    return steps, after


def _rescan(after: dict) -> dict[str, list[str]]:
    """Live re-scan of every package in the post-change environment."""
    found = {}
    npm_names = {}
    for purl in after:
        eco, rest = purl[4:].split("/", 1)
        name, ver = rest.rsplit("@", 1)
        if eco == "pypi":
            raw, _ = pypi.advisories_for(name, ver, purl)
            if raw:
                found[purl] = sorted({r["id"] for r in raw})
        else:
            npm_names.setdefault(name, []).append(ver)
    if npm_names:
        data, _, _ = npm.bulk_advisories(npm_names)
        for name, advs in (data or {}).items():
            for ver in npm_names[name]:
                from .. import versions as V
                hit = [a["url"].rsplit("/", 1)[-1] for a in advs if V.is_affected("npm", ver, [{"native": a["vulnerable_versions"]}])]
                if hit:
                    found[f"pkg:npm/{name}@{ver}"] = hit
    return found


def run_validation(state: dict, task: dict) -> AgentResult:
    plans = {pid: p for pid, p in state.get("remediation_plans", {}).items() if p.get("status") == "approved"}
    if not plans:
        return AgentResult(summary="nothing approved to validate")
    comps, evidence, results, updates, requests, lines = state["components"], {}, {}, {}, [], []
    for eco in ("pypi", "npm"):
        group = {pid: p for pid, p in plans.items()
                 if (comps.get(p["component"]) or {}).get("ecosystem") == eco
                 and (comps.get(p["component"]) or {}).get("scope") != "environment"
                 and p.get("action") in ("upgrade", "remove")}   # only changes the sandbox actually applies
        if not group:
            continue
        if eco == "npm" and not state["inputs"].get("npm_manifest"):
            continue
        steps, after = (_validate_python if eco == "pypi" else _validate_npm)(state, list(group.values()), evidence)
        ok = all(s["ok"] for s in steps.values())
        before = {p for p, c in comps.items() if c.get("ecosystem") == eco and c.get("scope") != "environment"}
        res = {"ecosystem": eco, "steps": steps, "ok": ok}
        if ok:
            res["sbom_diff"] = {"added": sorted(set(after) - before), "removed": sorted(before - set(after))}
            res["after_scan"] = _rescan(after)
            hosts = {p: m.get("resolved") for p, m in after.items()
                     if isinstance(m, dict) and m.get("resolved") and "registry.npmjs.org" not in m["resolved"]}
            res["untrusted_resolved_after"] = hosts
        eid, ev = make_evidence("validation_log", f"sandbox-{eco}", eco, res)
        evidence[eid] = ev
        res["evidence_id"] = eid
        results[eco] = res
        for pid in group:
            updates[pid] = {"status": "validated" if ok else "failed_validation", "validation_evidence": eid}
        if ok:
            residual = res["after_scan"]
            lines.append(f"{eco}: build+tests pass; added {len(res['sbom_diff']['added'])} / removed "
                         f"{len(res['sbom_diff']['removed'])} packages; residual vulnerable packages after "
                         f"change: {len(residual)}")
            requests.append(handoff("approval", f"{eco} sandbox validation passed; request Gate 2 review",
                                    gate=2, ecosystem=eco))
        else:
            failed = next(k for k, s in steps.items() if not s["ok"])
            log = steps[failed]["log"].strip().splitlines()
            reason = next((l for l in reversed(log) if "Error" in l or "error" in l), log[-1] if log else "")
            lines.append(f"{eco}: {failed} FAILED: {reason[:160]}")
            requests.append(handoff("remediation", f"sandbox {failed} failed: {reason[:200]}",
                                    strategy="latest_safe", components=[p["component"] for p in group.values()],
                                    failure=reason[:500]))
    return AgentResult(delta={"validation": results, "remediation_plans": updates, "evidence": evidence},
                       summary="; ".join(lines), requests=requests)
