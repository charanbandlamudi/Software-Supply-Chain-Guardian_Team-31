"""Human-in-the-loop remediation: Gate 1 approval -> sandboxed validation -> Gate 2 approval.

Works on a finished scan folder. Nothing is ever applied to the user's checkout, pushed or merged:
  Gate 1   a named reviewer approves/rejects each agent remediation plan
  policy   every mutation is checked by guardian_v2's policy firewall (guardian/* branch + Gate 1)
  apply    approved npm changes are applied to a COPY of package.json (direct deps: new version;
           transitive: npm "overrides")
  resolve  new lockfile resolved on the host with --package-lock-only --ignore-scripts (metadata only,
           same safety as the scan pipeline: no package code runs)
  verify   target versions present / vulnerable versions gone in the new lockfile
  sandbox  Docker, two phases: install (network on, install scripts OFF, so no package code runs) then
           test (network OFF, read-only rootfs, all capabilities dropped, non-root, pid/memory/cpu
           limits) which actually loads every upgraded package
  re-scan  OSV-Scanner on the new lockfile: cleared / residual / newly introduced vulnerabilities
  Gate 2   a reviewer approves the validated change set -> patch + draft PR text (not pushed or merged)
Every human decision and policy verdict is appended to a SHA-256 hash-chained audit trail
(guardian_v2.audit), stored as remediation/audit.jsonl next to the scan.
"""
from __future__ import annotations

import difflib
import json
import shutil
import subprocess
import sys as _sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from pipeline.scan import ROOT, run, safe_env

if str(ROOT / "guardian_v2") not in _sys.path:
    _sys.path.insert(0, str(ROOT / "guardian_v2"))
from guardian_v2.audit import append_entry, verify_chain, write_audit  # noqa: E402
from guardian_v2.policy import evaluate_tool_call  # noqa: E402

SANDBOX_IMAGE = "node:22-slim"
AUTOMATABLE = {"upgrade", "remove"}
_ACTIVE: dict[str, threading.Thread] = _sys.__dict__.setdefault("_ssg_active_validations", {})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _rdir(scan_dir: Path) -> Path:
    d = Path(scan_dir) / "remediation"
    d.mkdir(exist_ok=True)
    return d


def _read(p: Path, default):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _write(p: Path, data) -> None:
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    tmp.replace(p)


# ------------------------------------------------------------------ audit trail
def audit_entries(scan_dir: Path) -> list[dict]:
    f = _rdir(scan_dir) / "audit.jsonl"
    if not f.exists():
        return []
    return [json.loads(line) for line in f.read_text(encoding="utf-8").splitlines() if line.strip()]


def _audit(scan_dir: Path, actor: str, action: str, tool: str, args: dict, decision: dict,
           result: str | None = None) -> dict:
    entries = audit_entries(scan_dir)
    entry = append_entry(entries, actor, action, tool, args, decision, result)
    write_audit(_rdir(scan_dir) / "audit.jsonl", entries)
    return entry


def audit_integrity(scan_dir: Path) -> tuple[bool, str | None]:
    return verify_chain(audit_entries(scan_dir))


# ------------------------------------------------------------------ plans + review state
def _name_version(purl: str) -> tuple[str, str]:
    body = purl.split("/", 1)[1].replace("%40", "@")
    name, ver = body.rsplit("@", 1)
    return name, ver


def load_plans(scan_dir: Path) -> list[dict]:
    rep = _read(Path(scan_dir) / "agents" / "guardian-report.json", {})
    findings = {f["id"]: f for f in rep.get("findings", [])}
    pkg = _read(Path(scan_dir) / "repo" / "package.json", {})
    direct = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {}), **pkg.get("optionalDependencies", {})}
    rows = []
    for pid, p in rep.get("remediation_plans", {}).items():
        if not p.get("action"):
            continue
        comp = p.get("component", "")
        eco = comp[4:].split("/", 1)[0] if comp.startswith("pkg:") else "file"
        name, ver = _name_version(comp) if comp.startswith("pkg:") else (comp.replace("file:", ""), None)
        repo_prefix = str(Path(scan_dir) / "repo") + "/"
        name = name.replace(repo_prefix, "")
        if "/repo/" in name and not comp.startswith("pkg:"):
            name = name.split("/repo/", 1)[1]
        fids = p.get("finding_ids", [])
        auto, why = False, ""
        if eco != "npm":
            why = "manual: only npm changes are validated in the web sandbox" if eco in ("pypi",) else "manual task"
        elif p["action"] == "upgrade" and p.get("target_version"):
            auto = True
        elif p["action"] == "remove":
            auto = name in direct
            why = "" if auto else "manual: transitive removal needs a change to the parent package"
        else:
            why = "manual task"
        rows.append({
            "plan_id": pid, "component": comp, "name": name, "version": ver, "ecosystem": eco,
            "direct": name in direct, "action": p["action"], "target_version": p.get("target_version"),
            "rationale": p.get("rationale"), "blocker": p.get("compatibility_blocker"),
            "agent_status": p.get("status"), "automatable": auto, "manual_reason": why,
            "clears": sorted({findings[f]["canonical_id"] for f in fids if f in findings
                              and findings[f].get("type") == "vulnerability"}),
            "signals": sorted({findings[f]["type"] for f in fids if f in findings and findings[f].get("type") != "vulnerability"}),
            "max_score": max((findings[f].get("score") or 0 for f in fids if f in findings), default=0),
        })
    rows.sort(key=lambda r: (not r["automatable"], -r["max_score"]))
    return rows


def load_review(scan_dir: Path) -> dict:
    return _read(_rdir(scan_dir) / "review.json", {"gate1": {}, "gate2": None})


def record_gate1(scan_dir: Path, decisions: dict[str, str], reviewer: str, note: str = "") -> dict:
    """decisions: plan_id -> 'approve' | 'reject'. Replaces any earlier Gate 1 decision for those plans."""
    if not reviewer.strip():
        raise ValueError("Reviewer name is required for an approval decision.")
    review = load_review(scan_dir)
    for pid, d in decisions.items():
        review["gate1"][pid] = {"decision": d, "reviewer": reviewer.strip(), "ts": _now(), "note": note}
    review["gate2"] = None                         # new Gate 1 decisions invalidate an earlier Gate 2
    _write(_rdir(scan_dir) / "review.json", review)
    n_ok = sum(1 for d in decisions.values() if d == "approve")
    _audit(scan_dir, f"human:{reviewer.strip()}", "gate1.decide", "remediation.approval",
           {"approved": n_ok, "rejected": len(decisions) - n_ok, "plans": sorted(decisions), "note": note[:200]},
           {"allow": True, "rule": "Gate 1 is a human decision"})
    return review


def record_gate2(scan_dir: Path, decision: str, reviewer: str, note: str = "") -> dict:
    if not reviewer.strip():
        raise ValueError("Reviewer name is required for an approval decision.")
    val = load_validation(scan_dir)
    if decision == "approve" and (not val or val.get("status") != "passed"):
        raise ValueError("Gate 2 approval needs a passed sandbox validation.")
    branch = f"guardian/remediation-{Path(scan_dir).name[-15:]}"
    policy = evaluate_tool_call({"tool": "git.open_pr", "args": {"draft": True, "branch": branch},
                                 "approval": {"gate2": decision == "approve"}})
    review = load_review(scan_dir)
    review["gate2"] = {"decision": decision, "reviewer": reviewer.strip(), "ts": _now(), "note": note,
                       "policy": policy, "validation_id": (val or {}).get("id")}
    out = {}
    if decision == "approve" and policy["allow"]:
        out = _write_change_set(scan_dir, val, review, branch)
        review["gate2"]["artifacts"] = out
    _write(_rdir(scan_dir) / "review.json", review)
    _audit(scan_dir, f"human:{reviewer.strip()}", f"gate2.{decision}", "git.open_pr",
           {"draft": True, "branch": branch, "note": note[:200]}, policy,
           result=json.dumps(out) if out else None)
    return review


# ------------------------------------------------------------------ validation
def load_validation(scan_dir: Path) -> dict | None:
    return _read(_rdir(scan_dir) / "validation.json", None)


def validation_running(scan_dir: Path) -> bool:
    t = _ACTIVE.get(str(scan_dir))
    return bool(t and t.is_alive())


def docker_available() -> tuple[bool, str]:
    try:
        p = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True,
                           timeout=15, env=safe_env())
        return (p.returncode == 0, p.stdout.strip() if p.returncode == 0 else (p.stderr.strip()[:160] or "docker not running"))
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
        return False, f"docker unavailable ({type(e).__name__})"


def start_validation(scan_dir: Path) -> None:
    scan_dir = Path(scan_dir)
    if validation_running(scan_dir):
        return
    t = threading.Thread(target=_validate, args=(scan_dir,), name="ssg-sandbox", daemon=True)
    _ACTIVE[str(scan_dir)] = t
    t.start()


def _sandbox_args(work: Path, network: bool, read_only: bool) -> list[str]:
    """Hardened container flags (from guardian_v2.agents.gate), with an explicit network switch."""
    return ["run", "--rm", "--network=bridge" if network else "--network=none",
            *(["--read-only"] if read_only else []),
            "--tmpfs", "/tmp:rw,nosuid,size=256m", "--pids-limit", "256", "--memory", "1g", "--cpus", "1",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user", "1000:1000",
            "--mount", f"type=bind,src={work.resolve()},dst=/work", "--workdir", "/work",
            "--env", "HOME=/tmp", "--env", "NPM_CONFIG_IGNORE_SCRIPTS=true", "--env", "NPM_CONFIG_UPDATE_NOTIFIER=false",
            "--env", "NPM_CONFIG_CACHE=/tmp/npm-cache"]


def _docker(work: Path, cmd: list[str], network: bool, read_only: bool, timeout: int, log: Path) -> int:
    with open(log, "wb") as out:
        return subprocess.run(["docker", *_sandbox_args(work, network, read_only), SANDBOX_IMAGE, *cmd],
                              stdout=out, stderr=subprocess.STDOUT, timeout=timeout, env=safe_env(),
                              stdin=subprocess.DEVNULL).returncode


def _lock_versions(lock: dict) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for path, meta in (lock.get("packages") or {}).items():
        if path and "version" in meta:
            out.setdefault(path.split("node_modules/")[-1], set()).add(meta["version"])
    return out


def _osv_vulns(osv_json: dict) -> set[tuple[str, str, str]]:
    return {(p["package"]["name"], p["package"]["version"], v["id"])
            for r in osv_json.get("results", []) for p in r.get("packages", []) for v in p.get("vulnerabilities", [])}


def _tail(p: Path, n: int = 2500) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")[-n:]
    except FileNotFoundError:
        return ""


def _validate(scan_dir: Path) -> None:
    rd = _rdir(scan_dir)
    review = load_review(scan_dir)
    plans = {p["plan_id"]: p for p in load_plans(scan_dir)}
    approved = [plans[pid] for pid, d in review["gate1"].items() if d["decision"] == "approve" and pid in plans]
    auto = [p for p in approved if p["automatable"]]
    manual = [p for p in approved if not p["automatable"]]
    reviewer = next((d["reviewer"] for d in review["gate1"].values() if d["decision"] == "approve"), "unknown")
    v = {"id": f"VAL-{int(time.time())}", "started_at": _now(), "finished_at": None, "status": "running",
         "approved_by": reviewer, "plans": [p["plan_id"] for p in auto], "manual_tasks": [p["plan_id"] for p in manual],
         "steps": [], "results": {}}
    vpath = rd / "validation.json"

    def step(name: str, status: str, detail: str = "", log: str = "", **extra) -> None:
        v["steps"].append({"name": name, "status": status, "detail": detail, "log": log, "ts": _now(), **extra})
        _write(vpath, v)

    def finish(status: str) -> None:
        v.update(status=status, finished_at=_now())
        _write(vpath, v)
        _audit(scan_dir, "agent:sandbox_validation", "validation.finish", "test.run",
               {"plans": v["plans"], "status": status}, {"allow": True, "rule": "sandbox result"},
               result=v["id"])

    _write(vpath, v)
    try:
        if not auto:
            step("select", "skipped", f"No automatable package changes approved ({len(manual)} manual tasks).")
            return finish("passed" if manual else "nothing_to_validate")
        step("select", "ok", f"{len(auto)} package change(s) to apply; {len(manual)} manual task(s) recorded")

        # 1. policy firewall: mutations only on a guardian/* branch with Gate 1 approval
        branch = f"guardian/remediation-{scan_dir.name[-15:]}"
        verdicts = {t: evaluate_tool_call({"tool": t, "args": {"branch": branch}, "approval": {"gate1": True}})
                    for t in ("pkg.apply", "docker.build", "test.run")}
        for t, d in verdicts.items():
            _audit(scan_dir, "agent:sandbox_validation", "policy.check", t, {"branch": branch}, d)
        if not all(d["allow"] for d in verdicts.values()):
            step("policy", "failed", "; ".join(f"{t}: {d['deny_reason']}" for t, d in verdicts.items() if not d["allow"]))
            return finish("failed")
        step("policy", "ok", f"policy firewall allows pkg.apply, docker.build, test.run on {branch} with Gate 1")

        # 2. apply approved changes to a copy of the manifest
        repo, work = scan_dir / "repo", rd / "work"
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True)
        before_pkg = json.loads((repo / "package.json").read_text(encoding="utf-8"))
        pkg = json.loads(json.dumps(before_pkg))
        overrides = dict(pkg.get("overrides") or {})
        applied = []
        for p in auto:
            name, target = p["name"], p["target_version"]
            sections = [s for s in ("dependencies", "devDependencies", "optionalDependencies") if name in pkg.get(s, {})]
            if p["action"] == "remove":
                for s in sections:
                    pkg[s].pop(name, None)
                applied.append(f"remove {name}")
            elif sections:
                for s in sections:
                    pkg[s][name] = target
                if name in overrides:
                    overrides[name] = target
                applied.append(f"{name}: {p['version']} -> {target} (direct)")
            else:
                overrides[name] = target           # transitive: force via npm overrides
                applied.append(f"{name}: {p['version']} -> {target} (override)")
        # npm rejects an override for a direct dependency unless the specs are identical
        for s in ("dependencies", "devDependencies", "optionalDependencies"):
            for n in list(overrides):
                if n in pkg.get(s, {}) and pkg[s][n] != overrides[n]:
                    overrides[n] = f"${n}"
        if overrides:
            pkg["overrides"] = overrides
        (work / "package.json").write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
        if (repo / "package-lock.json").exists():
            shutil.copy2(repo / "package-lock.json", work / "package-lock.json")
        diff = "".join(difflib.unified_diff(json.dumps(before_pkg, indent=2).splitlines(True),
                                            json.dumps(pkg, indent=2).splitlines(True),
                                            "a/package.json", "b/package.json"))
        v["results"]["package_json_diff"] = diff
        step("apply", "ok", f"{len(applied)} change(s) applied to a copy of package.json", "\n".join(applied))

        # 3. resolve the new lockfile (metadata only, no scripts)
        t0 = time.monotonic()
        rc = run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                  "--legacy-peer-deps", "--fetch-timeout=30000", "--fetch-retries=5"], cwd=work, timeout=1200,
                 stderr=rd / "resolve.log")
        if rc != 0:
            step("resolve", "failed", f"npm could not resolve the changed dependencies (exit {rc})", _tail(rd / "resolve.log"),
                 seconds=round(time.monotonic() - t0, 1))
            return finish("failed")
        step("resolve", "ok", "new package-lock.json resolved (no package code executed)", seconds=round(time.monotonic() - t0, 1))

        # 4. verify versions in the new lockfile
        old_lock = _read(repo / "package-lock.json", {})
        new_lock = _read(work / "package-lock.json", {})
        oldv, newv = _lock_versions(old_lock), _lock_versions(new_lock)
        checks, bad = [], 0
        for p in auto:
            if p["action"] == "remove":
                ok = p["name"] not in newv
                checks.append({"package": p["name"], "expected": "removed", "found": sorted(newv.get(p["name"], [])), "ok": ok})
            else:
                found = newv.get(p["name"], set())
                ok = p["target_version"] in found and p["version"] not in found
                checks.append({"package": p["name"], "expected": p["target_version"], "was": p["version"],
                               "found": sorted(found), "ok": ok})
            bad += 0 if ok else 1
        added = sorted(set(newv) - set(oldv))
        removed = sorted(set(oldv) - set(newv))
        changed = sorted(n for n in set(oldv) & set(newv) if oldv[n] != newv[n])
        v["results"].update(version_checks=checks, lockfile_diff={"added": added, "removed": removed, "changed": changed})
        step("verify", "ok" if not bad else "warn",
             f"{len(checks) - bad}/{len(checks)} target versions confirmed in the new lockfile; "
             f"{len(added)} packages added, {len(removed)} removed, {len(changed)} changed")

        # 5-6. sandbox: install (network on, scripts off) then load the packages (network off)
        ok_docker, why = docker_available()
        upgraded = [p for p in auto if p["action"] == "upgrade"]
        if not ok_docker:
            step("sandbox", "skipped", f"No container runtime: {why}. Start Docker to execute the change in the sandbox.")
        elif upgraded:
            sb = work / "sandbox"
            sb.mkdir()
            deps = {}
            for p in upgraded:
                deps[p["name"]] = p["target_version"]
            (sb / "package.json").write_text(json.dumps({"name": "guardian-sandbox", "private": True,
                                                         "dependencies": deps}, indent=2), encoding="utf-8")
            names = json.dumps(sorted(deps))
            (sb / "smoke.cjs").write_text(
                "const names=" + names + ";const out={};\n"
                "for (const n of names){try{const v=require(n+'/package.json').version;"
                "try{require(n);out[n]={version:v,status:'loaded'}}catch(e){"
                "out[n]={version:v,status:(e.code==='ERR_PACKAGE_PATH_NOT_EXPORTED'||e.code==='MODULE_NOT_FOUND')?"
                "'no importable entry point (CLI or subpath-only package)':'load_failed',error:String(e.message).slice(0,200)}}}"
                "catch(e){out[n]={status:'not_installed',error:String(e.message).slice(0,200)}}}\n"
                "console.log(JSON.stringify(out));\n", encoding="utf-8")
            t0 = time.monotonic()
            rc = _docker(sb, ["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--legacy-peer-deps"],
                         network=True, read_only=False, timeout=900, log=rd / "sandbox-install.log")
            if rc != 0:
                step("sandbox_install", "failed", f"install in sandbox failed (exit {rc})", _tail(rd / "sandbox-install.log"),
                     seconds=round(time.monotonic() - t0, 1))
                return finish("failed")
            step("sandbox_install", "ok", f"{len(deps)} upgraded package(s) installed in a container with install "
                 "scripts disabled (no package code ran)", _tail(rd / "sandbox-install.log", 800),
                 seconds=round(time.monotonic() - t0, 1))
            t0 = time.monotonic()
            rc = _docker(sb, ["node", "smoke.cjs"], network=False, read_only=True, timeout=300, log=rd / "sandbox-test.log")
            raw = _tail(rd / "sandbox-test.log", 20000).strip().splitlines()
            try:
                res = json.loads(raw[-1]) if raw else {}
            except json.JSONDecodeError:
                res = {}
            v["results"]["sandbox_load"] = res
            failed = [n for n, r in res.items() if r.get("status") in ("load_failed", "not_installed")]
            status = "failed" if (rc != 0 or not res or failed) else "ok"
            step("sandbox_test", status,
                 f"executed in an isolated container (no network, read-only, no capabilities): "
                 f"{sum(1 for r in res.values() if r.get('status') == 'loaded')} loaded, "
                 f"{sum(1 for r in res.values() if 'entry point' in r.get('status', ''))} without an importable entry point, "
                 f"{len(failed)} failed", _tail(rd / "sandbox-test.log", 1500), seconds=round(time.monotonic() - t0, 1))
            if status == "failed":
                return finish("failed")

        # 7. re-scan the new lockfile
        t0 = time.monotonic()
        rc = run(["osv-scanner", "scan", "--lockfile", str(work / "package-lock.json"), "--format", "json"],
                 timeout=600, stdout=rd / "rescan-osv.json", stderr=rd / "rescan.log")
        if rc not in (0, 1):
            step("rescan", "failed", f"osv-scanner exited {rc}", _tail(rd / "rescan.log"))
            return finish("failed")
        before = _osv_vulns(_read(scan_dir / "scanner_results" / "osv.json", {}))
        after = _osv_vulns(_read(rd / "rescan-osv.json", {}))
        targeted = {p["name"] for p in auto}
        cleared = sorted({f"{n}@{ver} {i}" for n, ver, i in before - after if n in targeted})
        residual = sorted({f"{n}@{ver} {i}" for n, ver, i in after if n in targeted})
        introduced = sorted({f"{n}@{ver} {i}" for n, ver, i in after - before})
        v["results"]["rescan"] = {"before_total": len(before), "after_total": len(after), "cleared": cleared,
                                  "residual_on_changed_packages": residual, "newly_introduced": introduced}
        step("rescan", "ok" if not introduced else "warn",
             f"vulnerabilities {len(before)} → {len(after)}: {len(cleared)} cleared on changed packages, "
             f"{len(residual)} remain on them, {len(introduced)} newly introduced", seconds=round(time.monotonic() - t0, 1))
        finish("passed")
    except Exception as e:  # never leave the UI waiting on a dead thread
        step("error", "failed", f"{type(e).__name__}: {str(e)[:300]}")
        finish("failed")


# ------------------------------------------------------------------ Gate 2 output
def _write_change_set(scan_dir: Path, val: dict, review: dict, branch: str) -> dict:
    rd = _rdir(scan_dir)
    plans = {p["plan_id"]: p for p in load_plans(scan_dir)}
    out = {}
    if (rd / "work" / "package.json").exists():
        patch = val["results"].get("package_json_diff", "")
        (rd / "guardian-remediation.patch").write_text(patch, encoding="utf-8")
        shutil.copy2(rd / "work" / "package-lock.json", rd / "package-lock.remediated.json")
        out.update(patch=str(rd / "guardian-remediation.patch"), lockfile=str(rd / "package-lock.remediated.json"))
    rs = val["results"].get("rescan", {})
    lines = [f"# [Guardian] Supply-chain remediation (draft)", "",
             f"Branch: `{branch}` · Draft PR — **not pushed or merged** (merge is human-only by policy).", "",
             f"Gate 1 approved by: {val.get('approved_by')} · Gate 2 approved by: {review['gate2']['reviewer']} "
             f"({review['gate2']['ts']})", "", "## Package changes (sandbox-validated)", ""]
    for pid in val.get("plans", []):
        p = plans.get(pid, {})
        lines.append(f"- **{p.get('name')}** {p.get('version')} → {p.get('target_version') or 'removed'}"
                     + (f" — clears {', '.join(p.get('clears', [])[:6])}" if p.get("clears") else ""))
    lines += ["", "## Validation evidence", ""]
    for s in val.get("steps", []):
        lines.append(f"- `{s['name']}`: **{s['status']}** — {s['detail']}")
    if rs:
        lines += ["", f"Re-scan: {rs.get('before_total')} → {rs.get('after_total')} known vulnerabilities; "
                      f"{len(rs.get('cleared', []))} cleared on changed packages; "
                      f"{len(rs.get('newly_introduced', []))} newly introduced."]
    manual = [plans[pid] for pid in val.get("manual_tasks", []) if pid in plans]
    if manual:
        lines += ["", "## Manual tasks approved at Gate 1", ""]
        lines += [f"- [ ] {p['action']}: {p['name']} — {p.get('rationale') or ''}" for p in manual]
    ok, err = audit_integrity(scan_dir)
    entries = audit_entries(scan_dir)
    lines += ["", f"Audit trail: {len(entries)} entries, integrity {'valid' if ok else 'INVALID: ' + str(err)}, "
                  f"head `{entries[-1]['hash'][:16] if entries else 'n/a'}`."]
    (rd / "PR_DRAFT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    out["pr_draft"] = str(rd / "PR_DRAFT.md")
    return out
