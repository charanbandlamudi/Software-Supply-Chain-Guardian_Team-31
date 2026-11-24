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
  Gate 2   a reviewer approves the validated change set -> local patch and report
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
from guardian_v2.build_gate import evaluate as evaluate_build_gate  # noqa: E402

SANDBOX_IMAGE = "node:22-slim"
CACHE_VOLUME = "guardian-npm-cache"          # shared npm download cache for sandbox installs
# Native modules whose install script may run (in the sandbox) to fetch their prebuilt binary.
# Every other package — including every upgraded one — installs with scripts disabled.
# Whole-app build/test + image scan + SBOM diff are slow (~6 min on Juice Shop), so they are off by default.
FULL_APP_VALIDATION = __import__("os").environ.get("GUARDIAN_FULL_APP_VALIDATION", "").lower() in ("1", "true", "yes")
NATIVE_ALLOWLIST = [n.strip() for n in __import__("os").environ.get("GUARDIAN_SANDBOX_NATIVE_ALLOWLIST", "sqlite3").split(",") if n.strip()]
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
        related = [findings[f] for f in fids if f in findings]
        source_conflicts = sorted({
            json.dumps(c, sort_keys=True, default=str)
            for f in related
            for c in (f.get("source_conflicts") or [])
        })
        sources = sorted({s for f in related for s in (f.get("sources") or [])})
        evidence_ids = sorted({e for f in related for e in (f.get("evidence_ids") or [])})
        severities = sorted({str(f.get("severity") or f.get("tool_severity") or "UNKNOWN")
                             for f in related if f})
        cvss_values = [f.get("cvss") for f in related if isinstance(f.get("cvss"), dict)]
        cvss_scores = [v.get("score") for v in cvss_values if v.get("score") is not None]
        epss_values = [f.get("epss") for f in related if isinstance(f.get("epss"), dict)]
        epss_scores = [v.get("epss") for v in epss_values if v.get("epss") is not None]
        kev = any(bool(f.get("kev")) for f in related)
        reachability = sorted({str(f.get("reachability_state") or "unknown") for f in related})
        compatibility = p.get("compatibility") or {}
        blocker_raw = p.get("compatibility_blocker")
        blocker_verified = bool(blocker_raw) and bool(
            compatibility.get("parent_constraint_blockers")
            or compatibility.get("co_upgrade_required")
        )
        blocker_status = ("verified" if blocker_verified else
                          "reported" if blocker_raw else "none")
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
            "blocker_status": blocker_status,
            "blocker_details": compatibility,
            "agent_status": p.get("status"), "automatable": auto, "manual_reason": why,
            "sources": sources, "source_conflicts": [json.loads(c) for c in source_conflicts],
            "evidence_ids": evidence_ids, "severities": severities,
            "risk_score": max((f.get("score") or 0 for f in related), default=0),
            "cvss": max(cvss_scores, default=None), "epss": max(epss_scores, default=None),
            "kev": kev, "reachability": reachability,
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
    """decisions: plan_id -> 'approve' | 'reject' | 'accept_risk'. Replaces earlier Gate 1 decisions.
    'accept_risk' = the reviewer knowingly keeps the risk (no change); it needs a written justification."""
    if not reviewer.strip():
        raise ValueError("Reviewer name is required for an approval decision.")
    if any(d == "accept_risk" for d in decisions.values()) and len(note.strip()) < 10:
        raise ValueError("Accepting a risk needs a written justification in the comment (at least a sentence).")
    review = load_review(scan_dir)
    for pid, d in decisions.items():
        review["gate1"][pid] = {"decision": d, "reviewer": reviewer.strip(), "ts": _now(), "note": note}
    review["gate2"] = None                         # new Gate 1 decisions invalidate an earlier Gate 2
    _write(_rdir(scan_dir) / "review.json", review)
    n_ok = sum(1 for d in decisions.values() if d == "approve")
    n_acc = sum(1 for d in decisions.values() if d == "accept_risk")
    _audit(scan_dir, f"human:{reviewer.strip()}", "gate1.decide", "remediation.approval",
           {"approved": n_ok, "accepted_risk": n_acc, "rejected": len(decisions) - n_ok - n_acc,
            "plans": sorted(decisions), "note": note[:200]},
           {"allow": True, "rule": "Gate 1 is a human decision"})
    return review


def record_gate2(scan_dir: Path, decision: str, reviewer: str, note: str = "") -> dict:
    if not reviewer.strip():
        raise ValueError("Reviewer name is required for an approval decision.")
    val = load_validation(scan_dir)
    if decision == "approve" and (not val or val.get("status") != "passed"):
        raise ValueError("Gate 2 approval needs a passed sandbox validation.")
    report_path = Path(scan_dir) / "agents" / "guardian-report.json"
    report = _read(report_path, {})
    build_gate = evaluate_build_gate({
        "findings": report.get("findings", []),
        "cicd_findings": report.get("cicd_findings", []),
        "container_images": report.get("container_images", []),
        "license_violations": report.get("license_violations", []),
        "requested_actions": [],
    })
    policy = build_gate if decision == "approve" else {"allow": True, "deny_reason": []}
    review = load_review(scan_dir)
    review["gate2"] = {"decision": decision, "reviewer": reviewer.strip(), "ts": _now(), "note": note,
                       "policy": policy, "validation_id": (val or {}).get("id")}
    out = {}
    if decision == "approve" and policy["allow"]:
        out = _write_change_set(scan_dir, val, review)
        review["gate2"]["artifacts"] = out
    _write(_rdir(scan_dir) / "review.json", review)
    # post-remediation report (validation results, before/after, remaining & accepted risk, rollback)
    review["gate2"]["remediation_report"] = write_remediation_report(scan_dir)
    _write(_rdir(scan_dir) / "review.json", review)
    _audit(scan_dir, f"human:{reviewer.strip()}", f"gate2.{decision}", "remediation.approval",
           {"note": note[:200], "build_gate": "allow" if policy.get("allow") else "deny"}, policy,
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


def _sandbox_args(work: Path, network: bool, read_only: bool, cache: bool = False,
                  scripts: bool = False, memory: str = "1g") -> list[str]:
    """Hardened container flags (from guardian_v2.agents.gate), with an explicit network switch.
    scripts=True is only used for the explicit native-module allow-list rebuild."""
    return ["run", "--rm", "--network=bridge" if network else "--network=none",
            *(["--read-only"] if read_only else []),
            "--tmpfs", "/tmp:rw,nosuid,size=512m", "--pids-limit", "512", "--memory", memory, "--cpus", "2",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user", "1000:1000",
            "--mount", f"type=bind,src={work.resolve()},dst=/work", "--workdir", "/work",
            *(["--mount", f"type=volume,src={CACHE_VOLUME},dst=/npm-cache"] if cache else []),
            "--env", "HOME=/tmp", "--env", f"NPM_CONFIG_IGNORE_SCRIPTS={'false' if scripts else 'true'}",
            "--env", "NPM_CONFIG_UPDATE_NOTIFIER=false", "--env", "NPM_CONFIG_FUND=false", "--env", "CI=true",
            "--env", f"NPM_CONFIG_CACHE={'/npm-cache' if cache else '/tmp/npm-cache'}"]


def _docker(work: Path, cmd: list[str], network: bool, read_only: bool, timeout: int, log: Path,
            **kw) -> int:
    with open(log, "wb") as out:
        return subprocess.run(["docker", *_sandbox_args(work, network, read_only, **kw), SANDBOX_IMAGE, *cmd],
                              stdout=out, stderr=subprocess.STDOUT, timeout=timeout, env=safe_env(),
                              stdin=subprocess.DEVNULL).returncode


def apply_package_changes(text: str, changes: list[dict]) -> tuple[str, list[str]]:
    """Apply approved changes to package.json text: direct dependencies get the target version,
    transitive ones an npm "overrides" entry; removals drop direct dependencies. Only those keys
    change; key order is preserved and the file's indentation is kept."""
    pkg = json.loads(text)
    m = _re.search(r'\n([ \t]+)"', text)
    indent = m.group(1) if m else "  "
    overrides = dict(pkg.get("overrides") or {})
    applied = []
    for c in changes:
        name, target = c["name"], c["target"]
        sections = [s for s in ("dependencies", "devDependencies", "optionalDependencies") if name in pkg.get(s, {})]
        if c["action"] == "remove":
            for s in sections:
                pkg[s].pop(name, None)
            applied.append(f"remove {name}")
        elif sections:
            for s in sections:
                pkg[s][name] = target
            if name in overrides:
                overrides[name] = target
            applied.append(f"{name}: {c.get('version')} -> {target} (direct)")
        else:
            overrides[name] = target               # transitive: force via npm overrides
            applied.append(f"{name}: {c.get('version')} -> {target} (override)")
    # npm rejects an override for a direct dependency unless the specs are identical
    for s in ("dependencies", "devDependencies", "optionalDependencies"):
        for n in list(overrides):
            if n in pkg.get(s, {}) and pkg[s][n] != overrides[n]:
                overrides[n] = f"${n}"
    if overrides:
        pkg["overrides"] = overrides
    out = json.dumps(pkg, indent=indent, ensure_ascii=False)
    return out + ("\n" if text.endswith("\n") else ""), applied


def git_patch(before: str, after: str, name: str) -> str:
    """A real git patch (valid for `git apply`), produced by git itself."""
    import tempfile
    with tempfile.TemporaryDirectory(prefix="guardian-patch-") as t:
        (Path(t) / "a").mkdir()
        (Path(t) / "b").mkdir()
        (Path(t) / "a" / name).write_text(before, encoding="utf-8")
        (Path(t) / "b" / name).write_text(after, encoding="utf-8")
        p = subprocess.run(["git", "diff", "--no-index", "--no-color", "--src-prefix=", "--dst-prefix=",
                            f"a/{name}", f"b/{name}"], cwd=t, capture_output=True, text=True, env=safe_env())
        return p.stdout.replace(f"a/{name}", f"a/{name}", 1)


def _scan_tag(scan_dir: Path) -> str:
    """Timestamp part of the scan folder name (<owner>__<repo>__<YYYYmmdd-HHMMSS[-micro]>)."""
    return Path(scan_dir).name.rsplit("__", 1)[-1]


def _pr_branch(scan_dir: Path) -> str:
    return f"guardian/remediation-{_scan_tag(scan_dir)}"


def _sha256(p: Path) -> str | None:
    import hashlib
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None


ROLLBACK_MEANING = ("Rollback is the plan for undoing this change if it causes problems after it is merged: "
                    "restore the exact dependency files the application had before, so it returns to its "
                    "previously working (but vulnerable) state while the issue is investigated.")


def _rollback_snapshot(scan_dir: Path, repo: Path) -> dict:
    """Keep the original manifest + lockfile (with hashes) so the change can be undone exactly."""
    orig = _rdir(scan_dir) / "original"
    orig.mkdir(exist_ok=True)
    files = {}
    for name in ("package.json", "package-lock.json"):
        if (repo / name).exists():
            shutil.copy2(repo / name, orig / name)
            files[name] = _sha256(orig / name)
    branch = _pr_branch(scan_dir)
    return {"meaning": ROLLBACK_MEANING, "original_files": files, "saved_in": str(orig),
            "steps": [f"If the change was merged as a single commit: `git revert <merge-commit>` (or close the draft PR / delete branch `{branch}` if not merged).",
                      "Or restore the saved originals: copy remediation/original/package.json (and package-lock.json) back into the repository.",
                      "Reinstall with `npm ci` and confirm the files match the recorded SHA-256 hashes: "
                      + ", ".join(f"{k} {v[:16]}…" for k, v in files.items()),
                      "Re-run the Guardian scan to confirm the application is back to its previous state."]}


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
        v.update(status=status, finished_at=_now(), final_confidence=_final_confidence(v, status))
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
        branch = _pr_branch(scan_dir)
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
        changes = [{"name": p["name"], "version": p["version"], "action": p["action"], "target": p["target_version"]}
                   for p in auto]
        original_text = (repo / "package.json").read_text(encoding="utf-8")
        new_text, applied = apply_package_changes(original_text, changes)
        (work / "package.json").write_text(new_text, encoding="utf-8")
        if (repo / "package-lock.json").exists():
            shutil.copy2(repo / "package-lock.json", work / "package-lock.json")
        diff = git_patch(original_text, new_text, "package.json")
        v["results"]["changes"] = changes
        v["results"]["package_json_diff"] = diff
        v["results"]["rollback"] = _rollback_snapshot(scan_dir, repo)
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

        # 8. the whole application, before vs after: install, build, tests, container image, image scan, SBOM
        #    (opt-in: GUARDIAN_FULL_APP_VALIDATION=1)
        if not FULL_APP_VALIDATION:
            pass
        elif not ok_docker:
            step("app", "skipped", "No container runtime: whole-application build/test/image steps need Docker.")
        elif not (repo / "package.json").exists():
            step("app", "skipped", "Whole-application validation is implemented for npm projects only.")
        elif not _validate_app(scan_dir, repo, work, v, step):
            return finish("failed")
        finish("passed")
    except Exception as e:  # never leave the UI waiting on a dead thread
        step("error", "failed", f"{type(e).__name__}: {str(e)[:300]}")
        finish("failed")


# ------------------------------------------------------------------ Gate 2 output
def _write_change_set(scan_dir: Path, val: dict, review: dict) -> dict:
    rd = _rdir(scan_dir)
    plans = {p["plan_id"]: p for p in load_plans(scan_dir)}
    out = {}
    if (rd / "work" / "package.json").exists():
        patch = val["results"].get("package_json_diff", "")
        (rd / "guardian-remediation.patch").write_text(patch, encoding="utf-8")
        shutil.copy2(rd / "work" / "package-lock.json", rd / "package-lock.remediated.json")
        out.update(patch=str(rd / "guardian-remediation.patch"), lockfile=str(rd / "package-lock.remediated.json"))
    rs = val["results"].get("rescan", {})
    lines = ["# [Guardian] Supply-chain remediation change set", "",
             f"If opened as a pull request: branch `{_pr_branch(scan_dir)}`, **draft**, never merged automatically "
             "(merge is human-only by policy).", "",
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
    app = val["results"].get("app") or {}
    if app.get("variants"):
        lines += ["", "## Whole-application build & tests (sandbox, no network)", ""]
        for script in (app["scripts"].get("build") or []) + (app["scripts"].get("tests") or []):
            b, a = app["variants"].get("before", {}).get(script, {}), app["variants"].get("after", {}).get(script, {})
            lines.append(f"- `npm run {script}`: before {'✅' if b.get('ok') else '❌'} → after {'✅' if a.get('ok') else '❌'}"
                         + (f" ({a.get('passed')} passed / {a.get('failed')} failed)" if a.get("passed") is not None else ""))
        if app.get("image_diff"):
            lines.append(f"- Image scan (Trivy): {app['image_diff']['vulns_before']} → {app['image_diff']['vulns_after']} vulnerabilities")
        if app.get("sbom_diff"):
            sd = app["sbom_diff"]
            lines.append(f"- SBOM diff: {len(sd['added'])} added, {len(sd['removed'])} removed, {len(sd['changed'])} version changes")
    conf = val.get("final_confidence") or {}
    if conf:
        lines += ["", f"**Final confidence: {conf.get('level')}** — {'; '.join(conf.get('reasons', []))}"]
    accepted = [(pid, d) for pid, d in review.get("gate1", {}).items() if d["decision"] == "accept_risk" and pid in plans]
    if accepted:
        lines += ["", "## Accepted risks (no change made)", ""]
        lines += [f"- {plans[pid]['name']} ({plans[pid]['action']}) — accepted by {d['reviewer']}: {d.get('note') or ''}" for pid, d in accepted]
    rb = val["results"].get("rollback") or {}
    if rb:
        lines += ["", "## Rollback", "", f"_{rb.get('meaning')}_", ""] + [f"{i}. {x}" for i, x in enumerate(rb.get("steps", []), 1)]
    manual = [plans[pid] for pid in val.get("manual_tasks", []) if pid in plans]
    if manual:
        lines += ["", "## Manual tasks approved at Gate 1", ""]
        lines += [f"- [ ] {p['action']}: {p['name']} — {p.get('rationale') or ''}" for p in manual]
    ok, err = audit_integrity(scan_dir)
    entries = audit_entries(scan_dir)
    lines += ["", f"Audit trail: {len(entries)} entries, integrity {'valid' if ok else 'INVALID: ' + str(err)}, "
                  f"head `{entries[-1]['hash'][:16] if entries else 'n/a'}`."]
    (rd / "CHANGESET.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    out["changeset"] = str(rd / "CHANGESET.md")
    return out


# ------------------------------------------------------------------ whole-application validation
import re as _re  # noqa: E402

TEST_SUMMARY = [  # node --test (TAP), mocha, jest, vitest
    (_re.compile(r"^# pass (\d+)", _re.M), _re.compile(r"^# fail (\d+)", _re.M)),
    (_re.compile(r"(\d+) passing", _re.M), _re.compile(r"(\d+) failing", _re.M)),
    (_re.compile(r"Tests:.*?(\d+) passed", _re.M), _re.compile(r"Tests:.*?(\d+) failed", _re.M)),
]


def _parse_tests(log: str) -> dict:
    m = _re.search(r"^# tests (\d+)", log, _re.M)
    total = int(m.group(1)) if m else None
    for p_re, f_re in TEST_SUMMARY:
        p, f = p_re.findall(log), f_re.findall(log)
        if p or f:
            return {"passed": sum(map(int, p)), "failed": sum(map(int, f)), "total": total}
    return {"passed": None, "failed": None, "total": total}


def _ensure_cache_volume() -> None:
    subprocess.run(["docker", "volume", "create", CACHE_VOLUME], capture_output=True, env=safe_env(), timeout=60)
    # the volume starts root-owned; the sandbox runs as uid 1000 (root used only for this chown, no network)
    subprocess.run(["docker", "run", "--rm", "--network=none", "--mount", f"type=volume,src={CACHE_VOLUME},dst=/npm-cache",
                    SANDBOX_IMAGE, "chown", "-R", "1000:1000", "/npm-cache"], capture_output=True, env=safe_env(), timeout=120)


def _scripts_to_run(pkg: dict) -> dict[str, list[str]]:
    s = pkg.get("scripts") or {}
    build = next((k for k in ("build:server", "build:backend", "compile", "build") if k in s), None)
    unit = next((k for k in ("test:server", "test:unit", "test:backend") if k in s), None)
    integ = next((k for k in ("test:api", "test:integration", "test:int") if k in s), None)
    if not unit and not integ and "test" in s:
        unit = "test"
    return {"build": [build] if build else [], "tests": [t for t in (unit, integ) if t]}


def _image_scan(scan_dir: Path, app: Path, tag: str, rd: Path) -> dict:
    """Image from a generated Dockerfile with NO RUN steps (nothing executes at build time), then Trivy."""
    (app / "Dockerfile.guardian").write_text(
        f"FROM {SANDBOX_IMAGE}\nWORKDIR /app\nCOPY --chown=1000:1000 . /app\nUSER 1000\nCMD [\"node\", \"--version\"]\n",
        encoding="utf-8")
    # The repo's own .dockerignore usually excludes node_modules; a Dockerfile-specific ignore file takes
    # precedence (BuildKit), so the image really contains the installed dependencies being compared.
    (app / "Dockerfile.guardian.dockerignore").write_text(".git\n", encoding="utf-8")
    out = {"tag": tag}
    b = subprocess.run(["docker", "build", "-q", "-f", str(app / "Dockerfile.guardian"), "-t", tag, str(app)],
                       capture_output=True, text=True, env=safe_env(), timeout=1800)
    if b.returncode != 0:
        return {**out, "error": b.stderr[-500:]}
    tar = rd / f"{tag.replace(':', '_').replace('/', '_')}.tar"
    subprocess.run(["docker", "save", "-o", str(tar), tag], capture_output=True, env=safe_env(), timeout=1800)
    vuln_json, sbom_json = rd / f"image-{tag.split(':')[-1]}-trivy.json", rd / f"image-{tag.split(':')[-1]}-sbom.cdx.json"
    run(["trivy", "image", "--input", str(tar), "--scanners", "vuln", "--skip-db-update", "--no-progress",
         "--format", "json", "--output", str(vuln_json)], timeout=1800, stderr=rd / "image-trivy.log")
    run(["trivy", "image", "--input", str(tar), "--skip-db-update", "--no-progress",
         "--format", "cyclonedx", "--output", str(sbom_json)], timeout=1800, stderr=rd / "image-sbom.log")
    tar.unlink(missing_ok=True)
    subprocess.run(["docker", "rmi", "-f", tag], capture_output=True, env=safe_env(), timeout=300)
    sev, ids = {}, set()
    for r in (_read(vuln_json, {}).get("Results") or []):
        for x in r.get("Vulnerabilities") or []:
            sev[x.get("Severity", "UNKNOWN")] = sev.get(x.get("Severity", "UNKNOWN"), 0) + 1
            ids.add(f"{x.get('PkgName')}@{x.get('InstalledVersion')} {x.get('VulnerabilityID')}")
    comps = {f"{c.get('name')}@{c.get('version')}" for c in _read(sbom_json, {}).get("components", [])}
    return {**out, "vulnerabilities": len(ids), "by_severity": sev, "vuln_ids": sorted(ids),
            "components": sorted(comps), "trivy_json": str(vuln_json), "sbom": str(sbom_json)}


def _validate_app(scan_dir: Path, repo: Path, work: Path, v: dict, step) -> bool:
    """Install, build and test the whole application before and after the change, in the sandbox, then
    build both as images, scan them and diff their SBOMs. Returns False on a regression."""
    rd = _rdir(scan_dir)
    pkg = json.loads((repo / "package.json").read_text(encoding="utf-8"))
    plan = _scripts_to_run(pkg)
    _ensure_cache_volume()
    ignore = shutil.ignore_patterns(".git", "node_modules", ".angular", "coverage", "Dockerfile.guardian*")
    apps = {}
    for variant in ("before", "after"):
        app = work / f"app-{variant}"
        shutil.rmtree(app, ignore_errors=True)
        shutil.copytree(repo, app, ignore=ignore, symlinks=False)
        if variant == "after":
            shutil.copy2(work / "package.json", app / "package.json")
            shutil.copy2(work / "package-lock.json", app / "package-lock.json")
        apps[variant] = app
    app_res = {"scripts": plan, "native_allowlist": NATIVE_ALLOWLIST, "variants": {}}
    v["results"]["app"] = app_res

    for variant, app in apps.items():
        r = app_res["variants"].setdefault(variant, {})
        log = rd / f"app-{variant}-install.log"
        t0 = time.monotonic()
        rc = _docker(app, ["npm", "ci", "--ignore-scripts", "--no-audit", "--legacy-peer-deps"], network=True,
                     read_only=False, timeout=2400, log=log, cache=True, memory="3g")
        if rc != 0:      # lockfile slightly out of sync with package.json: fall back to install
            rc = _docker(app, ["npm", "install", "--ignore-scripts", "--no-audit", "--legacy-peer-deps"], network=True,
                         read_only=False, timeout=2400, log=log, cache=True, memory="3g")
        r["install"] = {"ok": rc == 0, "seconds": round(time.monotonic() - t0, 1)}
        step(f"app_install_{variant}", "ok" if rc == 0 else "failed",
             f"{variant}: full dependency install in the sandbox, install scripts disabled", _tail(log, 800),
             seconds=r["install"]["seconds"])
        if rc != 0:
            return variant == "before" and step("app", "warn", "the original application does not install in "
                                                "the sandbox; whole-app comparison skipped") is None
        native = [n for n in NATIVE_ALLOWLIST if (app / "node_modules" / n).exists()]
        if native:
            nlog = rd / f"app-{variant}-native.log"
            rc = _docker(app, ["npm", "rebuild", *native], network=True, read_only=False, timeout=900, log=nlog,
                         cache=True, scripts=True)
            r["native_rebuild"] = {"packages": native, "ok": rc == 0}
            step(f"app_native_{variant}", "ok" if rc == 0 else "warn",
                 f"{variant}: install scripts allowed only for the allow-listed native module(s) {', '.join(native)}",
                 _tail(nlog, 600))
        for kind in ("build", "tests"):
            for script in plan[kind]:
                slog = rd / f"app-{variant}-{script.replace(':', '_')}.log"
                t0 = time.monotonic()
                try:
                    rc = _docker(app, ["npm", "run", script], network=False, read_only=True, timeout=1500, log=slog,
                                 memory="3g")
                except subprocess.TimeoutExpired:
                    rc = 124
                text = _tail(slog, 200000)
                res = {"ok": rc == 0, "exit": rc, "seconds": round(time.monotonic() - t0, 1), **(_parse_tests(text) if kind == "tests" else {})}
                r[script] = res
                step(f"app_{'build' if kind == 'build' else 'test'}_{variant}", "ok" if rc == 0 else "warn",
                     f"{variant}: `npm run {script}` with no network" + (f" — {res.get('passed')} passed, {res.get('failed')} failed"
                                                                         if kind == "tests" and res.get("passed") is not None else f" — exit {rc}"),
                     text[-1500:], seconds=res["seconds"])

    # regressions: anything that worked before the change but not after
    regressions = []
    b, a = app_res["variants"]["before"], app_res["variants"]["after"]
    for script in plan["build"] + plan["tests"]:
        if (b.get(script) or {}).get("ok") and not (a.get(script) or {}).get("ok"):
            regressions.append(f"{script}: passed before, fails after")
        bf, af = (b.get(script) or {}).get("failed"), (a.get(script) or {}).get("failed")
        if bf is not None and af is not None and af > bf:
            regressions.append(f"{script}: {af} failing tests after vs {bf} before")
    app_res["regressions"] = regressions
    notes = []
    for script in plan["tests"]:
        bt, at = (b.get(script) or {}).get("total"), (a.get(script) or {}).get("total")
        if bt and at is not None and at < bt * 0.95:
            notes.append(f"{script}: {at} tests ran after vs {bt} before (none failed; this suite's test count also "
                         "varies between runs of the unchanged code)")
    app_res["test_count_notes"] = notes
    step("app_compare", "failed" if regressions else ("warn" if notes else "ok"),
         "; ".join(regressions) if regressions else ("no failing-test regressions; note: " + "; ".join(notes) if notes
                                                     else "no build or test regressions compared with the original application"))

    # images: build (no RUN steps), Trivy-scan and SBOM-diff both variants
    t0 = time.monotonic()
    img = {variant: _image_scan(scan_dir, app, f"guardian-{_scan_tag(scan_dir).lower()}:{variant}", rd)
           for variant, app in apps.items()}
    app_res["images"] = {k: {kk: vv for kk, vv in x.items() if kk not in ("components", "vuln_ids")} for k, x in img.items()}
    if any("error" in x for x in img.values()):
        step("image_scan", "warn", "image build failed: " + "; ".join(x.get("error", "")[:200] for x in img.values() if "error" in x))
    else:
        bv, av = set(img["before"]["vuln_ids"]), set(img["after"]["vuln_ids"])
        bc, ac = set(img["before"]["components"]), set(img["after"]["components"])
        app_res["image_diff"] = {"vulns_before": len(bv), "vulns_after": len(av), "cleared": sorted(bv - av),
                                 "introduced": sorted(av - bv)}
        app_res["sbom_diff"] = sbom_diff(bc, ac)
        step("image_scan", "ok" if not (av - bv) else "warn",
             f"images built without running any build step and scanned with Trivy: {len(bv)} → {len(av)} vulnerabilities "
             f"({len(bv - av)} cleared, {len(av - bv)} introduced)", seconds=round(time.monotonic() - t0, 1))
        sd = app_res["sbom_diff"]
        step("sbom_diff", "ok", f"image SBOMs (CycloneDX): {sd['components_before']} → {sd['components_after']} components; "
             f"{len(sd['added'])} added, {len(sd['removed'])} removed, {len(sd['changed'])} version changes")
    for app in apps.values():                       # free disk: node_modules are large
        shutil.rmtree(app / "node_modules", ignore_errors=True)
    return not regressions


def sbom_diff(before: set[str], after: set[str]) -> dict:
    """Exact name@version comparison (a package can exist in several versions at once);
    'changed' lists names whose set of versions differs."""
    def by_name(s_):
        out = {}
        for c in s_:
            if "@" in c[1:]:
                n, ver = c.rsplit("@", 1)
                out.setdefault(n, set()).add(ver)
        return out
    bn, an = by_name(before), by_name(after)
    return {"components_before": len(before), "components_after": len(after),
            "added": sorted(after - before), "removed": sorted(before - after),
            "changed": sorted(f"{n}: {', '.join(sorted(bn[n]))} → {', '.join(sorted(an[n]))}"
                              for n in set(an) & set(bn) if an[n] != bn[n])}


def _final_confidence(v: dict, status: str) -> dict:
    """High / medium / low, with the reasons — derived only from what actually ran."""
    st = {x["name"]: x["status"] for x in v.get("steps", [])}
    reasons = []
    if status != "passed":
        return {"level": "low", "reasons": ["validation did not pass"]}
    rs = v.get("results", {}).get("rescan", {})
    app = v.get("results", {}).get("app", {})
    level = "high"
    if rs.get("newly_introduced"):
        level, _ = "low", reasons.append(f"{len(rs['newly_introduced'])} newly introduced vulnerabilities in the lockfile")
    if not app or not app.get("variants"):
        level = "medium" if level == "high" else level
        reasons.append("whole application not built/tested" + ("" if FULL_APP_VALIDATION else
                       " (turned off for speed; set GUARDIAN_FULL_APP_VALIDATION=1 to enable)"))
    else:
        tests = [s for s in (app.get("scripts", {}).get("tests") or [])]
        after = app["variants"].get("after", {})
        if not tests:
            level = "medium" if level == "high" else level
            reasons.append("the project defines no unit/integration test scripts")
        elif any((after.get(t) or {}).get("failed") for t in tests):
            level = "medium" if level == "high" else level
            reasons.append("some tests fail, but they failed the same way before the change (pre-existing)")
        if app.get("test_count_notes"):
            level = "medium" if level == "high" else level
            reasons.append("fewer tests ran after the change (none failed)")
        if (app.get("image_diff") or {}).get("introduced"):
            level = "low"
            reasons.append(f"{len(app['image_diff']['introduced'])} vulnerabilities introduced in the image scan")
    if st.get("sandbox_test") != "ok":
        level = "medium" if level == "high" else level
        reasons.append("package load test in the sandbox did not run")
    if not reasons:
        reasons.append("lockfile resolved, versions verified, packages loaded in the sandbox, app built and tested "
                       "with no regressions, re-scans show no new vulnerabilities")
    return {"level": level, "reasons": reasons}


# ------------------------------------------------------------------ post-remediation report
def build_remediation_report(scan_dir: Path) -> dict:
    scan_dir = Path(scan_dir)
    meta = _read(scan_dir / "scan.json", {})
    rep = _read(scan_dir / "agents" / "guardian-report.json", {})
    findings = {f["id"]: f for f in rep.get("findings", [])}
    plans = {p["plan_id"]: p for p in load_plans(scan_dir)}
    review, val = load_review(scan_dir), load_validation(scan_dir) or {}
    g1 = review.get("gate1", {})
    plan_fids = {pid: (rep.get("remediation_plans", {}).get(pid) or {}).get("finding_ids", []) for pid in plans}

    def originals(pid):
        out = []
        for fid in plan_fids.get(pid, []):
            f = findings.get(fid)
            if f:
                out.append({"identifier": f.get("canonical_id"), "type": f.get("type"), "score": f.get("score"),
                            "ssvc": (f.get("ssvc") or {}).get("decision"), "summary": (f.get("summary") or "")[:200],
                            "evidence": (f.get("evidence_ids") or [])[:4]})
        return out

    def row(pid, d):
        p = plans[pid]
        return {"plan_id": pid, "component": p["name"] + (f"@{p['version']}" if p.get("version") else ""),
                "action": p["action"], "target": p.get("target_version"), "decision": d["decision"],
                "reviewer": d["reviewer"], "at": d["ts"], "note": d.get("note"), "mode": "sandbox" if p["automatable"] else "manual",
                "original_findings": originals(pid)}
    decided = [row(pid, d) for pid, d in g1.items() if pid in plans]
    approved = [r for r in decided if r["decision"] == "approve"]
    accepted = [r for r in decided if r["decision"] == "accept_risk"]
    rejected = [r for r in decided if r["decision"] == "reject"]
    undecided = [{"plan_id": pid, "component": p["name"], "action": p["action"]} for pid, p in plans.items() if pid not in g1]
    res = val.get("results", {})
    rs, app = res.get("rescan", {}), res.get("app", {})
    entries = audit_entries(scan_dir)
    ok, err = audit_integrity(scan_dir)
    remaining = {
        "residual_on_changed_packages": rs.get("residual_on_changed_packages", []),
        "known_vulnerabilities_after_change": rs.get("after_total"),
        "rejected_plans": [f"{r['component']} ({r['action']})" for r in rejected],
        "undecided_plans": len(undecided),
        "manual_tasks_pending": [f"{r['component']}: {r['action']}" for r in approved if r["mode"] == "manual"],
    }
    return {
        "schema": "ssg-remediation-report/1", "generated_at": _now(),
        "target": {"repository": meta.get("target"), "name": meta.get("repo_name"), "commit": meta.get("commit"),
                   "scan_id": meta.get("scan_id")},
        "validation": {"id": val.get("id"), "status": val.get("status"), "started_at": val.get("started_at"),
                       "finished_at": val.get("finished_at"), "steps": [{k: s[k] for k in ("name", "status", "detail")}
                                                                       for s in val.get("steps", [])]},
        "approved_actions": approved, "accepted_risks": accepted, "rejected_actions": rejected,
        "build_and_test": {"package_load": res.get("sandbox_load"), "app": {k: app.get(k) for k in
                                                                            ("scripts", "variants", "regressions", "native_allowlist")} if app else None},
        "before_after": {"lockfile_vulnerabilities": {"before": rs.get("before_total"), "after": rs.get("after_total"),
                                                      "cleared": rs.get("cleared", []), "introduced": rs.get("newly_introduced", [])},
                         "image": app.get("image_diff"), "image_scans": app.get("images"), "sbom": app.get("sbom_diff"),
                         "lockfile_diff": res.get("lockfile_diff"), "version_checks": res.get("version_checks")},
        "remaining_risk": remaining,
        "final_confidence": val.get("final_confidence"),
        "rollback": res.get("rollback"),
        "gate2": review.get("gate2"),
        "audit": {"entries": len(entries), "integrity": "valid" if ok else f"invalid: {err}",
                  "head_hash": entries[-1]["hash"] if entries else None},
    }


def _remediation_html(r: dict) -> str:
    from reporting.guardian_report import CSS, _e
    t, val = r["target"], r["validation"]
    conf = r.get("final_confidence") or {}
    h = [f"<!doctype html><html><head><meta charset='utf-8'><meta http-equiv='Content-Security-Policy' "
         f"content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>Remediation report — {_e(t['name'])}</title>"
         f"<style>{CSS}</style></head><body><div class='page'><div class='brand'>SOFTWARE SUPPLY CHAIN GUARDIAN</div>",
         f"<h1>Remediation report — {_e(t['name'])}</h1><div class='muted'>{_e(t['repository'])} · commit "
         f"<code>{_e((t.get('commit') or '')[:12])}</code> · validation {_e(val.get('id'))} · <b>{_e(val.get('status'))}</b> · "
         f"final confidence <b>{_e(conf.get('level', 'n/a'))}</b></div>"]
    h.append("<p class='small muted'>" + _e("; ".join(conf.get("reasons", []))) + "</p>")
    ba = r["before_after"]
    lv, im, sb = ba.get("lockfile_vulnerabilities") or {}, ba.get("image") or {}, ba.get("sbom") or {}
    h.append("<h2>1. Before vs after</h2><div class='grid'>" + "".join(
        f"<div class='kpi'><b>{_e(v)}</b><span>{_e(k)}</span></div>" for k, v in [
            ("Known vulns (lockfile) before → after", f"{lv.get('before')} → {lv.get('after')}"),
            ("Cleared / introduced (lockfile)", f"{len(lv.get('cleared') or [])} / {len(lv.get('introduced') or [])}"),
            ("Image vulns before → after", f"{im.get('vulns_before', 'n/a')} → {im.get('vulns_after', 'n/a')}"),
            ("SBOM components before → after", f"{sb.get('components_before', 'n/a')} → {sb.get('components_after', 'n/a')}")]) + "</div>")
    if sb:
        h.append(f"<p class='small'>SBOM diff: {len(sb.get('added', []))} added, {len(sb.get('removed', []))} removed, "
                 f"{len(sb.get('changed', []))} version changes. Changed: {_e(', '.join(sb.get('changed', [])[:12]))}</p>")
    h.append("<h2>2. Approved actions and the findings they address</h2>")
    for a in r["approved_actions"]:
        h.append(f"<div class='card'><h4>{_e(a['component'])} <span class='chip'>{_e(a['action'])}{' → ' + _e(a['target']) if a.get('target') else ''}</span>"
                 f"<span class='chip'>{_e(a['mode'])}</span></h4><div class='small muted'>approved by {_e(a['reviewer'])} at {_e(a['at'])}</div>"
                 + "".join(f"<div class='small'>• <code>{_e(o['identifier'])}</code> ({_e(o['type'])}, score {_e(o['score'])}, SSVC {_e(o['ssvc'])}) — {_e(o['summary'])}"
                           f" <span class='muted'>evidence: {_e(', '.join(o['evidence']))}</span></div>" for o in a["original_findings"]) + "</div>")
    bt = r["build_and_test"].get("app") or {}
    h.append("<h2>3. Build and test results (sandbox, no network)</h2>")
    if bt:
        rows = []
        for script in (bt.get("scripts", {}).get("build") or []) + (bt.get("scripts", {}).get("tests") or []):
            b, a = (bt["variants"].get("before") or {}).get(script, {}), (bt["variants"].get("after") or {}).get(script, {})
            fmt = lambda x: ("✅" if x.get("ok") else "❌") + (f" {x.get('passed')} passed / {x.get('failed')} failed" if x.get("passed") is not None else f" exit {x.get('exit')}")
            rows.append(f"<tr><td><code>npm run {_e(script)}</code></td><td>{_e(fmt(b))}</td><td>{_e(fmt(a))}</td></tr>")
        h.append("<table><tr><th>Step</th><th>Before</th><th>After</th></tr>" + "".join(rows) + "</table>")
        h.append(f"<p class='small'>Regressions: {_e('; '.join(bt.get('regressions') or []) or 'none')}. Install scripts were "
                 f"disabled for every package except the allow-listed native module(s) {_e(', '.join(bt.get('native_allowlist') or []))}.</p>")
    else:
        h.append("<p class='muted'>Whole-application build/test did not run.</p>")
    h.append("<table><tr><th>Validation step</th><th>Status</th><th>Result</th></tr>" + "".join(
        f"<tr><td>{_e(s['name'])}</td><td>{_e(s['status'])}</td><td class='small'>{_e(s['detail'])}</td></tr>" for s in val.get("steps", [])) + "</table>")
    rr = r["remaining_risk"]
    h.append("<h2>4. Remaining and accepted risk</h2><ul>"
             f"<li>Known vulnerabilities remaining after the change: <b>{_e(rr.get('known_vulnerabilities_after_change'))}</b></li>"
             f"<li>Still present on the changed package names: {_e(', '.join(rr['residual_on_changed_packages'][:10]) or 'none')}</li>"
             f"<li>Rejected plans: {_e(', '.join(rr['rejected_plans'][:15]) or 'none')}</li>"
             f"<li>Plans not yet decided: {_e(rr['undecided_plans'])}</li>"
             f"<li>Approved manual tasks still to do: {_e('; '.join(rr['manual_tasks_pending'][:10]) or 'none')}</li></ul>")
    if r["accepted_risks"]:
        h.append("<table><tr><th>Accepted risk</th><th>By</th><th>Justification</th></tr>" + "".join(
            f"<tr><td>{_e(a['component'])} ({_e(a['action'])})</td><td>{_e(a['reviewer'])}</td><td>{_e(a.get('note'))}</td></tr>"
            for a in r["accepted_risks"]) + "</table>")
    else:
        h.append("<p class='small muted'>No risks were explicitly accepted.</p>")
    rb = r.get("rollback") or {}
    h.append(f"<h2>5. Rollback</h2><p>{_e(rb.get('meaning', ''))}</p><ol>" + "".join(f"<li>{_e(x)}</li>" for x in rb.get("steps", [])) + "</ol>")
    g2, au = r.get("gate2") or {}, r["audit"]
    h.append(f"<h2>6. Approval and audit trail</h2><p>Gate 2: <b>{_e(g2.get('decision', 'pending'))}</b> by {_e(g2.get('reviewer', '—'))} "
             f"{_e(g2.get('ts', ''))}. Audit trail: {_e(au['entries'])} entries, integrity <b>{_e(au['integrity'])}</b>, head "
             f"<code>{_e((au.get('head_hash') or '')[:16])}</code>. Nothing was merged or published automatically.</p>")
    h.append(f"<p class='small muted'>Generated {_e(r['generated_at'])}.</p></div></body></html>")
    return "\n".join(h)


def write_remediation_report(scan_dir: Path) -> dict:
    from reporting.guardian_report import render_pdf
    rd = _rdir(scan_dir)
    r = build_remediation_report(scan_dir)
    (rd / "remediation-report.json").write_text(json.dumps(r, indent=2, default=str), encoding="utf-8")
    (rd / "remediation-report.html").write_text(_remediation_html(r), encoding="utf-8")
    pdf = render_pdf(rd / "remediation-report.html", rd / "remediation-report.pdf")
    return {"json": str(rd / "remediation-report.json"), "html": str(rd / "remediation-report.html"),
            "pdf": str(rd / "remediation-report.pdf") if pdf == "ok" else None, "pdf_status": pdf}


# ------------------------------------------------------------------ draft pull request (after Gate 2)
def _gh(*args: str, timeout: int = 120) -> str:
    p = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=timeout, env=safe_env(), stdin=subprocess.DEVNULL)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip()[:300] or f"gh {' '.join(args[:2])} failed")
    return p.stdout.strip()


def _existing_fork(upstream: str) -> str | None:
    """The logged-in user's fork of `upstream`, whatever it is named (GitHub allows one fork per account)."""
    try:
        forks = _gh("api", "user/repos", "--paginate", "--jq", ".[] | select(.fork) | .full_name").splitlines()
    except RuntimeError:
        return None
    for r in forks:
        try:
            if _gh("api", f"repos/{r}", "--jq", "[.parent.full_name, .source.full_name] | join(\" \")").split()[:2].count(upstream):
                return r
        except RuntimeError:
            continue
    return None


def pr_target(scan_dir: Path) -> dict:
    """Where a draft PR would go: the scanned repo if the logged-in user can push to it, otherwise
    the user's own fork. Never a repository the user cannot push to."""
    meta = _read(Path(scan_dir) / "scan.json", {})
    if meta.get("kind") != "github":
        return {"ok": False, "reason": "draft PRs are only supported for GitHub repositories"}
    upstream = meta["repo_name"]
    try:
        login = _gh("api", "user", "--jq", ".login")
    except RuntimeError as e:
        return {"ok": False, "reason": f"GitHub CLI not logged in ({e}); run `gh auth login`"}
    try:
        push = _gh("api", f"repos/{upstream}", "--jq", ".permissions.push") == "true"
    except RuntimeError:
        push = False
    existing = None if push else _existing_fork(upstream)
    target = upstream if push else (existing or f"{login}/{upstream.split('/', 1)[1]}")
    return {"ok": True, "login": login, "upstream": upstream, "target": target, "fork": not push,
            "fork_exists": bool(existing),
            "reason": "you have push access to the scanned repository" if push else
            (f"you cannot push to {upstream}, so the PR goes to your existing fork {target}" if existing else
             f"you cannot push to {upstream}, so the PR goes to a new fork {target}") + f"; {upstream} itself is never touched"}


def open_draft_pr(scan_dir: Path, reviewer: str, dry_run: bool = False) -> dict:
    """dry_run=True does everything except creating a fork, pushing and opening the PR: it clones the
    target branch, checks the approved patch still applies, commits locally and returns a preview."""
    scan_dir = Path(scan_dir)
    review, val = load_review(scan_dir), load_validation(scan_dir) or {}
    g2 = review.get("gate2") or {}
    if g2.get("decision") != "approve":
        raise ValueError("A draft PR needs Gate 2 approval first.")
    if not reviewer.strip():
        raise ValueError("Reviewer name is required.")
    tgt = pr_target(scan_dir)
    if not tgt["ok"]:
        raise ValueError(tgt["reason"])
    branch = _pr_branch(scan_dir)
    for tool, args, appr in (("git.branch", {"branch": branch}, {"gate1": True}),
                             ("git.open_pr", {"draft": True, "branch": branch}, {"gate2": True})):
        d = evaluate_tool_call({"tool": tool, "args": args, "approval": appr})
        _audit(scan_dir, f"human:{reviewer.strip()}", "policy.check", tool, {**args, "target": tgt["target"]}, d)
        if not d["allow"]:
            raise ValueError(f"policy firewall denied {tool}: {d['deny_reason']}")
    rd = _rdir(scan_dir).resolve()                        # absolute: git runs with cwd inside this folder
    clone_from = tgt["target"]
    if tgt["fork"]:
        try:
            _gh("api", f"repos/{tgt['target']}", "--jq", ".full_name")
        except RuntimeError:
            if dry_run:
                clone_from = tgt["upstream"]                  # fork doesn't exist yet: preview against upstream
            else:
                _gh("repo", "fork", tgt["upstream"], "--clone=false", "--default-branch-only", timeout=300)
                for _ in range(24):                           # GitHub creates forks asynchronously (up to ~2 min)
                    found = _existing_fork(tgt["upstream"])
                    if found:
                        tgt["target"] = clone_from = found
                        break
                    time.sleep(5)
                else:
                    raise RuntimeError("the fork was requested but did not become available within 2 minutes")
    base = _gh("api", f"repos/{clone_from}", "--jq", ".default_branch")
    # Work in a throwaway clone of the scanned commit, never in the user's own checkout.
    pr_repo = rd / "pr-repo"
    shutil.rmtree(pr_repo, ignore_errors=True)
    git = ["git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=",
           "-c", "credential.helper=!gh auth git-credential"]
    env = safe_env(GIT_TERMINAL_PROMPT="0")

    def g(*a, cwd=pr_repo, timeout=600):
        p = subprocess.run([*git, *a], cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env, stdin=subprocess.DEVNULL)
        if p.returncode != 0:
            raise RuntimeError(f"git {a[0]}: {p.stderr.strip()[:300]}")
        return p.stdout.strip()
    g("clone", "--depth", "1", "--branch", base, f"https://github.com/{clone_from}.git", str(pr_repo), cwd=rd)
    g("checkout", "-b", branch)
    changed = []
    # package.json: apply the approved changes to the TARGET's current file (only those keys change, so
    # newer upstream edits elsewhere in the file are kept)
    changes = val.get("results", {}).get("changes") or []
    if not changes:
        raise ValueError("this validation has no recorded package changes; run the sandbox again")
    current = (pr_repo / "package.json").read_text(encoding="utf-8")
    updated, _ = apply_package_changes(current, changes)
    if updated == current:
        raise ValueError(f"{clone_from}@{base} already contains these changes")
    (pr_repo / "package.json").write_text(updated, encoding="utf-8")
    changed.append("package.json")
    # lockfile: only if the repository tracks it (Juice Shop .gitignores its lockfile)
    lock = rd / "work" / "package-lock.json"
    tracked = subprocess.run([*git, "ls-files", "--error-unmatch", "package-lock.json"], cwd=pr_repo, env=env,
                             capture_output=True).returncode == 0
    if lock.exists() and tracked:
        shutil.copy2(lock, pr_repo / "package-lock.json")
        changed.append("package-lock.json")
    if not changed:
        raise ValueError("no tracked dependency files to change")
    g("add", *changed)
    who = _gh("api", "user", "--jq", '[.login, (.id|tostring)] | join(" ")').split()
    g("-c", f"user.name={who[0]}", "-c", f"user.email={who[1]}+{who[0]}@users.noreply.github.com",
      "commit", "-m", f"[Guardian] supply-chain remediation (draft)\n\nApproved at Gate 1 by {val.get('approved_by')}, "
      f"Gate 2 by {g2.get('reviewer')}. Validation {val.get('id')}: {val.get('status')}.")
    if dry_run:
        preview = {"dry_run": True, "target": tgt["target"], "fork": tgt["fork"], "fork_exists": clone_from == tgt["target"],
                   "branch": branch, "base": base, "files": changed, "commit": g("log", "--oneline", "-1"),
                   "diff": g("show", "--stat", "--format=", "HEAD") + "\n\n" + g("show", "--format=", "HEAD", "--", "package.json")[:4000],
                   "would_run": [*([f"gh repo fork {tgt['upstream']} --clone=false"] if tgt["fork"] and clone_from != tgt["target"] else []),
                                 f"git push https://github.com/{tgt['target']}.git HEAD:refs/heads/{branch}",
                                 f"gh pr create --repo {tgt['target']} --draft --head {branch} --base {base}"]}
        _audit(scan_dir, f"human:{reviewer.strip()}", "pr.dry_run", "git.open_pr",
               {"target": tgt["target"], "branch": branch, "draft": True}, {"allow": True, "rule": "preview only"})
        shutil.rmtree(pr_repo, ignore_errors=True)
        return preview
    g("push", "origin", f"HEAD:refs/heads/{branch}", timeout=900)
    body = rd / "CHANGESET.md"
    if not body.exists():
        raise ValueError("no change set found — record Gate 2 approval first")
    url = _gh("pr", "create", "--repo", tgt["target"], "--draft", "--head", branch, "--base", base,
              "--title", "[Guardian] Supply-chain remediation (draft)", "--body-file", str(body), timeout=300)
    result = {"url": url, "target": tgt["target"], "fork": tgt["fork"], "branch": branch, "base": base,
              "files": changed, "opened_by": reviewer.strip(), "at": _now()}
    review["pr"] = result
    _write(rd / "review.json", review)
    _audit(scan_dir, f"human:{reviewer.strip()}", "pr.open_draft", "git.open_pr",
           {"target": tgt["target"], "branch": branch, "draft": True}, {"allow": True, "rule": "Gate 2 approved"}, result=url)
    shutil.rmtree(pr_repo, ignore_errors=True)
    return result
