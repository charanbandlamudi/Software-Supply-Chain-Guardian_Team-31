"""End-to-end scan pipeline.

  GitHub URL / local path
    -> clone (read-only, no hooks)
    -> lockfile (npm --package-lock-only --ignore-scripts, only if the repo has none)
    -> CycloneDX SBOM (cdxgen, --no-install-deps)
    -> Grype (on the SBOM) + OSV-Scanner + Trivy (on the repo), in parallel
    -> dependency graph (graph.json + interactive HTML)
    -> multi-agent investigation (guardian_v2, unattended analysis stage)

Every scan gets its own folder under data/scans/ with a scan.json that records
tool versions, the Grype DB build date, per-step status and timings. The target
repository is treated as untrusted: nothing from it is executed, tools run with
argument lists (no shell) under timeouts and a minimal environment (no secrets).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from graph.build_graph import build

ROOT = Path(__file__).resolve().parent.parent
SCANS_DIR = ROOT / "data" / "scans"
GITHUB_RE = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")
REQUIRED = ("clone", "sbom", "grype", "osv", "trivy", "graph", "agents", "report")  # any failure here => scan not complete

STEPS = [
    ("clone", "Clone repository"),
    ("lockfile", "Resolve npm lockfile"),
    ("sbom", "Generate SBOM (cdxgen)"),
    ("grype", "Scan SBOM (Grype)"),
    ("osv", "Scan repository (OSV-Scanner)"),
    ("trivy", "Scan repository (Trivy)"),
    ("graph", "Build dependency graph"),
    ("agents", "Agent investigation (guardian_v2)"),
    ("report", "Final Guardian Report (JSON / HTML / PDF)"),
]


def safe_env(**extra: str) -> dict:
    """Minimal environment for tools that read untrusted input: no API keys or tokens."""
    extra_paths = [
        str(Path.home() / ".local/bin"), "/opt/homebrew/bin", "/usr/local/bin",
        str(Path(os.environ.get("APPDATA", "")) / "npm"),
        str(Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Packages" / "Anchore.Grype_Microsoft.Winget.Source_8wekyb3d8bbwe"),
        str(Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Packages" / "Google.OSVScanner_Microsoft.Winget.Source_8wekyb3d8bbwe"),
        str(Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Packages" / "AquaSecurity.Trivy_Microsoft.Winget.Source_8wekyb3d8bbwe"),
        str(Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Links"),
    ]
    path = os.pathsep.join(extra_paths + [os.environ.get("PATH", "")])
    env = {"HOME": str(Path.home()), "PATH": path, "LANG": "en_US.UTF-8"}
    for k in ("SYSTEMROOT", "SYSTEMDRIVE", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "TEMP", "TMP", "PATHEXT", "COMSPEC"):
        if k in os.environ:
            env[k] = os.environ[k]
    env.update(extra)
    return env


def resolve_cmd(cmd: list[str], env: dict) -> list[str]:
    if not cmd:
        return cmd
    prog = cmd[0]
    resolved = shutil.which(prog, path=env.get("PATH"))
    if resolved:
        return [resolved] + cmd[1:]
    return cmd


def run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 600, env: dict | None = None,
        stdout: Path | None = None, stderr: Path | None = None) -> int:
    """Run a command (argument list, never a shell). Output goes to files, not logs."""
    actual_env = env or safe_env()
    actual_cmd = resolve_cmd(cmd, actual_env)
    with open(stdout or os.devnull, "wb") as out, open(stderr or os.devnull, "wb") as err:
        return subprocess.run(actual_cmd, cwd=cwd, env=actual_env, stdout=out, stderr=err,
                              timeout=timeout, stdin=subprocess.DEVNULL).returncode


def first_line(cmd: list[str]) -> str:
    try:
        actual_env = safe_env()
        actual_cmd = resolve_cmd(cmd, actual_env)      # Windows: resolve .cmd/.exe via PATH
        r = subprocess.run(actual_cmd, capture_output=True, text=True, timeout=30, env=actual_env)
        line = (r.stdout or r.stderr).strip().splitlines()[0]
        return re.sub(r"\x1b\[[0-9;]*m", "", line)      # cdxgen colours its version string
    except Exception as e:  # tool missing or broken: record it, don't crash
        return f"unavailable ({type(e).__name__})"


def tool_versions() -> dict:
    v = {"git": first_line(["git", "--version"]), "npm": first_line(["npm", "--version"]),
         "cdxgen": first_line(["cdxgen", "--version"]),
         "osv-scanner": first_line(["osv-scanner", "--version"])}
    actual_env = safe_env()
    try:
        grype_bin = resolve_cmd(["grype"], actual_env)[0]
        g = json.loads(subprocess.run([grype_bin, "version", "-o", "json"], capture_output=True,
                                      text=True, timeout=30, env=actual_env).stdout)
        v["grype"] = g.get("version") or g.get("gitDescription")
        db = json.loads(subprocess.run([grype_bin, "db", "status", "-o", "json"], capture_output=True,
                                       text=True, timeout=30, env=actual_env).stdout)
        v["grype_db"] = {"schema": db.get("schemaVersion"), "built": db.get("built"),
                         "valid": db.get("valid", db.get("status") == "valid")}
    except Exception as e:
        v["grype"] = f"unavailable ({type(e).__name__})"
    try:
        trivy_bin = resolve_cmd(["trivy"], actual_env)[0]
        t = json.loads(subprocess.run([trivy_bin, "version", "--format", "json"], capture_output=True,
                                      text=True, timeout=30, env=actual_env).stdout)
        v["trivy"] = t.get("Version")
        db = t.get("VulnerabilityDB") or {}
        v["trivy_db"] = {"version": db.get("Version"), "updated": db.get("UpdatedAt"),
                         "downloaded": db.get("DownloadedAt")} if db else "not downloaded"
    except Exception as e:
        v["trivy"] = f"unavailable ({type(e).__name__})"
    return v


def parse_target(target: str) -> tuple[str, str, str]:
    """Return (kind, owner, name). Only https GitHub URLs or existing local dirs are accepted."""
    target = target.strip()
    m = GITHUB_RE.match(target)
    if m:
        return "github", m.group(1), m.group(2)
    p = Path(target).expanduser()
    if p.is_dir():
        return "local", "local", p.resolve().name
    raise ValueError("Enter an https://github.com/<owner>/<repo> URL or an existing local folder.")


# Scans run in background threads so they survive browser refreshes / closed tabs.
# Kept on `sys` so the registry survives Streamlit re-importing this module after edits.
import sys as _sys
_ACTIVE: dict[str, threading.Thread] = _sys.__dict__.setdefault("_ssg_active_scans", {})


def is_active(scan_id: str) -> bool:
    t = _ACTIVE.get(scan_id)
    return bool(t and t.is_alive())


def start_scan(target: str) -> str:
    """Start a scan in a background thread and return its scan_id once it has a folder."""
    parse_target(target)  # validate before spawning anything
    ready, holder = threading.Event(), {}

    def on_update(m: dict) -> None:
        holder.setdefault("id", m["scan_id"])
        ready.set()

    def work() -> None:
        try:
            run_scan(target, on_update=on_update)
        except Exception as e:  # recorded in scan.json where possible; never crash the server
            holder.setdefault("error", f"{type(e).__name__}: {e}")
        finally:
            ready.set()

    t = threading.Thread(target=work, name="ssg-scan", daemon=True)
    t.start()
    ready.wait(120)
    if "id" not in holder:
        raise RuntimeError(holder.get("error", "scan did not start"))
    _ACTIVE[holder["id"]] = t
    return holder["id"]


def load_scan(scan_id: str) -> dict | None:
    f = SCANS_DIR / scan_id / "scan.json"
    if not f.exists():
        return None
    try:
        m = json.loads(f.read_text(encoding="utf-8"))
    except json.JSONDecodeError:  # being written right now
        return None
    if m.get("status") == "running" and not is_active(scan_id):
        m["status"] = "interrupted"  # server restarted / process died mid-scan
    return m


def list_scans() -> list[dict]:
    out = [load_scan(f.parent.name) for f in sorted(SCANS_DIR.glob("*/scan.json"), reverse=True)]
    return [m for m in out if m]


def run_scan(target: str, on_update: Callable[[dict], None] = lambda m: None) -> dict:
    kind, owner, name = parse_target(target)
    started = datetime.now(timezone.utc)
    scan_dir = SCANS_DIR / f"{owner}__{name}__{started:%Y%m%d-%H%M%S}"
    repo, sbom, res, graphs = (scan_dir / d for d in ("repo", "sbom", "scanner_results", "graphs"))
    for d in (sbom, res, graphs):
        d.mkdir(parents=True, exist_ok=True)

    meta = {"scan_id": scan_dir.name, "scan_dir": str(scan_dir), "target": target.strip(),
            "kind": kind, "repo_name": f"{owner}/{name}" if kind == "github" else name,
            "started_at": started.isoformat(timespec="seconds"), "finished_at": None,
            "status": "running", "commit": None, "tools": tool_versions(),
            "steps": {k: {"label": lbl, "status": "pending", "detail": "", "seconds": None}
                      for k, lbl in STEPS},
            "artifacts": {}, "stats": None}

    def save() -> None:
        tmp = scan_dir / "scan.json.tmp"  # atomic write: readers never see half a file
        tmp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        tmp.replace(scan_dir / "scan.json")
        on_update(meta)

    def step(key: str, status: str, detail: str = "", t0: float | None = None) -> None:
        s = meta["steps"][key]
        s.update(status=status, detail=detail)
        if t0 is not None:
            s["seconds"] = round(time.monotonic() - t0, 1)
        save()

    def fail(key: str, detail: str, t0: float) -> dict:
        step(key, "failed", detail, t0)
        for k, s in meta["steps"].items():
            if s["status"] == "pending":
                s.update(status="skipped", detail=f"not run because '{key}' failed")
        meta.update(status="failed", finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
        save()
        return meta

    save()

    # 1. clone -------------------------------------------------------------------------
    t0 = time.monotonic(); step("clone", "running")
    try:
        if kind == "github":
            rc = run(["git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=", "-c", "core.longpaths=true", "clone", "--depth", "1", "--no-tags",
                      f"https://github.com/{owner}/{name}.git", str(repo)],
                     timeout=600, env=safe_env(GIT_TERMINAL_PROMPT="0"), stderr=res / "git.stderr")
            if rc != 0:
                return fail("clone", f"git clone exited {rc} (repo missing, private or network error)", t0)
        else:  # copy so lockfile generation never writes into the user's own checkout
            shutil.copytree(Path(target).expanduser(), repo,
                            ignore=shutil.ignore_patterns(".git", "node_modules"))
        meta["commit"] = first_line(["git", "-C", str(repo), "rev-parse", "HEAD"]) if (repo / ".git").exists() else None
        step("clone", "ok", f"commit {meta['commit'][:12]}" if meta["commit"] else "copied local folder", t0)
    except subprocess.TimeoutExpired:
        return fail("clone", "timed out after 600s", t0)

    # 2. lockfile ----------------------------------------------------------------------
    t0 = time.monotonic()
    if not (repo / "package.json").exists():
        step("lockfile", "skipped", "not an npm project at the repo root", t0)
    elif any((repo / f).exists() for f in LOCKFILES):
        step("lockfile", "skipped", "repository already commits a lockfile", t0)
    else:
        step("lockfile", "running")
        try:
            rc = run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit",
                      "--no-fund", "--legacy-peer-deps", "--fetch-timeout=30000", "--fetch-retries=5"],
                     cwd=repo, timeout=900, stderr=res / "npm.stderr")
            if rc == 0 and (repo / "package-lock.json").exists():
                step("lockfile", "ok", "generated — versions resolved today, not committed by the repo", t0)
            else:
                step("lockfile", "warn", f"npm exited {rc}; SBOM may only contain direct dependencies", t0)
        except subprocess.TimeoutExpired:
            step("lockfile", "warn", "timed out; SBOM may only contain direct dependencies", t0)

    # 3. SBOM --------------------------------------------------------------------------
    t0 = time.monotonic(); step("sbom", "running")
    bom = sbom / "bom.json"
    try:
        rc = run(["cdxgen", "-r", "--no-install-deps", "--project-name", name, "-o", str(bom), str(repo)],
                 timeout=900, env=safe_env(FETCH_LICENSE="false"), stdout=res / "cdxgen.stdout",
                 stderr=res / "cdxgen.stderr")
    except subprocess.TimeoutExpired:
        return fail("sbom", "cdxgen timed out after 900s", t0)
    n_comp = len(json.loads(bom.read_text(encoding="utf-8")).get("components") or []) if bom.exists() else 0
    if rc != 0 or not bom.exists():
        return fail("sbom", f"cdxgen exited {rc}, no SBOM written", t0)
    if n_comp == 0 and not (repo / "package.json").exists():
        return fail("sbom", "SBOM has 0 components (no supported manifests/lockfiles found)", t0)
    meta["artifacts"]["sbom"] = str(bom)
    step("sbom", "ok" if n_comp else "warn",
         f"{n_comp} components" if n_comp else "0 components — falling back to package.json", t0)

    # 4. scanners in parallel (status updates stay on this thread for the UI) -----------
    grype_out, osv_out, trivy_out = res / "grype.json", res / "osv.json", res / "trivy.json"

    def do_grype() -> tuple[str, str]:
        if not n_comp:
            return "skipped", "no SBOM components to scan"
        rc = run(["grype", f"sbom:{bom}", "-o", "json", "--file", str(grype_out)], timeout=900,
                 env=safe_env(GRYPE_DB_AUTO_UPDATE="false", GRYPE_CHECK_FOR_APP_UPDATE="false"),
                 stderr=res / "grype.stderr")
        if rc != 0 or not grype_out.exists():
            grype_out.unlink(missing_ok=True)
            return "failed", f"grype exited {rc} (see grype.stderr; DB may be missing or too old)"
        return "ok", f"{len(json.loads(grype_out.read_text(encoding='utf-8')).get('matches', []))} matches"

    def do_osv() -> tuple[str, str]:
        # --no-ignore: repos often .gitignore their lockfile (Juice Shop does), which would
        # otherwise hide the lockfile we just generated from OSV-Scanner.
        rc = run(["osv-scanner", "scan", "-r", "--no-ignore", str(repo), "--format", "json"], timeout=600,
                 stdout=osv_out, stderr=res / "osv.stderr")
        # 0 = no vulns, 1 = vulns found, 128 = no packages found; anything else is an error
        if rc == 128:
            osv_out.unlink(missing_ok=True)
            return "warn", "no lockfiles/packages found to scan"
        if rc not in (0, 1):
            osv_out.unlink(missing_ok=True)
            return "failed", f"osv-scanner exited {rc} (see osv.stderr)"
        d = json.loads(osv_out.read_text(encoding="utf-8"))
        n = sum(len(p.get("vulnerabilities", [])) for r in d.get("results", []) for p in r.get("packages", []))
        return "ok", f"{n} vulnerabilities"

    def do_trivy() -> tuple[str, str]:
        # vuln + misconfig + secret scanning of the checkout. DB/check updates are skipped so a
        # slow download can never stall a scan (refresh with `trivy fs --download-db-only`).
        rc = run(["trivy", "fs", "--scanners", "vuln,misconfig,secret", "--include-dev-deps",
                  "--skip-db-update", "--skip-check-update", "--no-progress", "--timeout", "15m",
                  "--format", "json", "--output", str(trivy_out), str(repo)],
                 timeout=1200, stderr=res / "trivy.stderr")
        if rc != 0 or not trivy_out.exists():
            trivy_out.unlink(missing_ok=True)
            return "failed", f"trivy exited {rc} (see trivy.stderr; DB may not be downloaded)"
        results = json.loads(trivy_out.read_text(encoding="utf-8")).get("Results") or []
        nv = sum(len(r.get("Vulnerabilities") or []) for r in results)
        nm = sum(1 for r in results for m in (r.get("Misconfigurations") or []) if m.get("Status", "FAIL") == "FAIL")
        ns = sum(len(r.get("Secrets") or []) for r in results)
        return "ok", f"{nv} vulnerabilities, {nm} misconfigurations, {ns} secrets"

    for k in ("grype", "osv", "trivy"):
        step(k, "running")
    with ThreadPoolExecutor(max_workers=3) as pool:
        t0 = time.monotonic()
        futures = {"grype": pool.submit(do_grype), "osv": pool.submit(do_osv),
                   "trivy": pool.submit(do_trivy)}
        for k, f in futures.items():
            try:
                status, detail = f.result()
            except subprocess.TimeoutExpired:
                status, detail = "failed", "timed out"
            except Exception as e:
                status, detail = "failed", f"{type(e).__name__}: {e}"
            step(k, status, detail, t0)
    for k, path in (("grype", grype_out), ("osv", osv_out), ("trivy", trivy_out)):
        if path.exists():
            meta["artifacts"][k] = str(path)

    # 5. graph -------------------------------------------------------------------------
    t0 = time.monotonic(); step("graph", "running")
    try:
        scan_info = {k: meta[k] for k in ("scan_id", "target", "commit", "started_at", "tools")}
        scan_info["scanner_status"] = {k: meta["steps"][k]["status"] for k in ("grype", "osv", "trivy")}
        meta["stats"] = build(repo, bom, grype_out if grype_out.exists() else None,
                              osv_out if osv_out.exists() else None,
                              graphs / "dependency_graph.html", graphs / "graph.json",
                              target=meta["repo_name"], scan=scan_info,
                              trivy=trivy_out if trivy_out.exists() else None)
        meta["artifacts"].update(graph_html=str(graphs / "dependency_graph.html"),
                                 graph_json=str(graphs / "graph.json"))
        step("graph", "ok", f"{meta['stats']['nodes']} nodes, {meta['stats']['findings']} findings", t0)
    except Exception as e:
        return fail("graph", f"{type(e).__name__}: {e}", t0)

    # 6. multi-agent investigation (guardian_v2 supervisor + specialist agents) ----------
    t0 = time.monotonic(); step("agents", "running", "starting supervisor")
    try:
        from pipeline.agents import run_agents

        def on_message(m: dict) -> None:
            to = ",".join(m["to"]) if isinstance(m.get("to"), list) else m.get("to")
            meta["steps"]["agents"]["detail"] = f"turn {m.get('turn')}: {m.get('from')} → {to}"
            save()

        ag = run_agents(scan_dir, repo, on_message=on_message)
        meta["agents"] = ag
        meta["artifacts"]["agents_dir"] = str(scan_dir / "agents")
        failed_cov = [k for k, v in ag["coverage"].items() if str(v).startswith("failed")]
        # Re-render the graph with the agents' assessment attached to each package node.
        build(repo, bom, grype_out if grype_out.exists() else None, osv_out if osv_out.exists() else None,
              graphs / "dependency_graph.html", graphs / "graph.json", target=meta["repo_name"], scan=scan_info,
              trivy=trivy_out if trivy_out.exists() else None, agent_report=scan_dir / "agents" / "guardian-report.json")
        step("agents", "warn" if failed_cov else "ok",
             f"{ag['turns']} turns, {ag['findings']} findings, {ag['handoffs']} handoffs, "
             f"LLM: {', '.join(ag['llm']) if ag['llm'] else 'none (templates)'}"
             + (f"; failed: {', '.join(failed_cov)}" if failed_cov else ""), t0)
    except Exception as e:
        step("agents", "failed", f"{type(e).__name__}: {str(e)[:300]}", t0)

    # 7. Final Guardian Report (validated findings -> JSON, HTML, PDF) --------------------
    t0 = time.monotonic(); step("report", "running")
    try:
        from reporting.guardian_report import write_reports
        rp = write_reports(scan_dir)
        meta["report"] = rp
        for ext in ("json", "html", "pdf"):
            f = Path(rp["dir"]) / f"guardian-report.{ext}"
            if f.exists():
                meta["artifacts"][f"report_{ext}"] = str(f)
        step("report", "ok" if rp["pdf"] == "ok" else "warn",
             f"{rp['findings']} validated findings in {len(rp['by_category'])} categories, "
             f"{rp['rejected']} rejected; PDF: {rp['pdf']}", t0)
    except Exception as e:
        step("report", "failed", f"{type(e).__name__}: {str(e)[:300]}", t0)

    # A scan is only "complete" if every required step succeeded.
    ok = all(meta["steps"][k]["status"] == "ok" for k in REQUIRED)
    meta.update(status="complete" if ok else "incomplete",
                finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    save()
    return meta


if __name__ == "__main__":
    import sys
    m = run_scan(sys.argv[1] if len(sys.argv) > 1 else "https://github.com/juice-shop/juice-shop",
                 on_update=lambda m: None)
    print(json.dumps({k: m[k] for k in ("scan_id", "status", "stats")}, indent=2))
    for k, s in m["steps"].items():
        print(f"  {s['status']:8} {s['label']:32} {s['detail']}")
