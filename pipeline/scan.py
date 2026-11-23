"""End-to-end scan pipeline.

  GitHub URL / local path
    -> clone (read-only, no hooks)
    -> lockfile (npm --package-lock-only --ignore-scripts, only if the repo has none)
    -> CycloneDX SBOM (cdxgen, --no-install-deps)
    -> Grype (on the SBOM) + OSV-Scanner (on the repo), in parallel
    -> dependency graph (graph.json + interactive HTML)

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
REQUIRED = ("clone", "sbom", "grype", "osv", "graph")  # any failure here => scan not complete

STEPS = [
    ("clone", "Clone repository"),
    ("lockfile", "Resolve npm lockfile"),
    ("sbom", "Generate SBOM (cdxgen)"),
    ("grype", "Scan SBOM (Grype)"),
    ("osv", "Scan repository (OSV-Scanner)"),
    ("graph", "Build dependency graph"),
]


def safe_env(**extra: str) -> dict:
    """Minimal environment for tools that read untrusted input: no API keys or tokens."""
    path = os.pathsep.join([str(Path.home() / ".local/bin"), "/opt/homebrew/bin",
                            "/usr/local/bin", os.environ.get("PATH", "")])
    env = {"HOME": str(Path.home()), "PATH": path, "LANG": "en_US.UTF-8"}
    env.update(extra)
    return env


def run(cmd: list[str], *, cwd: Path | None = None, timeout: int = 600, env: dict | None = None,
        stdout: Path | None = None, stderr: Path | None = None) -> int:
    """Run a command (argument list, never a shell). Output goes to files, not logs."""
    with open(stdout or os.devnull, "wb") as out, open(stderr or os.devnull, "wb") as err:
        return subprocess.run(cmd, cwd=cwd, env=env or safe_env(), stdout=out, stderr=err,
                              timeout=timeout, stdin=subprocess.DEVNULL).returncode


def first_line(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=safe_env())
        return (r.stdout or r.stderr).strip().splitlines()[0]
    except Exception as e:  # tool missing or broken: record it, don't crash
        return f"unavailable ({type(e).__name__})"


def tool_versions() -> dict:
    v = {"git": first_line(["git", "--version"]), "npm": first_line(["npm", "--version"]),
         "cdxgen": first_line(["cdxgen", "--version"]),
         "osv-scanner": first_line(["osv-scanner", "--version"])}
    try:
        g = json.loads(subprocess.run(["grype", "version", "-o", "json"], capture_output=True,
                                      text=True, timeout=30, env=safe_env()).stdout)
        v["grype"] = g.get("version") or g.get("gitDescription")
        db = json.loads(subprocess.run(["grype", "db", "status", "-o", "json"], capture_output=True,
                                       text=True, timeout=30, env=safe_env()).stdout)
        v["grype_db"] = {"schema": db.get("schemaVersion"), "built": db.get("built"),
                         "valid": db.get("valid", db.get("status") == "valid")}
    except Exception as e:
        v["grype"] = f"unavailable ({type(e).__name__})"
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
        m = json.loads(f.read_text())
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
        tmp.write_text(json.dumps(meta, indent=2))
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
            rc = run(["git", "-c", "core.hooksPath=/dev/null", "clone", "--depth", "1", "--no-tags",
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
    n_comp = len(json.loads(bom.read_text()).get("components") or []) if bom.exists() else 0
    if rc != 0 or not bom.exists():
        return fail("sbom", f"cdxgen exited {rc}, no SBOM written", t0)
    if n_comp == 0 and not (repo / "package.json").exists():
        return fail("sbom", "SBOM has 0 components (no supported manifests/lockfiles found)", t0)
    meta["artifacts"]["sbom"] = str(bom)
    step("sbom", "ok" if n_comp else "warn",
         f"{n_comp} components" if n_comp else "0 components — falling back to package.json", t0)

    # 4. scanners in parallel (status updates stay on this thread for the UI) -----------
    grype_out, osv_out = res / "grype.json", res / "osv.json"

    def do_grype() -> tuple[str, str]:
        if not n_comp:
            return "skipped", "no SBOM components to scan"
        rc = run(["grype", f"sbom:{bom}", "-o", "json", "--file", str(grype_out)], timeout=900,
                 env=safe_env(GRYPE_DB_AUTO_UPDATE="false", GRYPE_CHECK_FOR_APP_UPDATE="false"),
                 stderr=res / "grype.stderr")
        if rc != 0 or not grype_out.exists():
            grype_out.unlink(missing_ok=True)
            return "failed", f"grype exited {rc} (see grype.stderr; DB may be missing or too old)"
        return "ok", f"{len(json.loads(grype_out.read_text()).get('matches', []))} matches"

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
        d = json.loads(osv_out.read_text())
        n = sum(len(p.get("vulnerabilities", [])) for r in d.get("results", []) for p in r.get("packages", []))
        return "ok", f"{n} vulnerabilities"

    for k in ("grype", "osv"):
        step(k, "running")
    with ThreadPoolExecutor(max_workers=2) as pool:
        t0 = time.monotonic()
        futures = {"grype": pool.submit(do_grype), "osv": pool.submit(do_osv)}
        for k, f in futures.items():
            try:
                status, detail = f.result()
            except subprocess.TimeoutExpired:
                status, detail = "failed", "timed out"
            except Exception as e:
                status, detail = "failed", f"{type(e).__name__}: {e}"
            step(k, status, detail, t0)
    for k, path in (("grype", grype_out), ("osv", osv_out)):
        if path.exists():
            meta["artifacts"][k] = str(path)

    # 5. graph -------------------------------------------------------------------------
    t0 = time.monotonic(); step("graph", "running")
    try:
        scan_info = {k: meta[k] for k in ("scan_id", "target", "commit", "started_at", "tools")}
        scan_info["scanner_status"] = {k: meta["steps"][k]["status"] for k in ("grype", "osv")}
        meta["stats"] = build(repo, bom, grype_out if grype_out.exists() else None,
                              osv_out if osv_out.exists() else None,
                              graphs / "dependency_graph.html", graphs / "graph.json",
                              target=meta["repo_name"], scan=scan_info)
        meta["artifacts"].update(graph_html=str(graphs / "dependency_graph.html"),
                                 graph_json=str(graphs / "graph.json"))
        step("graph", "ok", f"{meta['stats']['nodes']} nodes, {meta['stats']['findings']} findings", t0)
    except Exception as e:
        return fail("graph", f"{type(e).__name__}: {e}", t0)

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
