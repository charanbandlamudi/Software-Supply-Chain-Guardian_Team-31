"""'What changed' detection: compare the scanned commit against (1) the repository's own git history
and (2) the previous scan of the same repository.

Git baseline: the clone carries the last commits (blobless), so we find the most recent commit that
touched a dependency manifest/lockfile/Dockerfile/workflow and diff it against its parent:
  - package.json dependencies added / removed / version-range changed
  - lockfile packages added / removed / version changed, SAME version with a DIFFERENT integrity hash
    (tampering signal) and resolved-URL host changes (untrusted source signal)
  - requirements*.txt and other manifests: line-level changes
Previous scan: components added / removed / version-changed and vulnerabilities new / resolved.
Only facts from git and the two scans are reported; nothing is inferred.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from pipeline.scan import SCANS_DIR, safe_env

DEP_FILES = ("package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
             "requirements.txt", "requirements-dev.txt", "poetry.lock", "Pipfile.lock", "pyproject.toml",
             "go.mod", "go.sum", "pom.xml", "build.gradle", "Gemfile.lock", "composer.json", "composer.lock",
             "Cargo.toml", "Cargo.lock", "Dockerfile")
GIT = ["git", "-c", "core.hooksPath=/dev/null"]


def _git(repo: Path, *args: str, timeout: int = 120) -> str:
    p = subprocess.run([*GIT, "-C", str(repo), *args], capture_output=True, text=True, timeout=timeout,
                       env=safe_env(GIT_TERMINAL_PROMPT="0"), stdin=subprocess.DEVNULL)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip()[:300] or f"git {' '.join(args)} failed")
    return p.stdout


def _show(repo: Path, rev: str, path: str) -> str | None:
    try:
        return _git(repo, "show", f"{rev}:{path}")
    except RuntimeError:
        return None                                    # file did not exist at that revision


def _npm_deps(text: str | None) -> dict[str, str]:
    if not text:
        return {}
    try:
        pkg = json.loads(text)
    except json.JSONDecodeError:
        return {}
    out = {}
    for sec in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for n, v in (pkg.get(sec) or {}).items():
            out[n] = f"{v}" + (" (dev)" if sec == "devDependencies" else "")
    return out


def _lock_entries(text: str | None) -> dict[tuple[str, str], dict]:
    if not text:
        return {}
    try:
        lock = json.loads(text)
    except json.JSONDecodeError:
        return {}
    out = {}
    for path, meta in (lock.get("packages") or {}).items():
        if path and meta.get("version"):
            out[(path.split("node_modules/")[-1], meta["version"])] = {
                "integrity": meta.get("integrity"), "resolved": meta.get("resolved")}
    return out


def _host(url: str | None) -> str | None:
    return url.split("/")[2] if url and "://" in url else None


def diff_npm_manifest(before: str | None, after: str | None) -> dict:
    b, a = _npm_deps(before), _npm_deps(after)
    return {"added": sorted(f"{n} {a[n]}" for n in set(a) - set(b)),
            "removed": sorted(f"{n} {b[n]}" for n in set(b) - set(a)),
            "changed": sorted(f"{n}: {b[n]} → {a[n]}" for n in set(a) & set(b) if a[n] != b[n])}


def diff_lockfile(before: str | None, after: str | None) -> dict:
    b, a = _lock_entries(before), _lock_entries(after)
    bn, an = {}, {}
    for (n, v) in b:
        bn.setdefault(n, set()).add(v)
    for (n, v) in a:
        an.setdefault(n, set()).add(v)
    return {
        "added": sorted(f"{n}@{v}" for n in set(an) - set(bn) for v in an[n]),
        "removed": sorted(f"{n}@{v}" for n in set(bn) - set(an) for v in bn[n]),
        "version_changed": sorted(f"{n}: {', '.join(sorted(bn[n]))} → {', '.join(sorted(an[n]))}"
                                  for n in set(an) & set(bn) if an[n] != bn[n]),
        # same name AND version but a different integrity hash: the tarball changed under the same version
        "integrity_changed": sorted(f"{n}@{v}" for (n, v) in set(a) & set(b)
                                    if a[(n, v)]["integrity"] and b[(n, v)]["integrity"]
                                    and a[(n, v)]["integrity"] != b[(n, v)]["integrity"]),
        "source_host_changed": sorted(f"{n}@{v}: {_host(b[(n, v)]['resolved'])} → {_host(a[(n, v)]['resolved'])}"
                                      for (n, v) in set(a) & set(b)
                                      if _host(a[(n, v)]["resolved"]) != _host(b[(n, v)]["resolved"])),
    }


def _line_diff(before: str | None, after: str | None) -> dict:
    bl = {l.strip() for l in (before or "").splitlines() if l.strip() and not l.strip().startswith("#")}
    al = {l.strip() for l in (after or "").splitlines() if l.strip() and not l.strip().startswith("#")}
    return {"added": sorted(al - bl)[:200], "removed": sorted(bl - al)[:200]}


def _diff_dep_files(repo: Path, base: str, head: str) -> tuple[list[str], dict]:
    files = [f for f in _git(repo, "diff", "--name-only", base, head).splitlines()
             if Path(f).name in DEP_FILES or f.startswith(".github/workflows/") or Path(f).name.startswith("Dockerfile")]
    details = {}
    for f in files:
        before, after = _show(repo, base, f), _show(repo, head, f)
        name = Path(f).name
        if name == "package.json":
            details[f] = {"kind": "npm manifest", **diff_npm_manifest(before, after)}
        elif name in ("package-lock.json", "npm-shrinkwrap.json"):
            details[f] = {"kind": "npm lockfile", **diff_lockfile(before, after)}
        else:
            details[f] = {"kind": "file", **_line_diff(before, after)}
    return files, details


def git_changes(repo: Path) -> dict:
    """Diff the most recent dependency-changing commit against its parent."""
    if not (repo / ".git").exists():
        return {"available": False, "reason": "not a git checkout"}
    depth = len(_git(repo, "rev-list", "HEAD").split())
    patterns = [f":(glob)**/{f}" for f in DEP_FILES] + [f":(glob){f}" for f in DEP_FILES] + [":(glob).github/workflows/*"]
    log = _git(repo, "log", "--format=%H%x1f%aI%x1f%an%x1f%s", "-n", "15", "--", *patterns).strip().splitlines()
    timeline = [dict(zip(("commit", "date", "author", "subject"), l.split("\x1f"))) for l in log if l]
    if not timeline:
        return {"available": True, "history_depth": depth, "timeline": [],
                "reason": f"no dependency, Dockerfile or workflow changes in the last {depth} commits"}
    latest = timeline[0]["commit"]
    try:
        parent = _git(repo, "rev-parse", f"{latest}^").strip()
    except RuntimeError:
        return {"available": True, "history_depth": depth, "timeline": timeline,
                "reason": "the dependency change is at the edge of the fetched history (no parent available)"}
    files, details = _diff_dep_files(repo, parent, latest)
    stat = _git(repo, "diff", "--numstat", parent, latest, "--", *files).strip().splitlines() if files else []
    # Cumulative view: everything that changed in dependency files across the fetched history window.
    oldest = _git(repo, "rev-list", "--max-parents=0", "HEAD").split()[-1] if depth else None
    window = None
    if oldest and depth > 1:
        wfiles, wdetails = _diff_dep_files(repo, oldest, "HEAD")
        window = {"from_commit": oldest, "to_commit": _git(repo, "rev-parse", "HEAD").strip(),
                  "commits": depth, "files": wfiles, "details": wdetails}
    return {"available": True, "history_depth": depth, "timeline": timeline, "window": window,
            "baseline": {"commit": parent, "compared_commit": latest, "date": timeline[0]["date"],
                         "author": timeline[0]["author"], "subject": timeline[0]["subject"],
                         "head_is_change": latest == _git(repo, "rev-parse", "HEAD").strip()},
            "files": files, "numstat": stat, "details": details}


def previous_scan(scan_dir: Path, repo_name: str) -> Path | None:
    cands = []
    for f in SCANS_DIR.glob("*/scan.json"):
        if f.parent == scan_dir:
            continue
        try:
            m = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if m.get("repo_name") == repo_name and (f.parent / "graphs" / "graph.json").exists() \
                and m.get("started_at", "") < json.loads((scan_dir / "scan.json").read_text(encoding="utf-8")).get("started_at", "~"):
            cands.append((m.get("started_at", ""), f.parent))
    return max(cands)[1] if cands else None


def scan_changes(scan_dir: Path, prev: Path) -> dict:
    cur = json.loads((scan_dir / "graphs" / "graph.json").read_text(encoding="utf-8"))
    old = json.loads((prev / "graphs" / "graph.json").read_text(encoding="utf-8"))
    pm = json.loads((prev / "scan.json").read_text(encoding="utf-8"))

    def comps(g):
        out = {}
        for n in g["nodes"]:
            if n.get("dep_type") != "root":
                out.setdefault(n["name"], set()).add(n["version"])
        return out

    def vulns(g):
        return {(f"{n['name']}@{n['version']}", v["id"]) for n in g["nodes"] for v in n.get("vulns", [])}
    c, o = comps(cur), comps(old)
    vc, vo = vulns(cur), vulns(old)
    return {"previous_scan": prev.name, "previous_commit": pm.get("commit"), "previous_started_at": pm.get("started_at"),
            "components_added": sorted(f"{n}@{v}" for n in set(c) - set(o) for v in c[n]),
            "components_removed": sorted(f"{n}@{v}" for n in set(o) - set(c) for v in o[n]),
            "versions_changed": sorted(f"{n}: {', '.join(sorted(o[n]))} → {', '.join(sorted(c[n]))}"
                                       for n in set(c) & set(o) if c[n] != o[n]),
            "vulnerabilities_new": sorted(f"{p} {i}" for p, i in vc - vo),
            "vulnerabilities_resolved": sorted(f"{p} {i}" for p, i in vo - vc)}


def detect_changes(scan_dir: Path, repo: Path, repo_name: str) -> dict:
    out_dir = scan_dir / "changes"
    out_dir.mkdir(exist_ok=True)
    result = {"git": None, "since_last_scan": None, "baseline_lockfile": None}
    try:
        result["git"] = git_changes(repo)
    except Exception as e:                                 # history is a bonus: never fail the scan on it
        result["git"] = {"available": False, "reason": f"{type(e).__name__}: {str(e)[:200]}"}
    prev = previous_scan(scan_dir, repo_name)
    if prev:
        result["since_last_scan"] = scan_changes(scan_dir, prev)
    # Baseline lockfile for the anomaly agent: the lockfile before the last dependency commit, else the
    # lockfile the previous scan of this repo used.
    g = result["git"] or {}
    base_lock = None
    if g.get("baseline") and (repo / "package-lock.json").exists():
        base_lock = _show(repo, g["baseline"]["commit"], "package-lock.json")
        src = f"git {g['baseline']['commit'][:12]}"
    if not base_lock and prev and (prev / "repo" / "package-lock.json").exists():
        base_lock = (prev / "repo" / "package-lock.json").read_text(encoding="utf-8")
        src = f"previous scan {prev.name}"
    if base_lock:
        (out_dir / "baseline-package-lock.json").write_text(base_lock, encoding="utf-8")
        result["baseline_lockfile"] = {"path": str(out_dir / "baseline-package-lock.json"), "source": src}
    (out_dir / "changes.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def summarize(c: dict) -> str:
    parts = []
    g = c.get("git") or {}
    if g.get("baseline"):
        n = sum(len(v.get("added", [])) + len(v.get("removed", [])) + len(v.get("changed", v.get("version_changed", [])))
                for v in g.get("details", {}).values())
        parts.append(f"last dependency commit {g['baseline']['compared_commit'][:8]} changed {len(g.get('files', []))} file(s), {n} entries")
    elif g.get("reason"):
        parts.append(f"git: {g['reason']}")
    s = c.get("since_last_scan")
    if s:
        parts.append(f"since last scan: +{len(s['components_added'])}/-{len(s['components_removed'])} components, "
                     f"{len(s['versions_changed'])} version changes, {len(s['vulnerabilities_new'])} new / "
                     f"{len(s['vulnerabilities_resolved'])} resolved vulns")
    else:
        parts.append("no previous scan of this repo")
    if c.get("baseline_lockfile"):
        parts.append(f"baseline lockfile from {c['baseline_lockfile']['source']}")
    return "; ".join(parts)
