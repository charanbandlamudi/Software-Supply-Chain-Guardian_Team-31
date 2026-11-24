"""Unit tests for the pipeline's pure logic (no network, no Docker).

Run:  .venv/bin/python -m pytest -q tests
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pipeline.changes import diff_lockfile, diff_npm_manifest  # noqa: E402
from pipeline.remediation import _parse_tests, apply_package_changes, git_patch, sbom_diff  # noqa: E402


def lock(entries):
    return json.dumps({"packages": {"": {}, **{f"node_modules/{n}": {"version": v, "integrity": i, "resolved": r}
                                               for n, v, i, r in entries}}})


def test_lockfile_diff_flags_integrity_change_for_same_version():
    before = lock([("a", "1.0.0", "sha512-AAA", "https://registry.npmjs.org/a/-/a-1.0.0.tgz"),
                   ("b", "2.0.0", "sha512-BBB", "https://registry.npmjs.org/b/-/b-2.0.0.tgz")])
    after = lock([("a", "1.0.0", "sha512-EVIL", "https://registry.npmjs.org/a/-/a-1.0.0.tgz"),   # same version, new hash
                  ("b", "2.1.0", "sha512-CCC", "https://registry.npmjs.org/b/-/b-2.1.0.tgz"),
                  ("c", "0.1.0", "sha512-DDD", "https://evil.example/c-0.1.0.tgz")])
    d = diff_lockfile(before, after)
    assert d["integrity_changed"] == ["a@1.0.0"]
    assert d["added"] == ["c@0.1.0"]
    assert d["version_changed"] == ["b: 2.0.0 → 2.1.0"]


def test_lockfile_diff_flags_download_source_change():
    before = lock([("a", "1.0.0", "x", "https://registry.npmjs.org/a/-/a-1.0.0.tgz")])
    after = lock([("a", "1.0.0", "x", "https://mirror.example/a-1.0.0.tgz")])
    assert diff_lockfile(before, after)["source_host_changed"] == ["a@1.0.0: registry.npmjs.org → mirror.example"]


def test_manifest_diff():
    b = json.dumps({"dependencies": {"x": "^1.0.0", "gone": "1"}, "devDependencies": {"t": "2"}})
    a = json.dumps({"dependencies": {"x": "^2.0.0", "new": "3"}, "devDependencies": {"t": "2"}})
    d = diff_npm_manifest(b, a)
    assert d == {"added": ["new 3"], "removed": ["gone 1"], "changed": ["x: ^1.0.0 → ^2.0.0"]}


def test_apply_package_changes_only_touches_approved_keys():
    text = '{\n    "name": "app",\n    "dependencies": {\n        "jsonwebtoken": "0.4.0",\n        "express": "4"\n    }\n}\n'
    new, applied = apply_package_changes(text, [
        {"name": "jsonwebtoken", "version": "0.4.0", "action": "upgrade", "target": "9.0.0"},   # direct
        {"name": "lodash", "version": "2.4.2", "action": "upgrade", "target": "4.18.1"}])       # transitive
    pkg = json.loads(new)
    assert pkg["dependencies"] == {"jsonwebtoken": "9.0.0", "express": "4"}
    assert pkg["overrides"] == {"lodash": "4.18.1"}
    assert new.startswith('{\n    "name"') and new.endswith("}\n")          # 4-space indent + newline kept
    assert len(applied) == 2


def test_override_for_direct_dependency_uses_reference():
    text = json.dumps({"dependencies": {"a": "^1"}, "overrides": {"a": "2.0.0"}}, indent=2)
    pkg = json.loads(apply_package_changes(text, [])[0])
    assert pkg["overrides"]["a"] == "$a"      # npm rejects mismatched override specs for direct deps


def test_git_patch_is_valid(tmp_path):
    before = json.dumps({"name": "x", "dependencies": {"a": "1"}}, indent=2) + "\n"
    after = json.dumps({"name": "x", "dependencies": {"a": "2"}}, indent=2) + "\n"
    (tmp_path / "package.json").write_text(before)
    (tmp_path / "fix.patch").write_text(git_patch(before, after, "package.json"))
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    assert subprocess.run(["git", "apply", "fix.patch"], cwd=tmp_path).returncode == 0
    assert json.loads((tmp_path / "package.json").read_text())["dependencies"]["a"] == "2"


def test_sbom_diff_is_exact_per_version():
    d = sbom_diff({"lodash@2.4.2", "lodash@4.18.1", "moment@2.0.0"}, {"lodash@4.18.1", "moment@2.31.0"})
    assert d["removed"] == ["lodash@2.4.2", "moment@2.0.0"]
    assert d["added"] == ["moment@2.31.0"]
    assert d["changed"] == ["lodash: 2.4.2, 4.18.1 → 4.18.1", "moment: 2.0.0 → 2.31.0"]


def test_parse_node_test_summary():
    log = "ok 1\n# tests 432\n# suites 136\n# pass 430\n# fail 0\n# skipped 2\n"
    assert _parse_tests(log) == {"passed": 430, "failed": 0, "total": 432}
    assert _parse_tests("  12 passing\n  3 failing\n")["failed"] == 3
