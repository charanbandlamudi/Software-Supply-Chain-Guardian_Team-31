"""Risk detection checks (offline): every detector fires on a seeded case and
install-time risks are prioritised regardless of import-based reachability."""
import json
from datetime import datetime, timedelta, timezone

from guardian_v2.agents import anomaly
from guardian_v2.scoring import score

GOOD = "sha512-GOOD"


def _state(tmp_path):
    base = {"packages": {"": {"dependencies": {"lodash": "4.17.15"}},
                         "node_modules/lodash": {"version": "4.17.15", "integrity": GOOD,
                                                 "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"}}}
    cur = json.loads(json.dumps(base))
    cur["packages"]["node_modules/lodash"].update(integrity="sha512-EVIL",
                                                  resolved="https://evil.example/lodash-4.17.15.tgz")
    cur["packages"]["node_modules/sneaky"] = {"version": "1.0.0"}
    (tmp_path / "base.json").write_text(json.dumps(base))
    (tmp_path / "cur.json").write_text(json.dumps(cur))
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash": "4.17.15"}}))
    recent = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    comps = {
        "pkg:npm/lodash@4.17.15": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm", "direct": True,
                                   "lock": {"resolved": "https://evil.example/lodash-4.17.15.tgz", "integrity": "sha512-EVIL"},
                                   "registry": {"exists": True, "version_published": True, "integrity": GOOD}},
        "pkg:npm/sneaky@1.0.0": {"name": "sneaky", "version": "1.0.0", "ecosystem": "npm", "direct": False,
                                 "registry": {"exists": True, "version_published": True, "uploaded": recent}},
        "pkg:npm/%40acme-internal/auth@1.0.0": {"name": "@acme-internal/auth", "version": "1.0.0", "ecosystem": "npm",
                                                "direct": True, "registry": {"exists": True, "version_published": True}},
        "pkg:npm/lodahs@1.0.0": {"name": "lodahs", "version": "1.0.0", "ecosystem": "npm", "direct": True,
                                 "lock": {"hasInstallScript": True},
                                 "registry": {"exists": True, "security_holding": True, "latest": "0.0.1-security"}},
    }
    return {"components": comps, "edges": [], "inputs": {
        "npm_lock_baseline": str(tmp_path / "base.json"), "npm_lock": str(tmp_path / "cur.json"),
        "npm_manifest": str(tmp_path / "package.json"), "internal_namespaces": ["@acme-internal/"]}}


def test_every_detector_fires(tmp_path):
    res = anomaly.run(_state(tmp_path), {})
    kinds = {(f["type"], f["component_purl"].split("/")[-1]) for f in res.delta["findings"].values()}
    expected = {("integrity_mismatch", "lodash@4.17.15"), ("untrusted_resolved_url", "lodash@4.17.15"),
                ("lockfile_tampering", "lodash@4.17.15"), ("unexpected_dependency", "sneaky@1.0.0"),
                ("suspicious_update", "sneaky@1.0.0"), ("dependency_confusion", "auth@1.0.0"),
                ("malicious_package", "lodahs@1.0.0"), ("typosquat_suspect", "lodahs@1.0.0"),
                ("install_script", "lodahs@1.0.0")}
    assert expected <= kinds, expected - kinds
    assert res.requests and res.requests[0]["to"] == "reachability"
    mal = next(f for f in res.delta["findings"].values() if f["type"] == "malicious_package")
    assert mal["corroborating_signals"] == 2 and set(mal["correlated_with"]) == {"typosquat_suspect", "install_script"}
    assert all(f["evidence_ids"] for f in res.delta["findings"].values())


def test_install_time_risk_not_discounted_by_reachability():
    comp = {"reachability": {"state": "not_imported"}, "direct": True, "scope": "prod"}
    mal = score({"type": "malicious_package", "calibrated_base": 9.5, "corroborating_signals": 2}, comp, {})
    vuln = score({"type": "vulnerability", "cvss": {"score": 7.5}}, comp, {})
    assert mal["score_breakdown"]["reachability"][1] == 1.0
    assert mal["ssvc"]["decision"] == "Act" and mal["confidence"] == "High"
    assert mal["score"] > 60 and mal["score"] > vuln["score"]
    assert vuln["score_breakdown"]["reachability"][1] == 0.3      # CVEs still use reachability


def test_pipeline_risk_scored_without_package_reachability():
    wf = score({"type": "dangerous_workflow", "calibrated_base": 8.0}, {}, {})
    assert wf["risk_class"] == "pipeline" and wf["ssvc"]["decision"] == "Attend"


def test_typosquat_does_not_flag_the_real_package():
    assert anomaly.typosquat_target("lodash", "npm") is None
    assert anomaly.typosquat_target("lodahs", "npm") == "lodash"
    assert anomaly.typosquat_target("reqeusts", "pypi") == "requests"
