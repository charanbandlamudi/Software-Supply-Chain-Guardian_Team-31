import json
import subprocess
from pathlib import Path

from guardian_v2.audit import EvidenceCAS, append_entry, verify_chain
from guardian_v2.baseline import compare
from guardian_v2.build_gate import evaluate as evaluate_build_gate
from guardian_v2.checkpoints import SQLiteCheckpointStore
from guardian_v2.detonation import detonate, runtime_status
from guardian_v2.reachability_advisory import advisory_state
from guardian_v2.signing import make_in_toto_statement, sign_statement
from guardian_v2.calibration import reliability_table
from guardian_v2.release_anomalies import analyze_release_history
from guardian_v2.redaction import pointer, redact
from guardian_v2.dedup import merge_advisories
from guardian_v2.safe_version import plan_for_component
from pipeline.remediation import load_plans
import sys


def test_detonation_fails_closed_when_runsc_is_missing(tmp_path):
    status = runtime_status()
    result = detonate(tmp_path, "node:22-slim", ["node", "-e", "console.log('x')"])
    if not status["available"]:
        assert result["status"] == "unavailable"
        assert "gVisor/runsc" in result["reason"]


def test_evidence_cas_and_audit_args_hash(tmp_path):
    cas = EvidenceCAS(tmp_path / "cas")
    blob = cas.put("evidence")
    assert cas.get(blob["sha256"]) == b"evidence"
    entries = []
    append_entry(entries, "agent:test", "test.run", "test.tool",
                 {"secret": "redacted", "arg": "value"}, {"allow": True},
                 tool_version="1.0", args_hash=None)
    assert entries[0]["args_hash"]
    assert verify_chain(entries)[0]


def test_sqlite_checkpoint_round_trip_and_interrupt(tmp_path):
    store = SQLiteCheckpointStore(tmp_path / "checkpoints.sqlite")
    store.save("run-1", {"turn": 1, "findings": {}})
    store.save_interrupt("run-1", {"question": "Approve?", "gate": 1})
    loaded = store.load("run-1")
    assert loaded["interrupted"] is True
    assert loaded["state"]["gate"] == 1
    assert len(store.interrupts("run-1")) == 1
    assert store.verify("run-1")[0]


def test_in_toto_statement_and_unsigned_result(tmp_path):
    statement = make_in_toto_statement(
        [{"name": "report.json", "digest": {"sha256": "a" * 64}}],
        {"run_id": "run-1", "audit_head_hash": "b" * 64},
    )
    path = tmp_path / "statement.json"
    path.write_text(json.dumps(statement), encoding="utf-8")
    signed = sign_statement(path, tmp_path / "statement.sig")
    assert signed["status"] in {"signed", "unavailable", "failed"}
    assert sign_statement(path)["status"] != "signed" or sign_statement(path)["rekor_upload"] is False


def test_baseline_comparison_separates_regression_and_resolution():
    before = {"status": "passed"}
    after = {"status": "failed"}
    result = compare(before, after)
    assert result["introduced_regression"] is True
    assert result["resolved_preexisting"] is False


def test_build_gate_rejects_act_pins_and_publish():
    result = evaluate_build_gate({
        "findings": [{"canonical_id": "CVE-1", "ssvc": {"decision": "Act"}, "resolution": "open"}],
        "unpinned_actions": 1,
        "cicd_findings": ["uses: owner/action@main"],
        "container_images": ["nginx:latest"],
        "requested_actions": ["npm.publish"],
        "license_violations": ["GPL-3.0"],
    })
    assert result["allow"] is False
    reasons = " ".join(result["deny_reason"])
    assert "ACT" in reasons
    assert "unpinned" in reasons
    assert "publish" in reasons


def test_advisory_reachability_reachable_unknown_not_reachable(tmp_path):
    py = tmp_path / "app.py"
    py.write_text("import requests\nrequests.get('https://example.test')\n", encoding="utf-8")
    assert advisory_state([str(tmp_path)], ["requests"])[ "state"] == "reachable"
    assert advisory_state([str(tmp_path)], ["missingpkg"])["state"] == "not_reachable"
    py.write_text("payload = eval(user_input)\n", encoding="utf-8")
    assert advisory_state([str(tmp_path)], ["payload"])["state"] == "unknown"


def test_calibration_metrics():
    labels = [
        {"actual": True, "predicted": True},
        {"actual": False, "predicted": True},
        {"actual": True, "predicted": False},
        {"actual": False, "predicted": False},
    ]
    result = reliability_table(labels)
    assert result["precision"] == 0.5
    assert result["recall"] == 0.5
    assert result["accuracy"] == 0.5
    assert result["fp"] == 1 and result["fn"] == 1


def test_secret_redaction_and_hash_pointer():
    redacted = redact("token ghp_abcdefghijklmnopqrstuvwxyz123456")
    assert "ghp_" not in redacted
    assert "[REDACTED]" in redacted
    evidence = pointer("super-secret")
    assert evidence["redacted"] is True
    assert len(evidence["sha256"]) == 64


def test_release_anomalies_detect_owner_and_cadence():
    history = [
        {"version": "1.0", "maintainers": ["alice"], "published": "2026-01-01T02:00:00Z"},
        {"version": "1.1", "maintainers": ["bob"], "published": "2026-01-01T03:00:00Z"},
        {"version": "1.2", "maintainers": ["bob"], "published": "2026-01-01T23:00:00Z"},
    ]
    result = analyze_release_history(history)
    kinds = {finding["type"] for finding in result["findings"]}
    assert "maintainer_change" in kinds
    assert "release_cadence_burst" in kinds
    assert "publish_hour_anomaly" in kinds


def test_seed_mirror_prepares_npm_and_python_fixtures(tmp_path):
    sys.path.insert(0, str(Path(__file__).parents[1] / "tools"))
    from seed_mirrors import seed
    result = seed(tmp_path)
    assert (tmp_path / "npm" / "guardian-canary-legit" / "package.json").exists()
    assert (tmp_path / "npm" / "guardian-canary-malicious" / "postinstall.js").exists()
    assert result["python_mirror"]["status"] == "prepared"


def test_source_conflict_and_blocker_details_cross_verified(tmp_path):
    raw = [
        {"source": "grype", "id": "CVE-2026-0001", "aliases": [], "purl": "pkg:npm/a@1.0.0",
         "ranges": [{"native": "<1.2.0"}], "fixed": ["1.2.0"], "cvss": {"score": 9.1},
         "severity": "CRITICAL", "summary": "source conflict test", "evidence_id": "EV-1"},
        {"source": "osv", "id": "CVE-2026-0001", "aliases": [], "purl": "pkg:npm/a@1.0.0",
         "ranges": [{"native": "<1.1.0"}], "fixed": ["1.1.0"], "cvss": {"score": 7.5},
         "severity": "HIGH", "summary": "source conflict test", "evidence_id": "EV-2"},
    ]
    merged = merge_advisories(raw)
    advisory = next(iter(merged.values()))
    assert {c["field"] for c in advisory["source_conflicts"]} >= {"fixed_version", "severity"}

    plan = plan_for_component(
        "pkg:npm/a@1.0.0",
        [advisory],
        [{"version": "1.2.0", "yanked": False}],
        [{"from": "pkg:npm/parent@1.0.0", "to": "pkg:npm/a@1.0.0", "constraint": "<2.0.0"}],
    )
    assert plan["target_version"] == "1.2.0"

    (tmp_path / "agents").mkdir()
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / "package.json").write_text(
        json.dumps({"dependencies": {"a": "1.0.0"}}), encoding="utf-8"
    )
    finding = {
        "id": "VULN::CVE-2026-0001::pkg:npm/a@1.0.0",
        "canonical_id": "CVE-2026-0001",
        "type": "vulnerability",
        "sources": ["grype", "osv"],
        "source_conflicts": advisory["source_conflicts"],
        "evidence_ids": ["EV-1", "EV-2"],
        "score": 91.0,
        "cvss": {"score": 9.1},
        "epss": {"epss": 0.42},
        "kev": True,
        "reachability_state": "reachable",
    }
    report_plan = {
        "action": "upgrade",
        "target_version": "1.2.0",
        "rationale": "cross-verified safe target",
        "compatibility_blocker": "parent needs a <2.0.0; no clean match",
        "compatibility": {
            "parent_constraint_blockers": [{"parent": "pkg:npm/parent@1.0.0", "constraint": "<2.0.0"}],
            "co_upgrade_required": ["pkg:npm/parent@1.0.0"],
        },
        "finding_ids": [finding["id"]],
    }
    (tmp_path / "agents" / "guardian-report.json").write_text(json.dumps({
        "findings": [finding],
        "remediation_plans": {"PLAN::pkg:npm/a@1.0.0": report_plan},
    }), encoding="utf-8")

    rows = load_plans(tmp_path)
    row = rows[0]
    assert row["blocker_status"] == "verified"
    assert row["risk_score"] == 91.0
    assert row["cvss"] == 9.1
    assert row["epss"] == 0.42
    assert row["kev"] is True
    assert row["reachability"] == ["reachable"]
    assert row["evidence_ids"] == ["EV-1", "EV-2"]
    assert len(row["source_conflicts"]) == 2
