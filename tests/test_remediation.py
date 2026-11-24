from pathlib import Path

from remediation.analyzer import extract_grype_findings
from remediation.dependency_resolver import find_dependency
from remediation.planner import aggregate_remediation_actions, generate_plan
from remediation.version_selector import select_version
from remediation.approval import record_decision


def test_grype_analyzer_and_direct_plan(tmp_path: Path):
    grype = tmp_path / "grype.json"
    grype.write_text(
        '{"matches":[{"artifact":{"name":"lodash","version":"2.4.2","purl":"pkg:npm/lodash@2.4.2","type":"npm"},'
        '"vulnerability":{"id":"GHSA-35jh-r3h4-6jhm","severity":"High","fix":{"versions":["4.17.21"]}},'
        '"matchDetails":[{"fix":{"suggestedVersion":"4.17.21"}}]}]}',
        encoding="utf-8",
    )
    findings = extract_grype_findings(grype)
    assert findings[0]["ecosystem"] == "npm"
    assert findings[0]["suggested_versions"] == ["4.17.21"]
    assert select_version(findings[0])["recommended_version"] == "4.17.21"

    graph = {
        "root": "pkg:npm/app@1",
        "nodes": [
            {"id": "pkg:npm/app@1", "name": "app", "version": "1", "purl": "pkg:npm/app@1"},
            {"id": "lodash-node", "name": "lodash", "version": "2.4.2",
             "purl": "pkg:npm/lodash@2.4.2", "dep_type": "direct"},
        ],
        "edges": [{"from": "pkg:npm/app@1", "to": "lodash-node"}],
    }
    plan = generate_plan(graph, grype)
    change = plan["changes"][0]
    assert change["vulnerability_ids"] == ["GHSA-35jh-r3h4-6jhm"]
    assert change["vulnerability_count"] == 1
    assert change["dependency_type"] == "direct"
    assert change["strategy"] == "direct_upgrade"
    assert change["status"] == "pending_approval"


def test_missing_dependency_requires_manual_review(tmp_path: Path):
    grype = tmp_path / "grype.json"
    grype.write_text(
        '{"matches":[{"artifact":{"name":"unknown","version":"1.0.0","purl":"pkg:npm/unknown@1.0.0"},'
        '"vulnerability":{"id":"CVE-2026-0001","severity":"Medium","fix":{"versions":["1.0.1"]}}}]}',
        encoding="utf-8",
    )
    graph = {"root": "root", "nodes": [{"id": "root", "name": "app", "purl": "pkg:npm/app@1"}], "edges": []}
    change = generate_plan(graph, grype)["changes"][0]
    assert change["dependency_type"] == "unresolved"
    assert change["strategy"] == "manual_review"
    assert change["status"] == "requires_review"


def test_purl_is_preferred_over_name():
    graph = {
        "root": "root",
        "nodes": [
            {"id": "other", "name": "lodash", "version": "4.17.20", "purl": "pkg:pypi/lodash@4.17.20"},
            {"id": "npm", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20",
             "dep_type": "direct"},
        ],
        "edges": [],
    }
    result = find_dependency(graph, {
        "package": "lodash",
        "current_version": "4.17.20",
        "purl": "pkg:npm/lodash@4.17.20",
    })
    assert result["status"] == "resolved"
    assert result["node_id"] == "npm"


def test_package_level_aggregation_and_approval():
    changes = [
        {
            "ecosystem": "npm",
            "purl": "pkg:npm/hono@4.13.13",
            "current_version": "4.13.13",
            "recommended_version": "4.13.16",
            "candidate_versions": ["4.13.16"],
            "package": "hono",
            "severity": "MEDIUM",
            "vulnerability_id": "CVE-1",
            "aliases": ["CVE-1"],
            "dependency_type": "transitive",
            "path_ids": ["root", "hono"],
            "parent_ids": ["sdk"],
            "strategy": "transitive_review",
        },
        {
            "ecosystem": "npm",
            "purl": "pkg:npm/hono@4.13.13",
            "current_version": "4.13.13",
            "recommended_version": "4.13.16",
            "candidate_versions": ["4.13.16"],
            "package": "hono",
            "severity": "LOW",
            "vulnerability_id": "CVE-2",
            "aliases": ["CVE-2"],
            "dependency_type": "transitive",
            "path_ids": ["root", "hono"],
            "parent_ids": ["node-server"],
            "strategy": "transitive_review",
        },
    ]
    actions = aggregate_remediation_actions(changes)
    assert len(actions) == 1
    assert actions[0]["vulnerability_count"] == 2
    assert actions[0]["status"] == "requires_dependency_review"

    approved = record_decision(
        {"changes": actions},
        actions[0]["action_id"],
        "approve",
        "alice",
    )
    assert approved["changes"][0]["status"] == "approved"
    assert approved["changes"][0]["approval"]["reviewer"] == "alice"
