from guardian.agents.ingestion import IngestionAgent
from guardian.core.models import GuardianState
from guardian.orchestrator import Supervisor


def test_ingestion_parses_requirements(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("Flask==2.0.1\nWerkzeug==2.0.1\n")
    state = GuardianState(run_id="test", inputs=[str(requirements)])

    result = IngestionAgent().run(state)

    assert result.coverage["ingestion"] == "complete"
    assert "pkg:pypi/flask@2.0.1" in result.components
    assert "pkg:pypi/werkzeug@2.0.1" in result.components


def test_supervisor_runs_without_findings(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.25.1\n")

    state = Supervisor().run([str(requirements)], run_id="test-run")

    assert state.run_id == "test-run"
    assert state.coverage["ingestion"] == "complete"
    assert state.coverage["evidence_critic"] == "complete"


def test_container_agent_detects_unpinned_image(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM python:3.9\n")
    state = GuardianState(run_id="test", inputs=[str(dockerfile)])

    result = Supervisor().run([str(dockerfile)], run_id="test")

    assert any(finding.type == "image" for finding in result.findings.values())


def test_supplied_cyclonedx_and_graph_format(tmp_path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text(
        '{"bomFormat":"CycloneDX","components":[{"name":"multer","version":"1.4.5-lts.2",'
        '"purl":"pkg:npm/multer@1.4.5-lts.2","licenses":[]}],'
        '"dependencies":[]}'
    )
    graph = tmp_path / "graph.json"
    graph.write_text(
        '{"nodes":[{"id":"pkg:npm/multer@1.4.5-lts.2?x","purl":"pkg:npm/multer@1.4.5-lts.2","vulns":[]}],'
        '"edges":[],"roots":["pkg:npm/multer@1.4.5-lts.2?x"]}'
    )

    state = Supervisor().run([str(sbom), str(graph)], run_id="formats")

    assert state.coverage["ingestion"] == "complete"
    assert state.coverage["graph"] == "complete"
    assert "pkg:npm/multer@1.4.5-lts.2" in state.components


def test_groq_is_disabled_until_key_is_present():
    from guardian.agents.inference import GroqInferenceAgent
    from guardian.core.groq import GroqClient
    from guardian.core.gemini import GeminiClient

    state = GuardianState(run_id="groq")
    result = GroqInferenceAgent(
        GroqClient(api_key=""),
        GeminiClient(api_key=""),
    ).run(state)

    assert result.coverage["groq"] == "awaiting_api_key"


def test_supplied_grype_report(tmp_path):
    grype = tmp_path / "grype-report.json"
    grype.write_text(
        '{"matches":[{"vulnerability":{"id":"GHSA-test","severity":"High","cvss":[],'
        '"fix":{"versions":["2.0.0"]}},"artifact":{"purl":"pkg:npm/multer@1.0.0",'
        '"name":"multer","version":"1.0.0"}}]}',
        encoding="utf-8",
    )
    state = Supervisor().run([str(grype)], run_id="grype")

    assert state.coverage["vulnerability_intelligence"] == "1_matches"
    assert len(state.findings) == 1


def test_duplicate_advisory_preserves_distinct_versions(tmp_path):
    grype = tmp_path / "grype.json"
    grype.write_text(
        '{"matches":['
        '{"vulnerability":{"id":"GHSA-qs","severity":"Medium","cvss":[],"fix":{"versions":["6.15.2"]}},'
        '"artifact":{"purl":"pkg:npm/qs@6.14.2","name":"qs","version":"6.14.2"}},'
        '{"vulnerability":{"id":"GHSA-qs","severity":"Medium","cvss":[],"fix":{"versions":["6.15.2"]}},'
        '"artifact":{"purl":"pkg:npm/qs@6.15.1","name":"qs","version":"6.15.1"}}'
        "]}",
        encoding="utf-8",
    )

    state = Supervisor().run([str(grype)], run_id="qs-versions")

    assert len(state.findings) == 2
    purls = {finding.component_purl for finding in state.findings.values()}
    assert "pkg:npm/qs@6.14.2" in purls
    assert "pkg:npm/qs@6.15.1" in purls


def test_ingestion_preserves_parse_issue(tmp_path):
    missing = tmp_path / "missing.json"
    bad = tmp_path / "bad.json"
    bad.write_text("{invalid")

    state = IngestionAgent().run(
        GuardianState(run_id="issues", inputs=[str(missing), str(bad)])
    )

    assert state.coverage["ingestion"] == "partial"
    assert "missing_input:" in state.coverage["ingestion_issues"]
    assert "parse_error:" in state.coverage["ingestion_issues"]


def test_anomaly_persists_evidence(tmp_path):
    from guardian.agents.anomaly import SupplyChainAnomalyAgent

    package = tmp_path / "package.json"
    package.write_text(
        '{"scripts":{"postinstall":"echo test"},"dependencies":{"reqeusts":"1.0.0"}}'
    )
    state = GuardianState(run_id="anomaly", inputs=[str(package)])

    result = SupplyChainAnomalyAgent().run(state)

    assert result.coverage["anomaly_evidence_count"] == "1"
    assert result.evidence


def test_scoring_uses_scope_and_reachability(tmp_path):
    from guardian.agents.reachability import ReachabilityAgent
    from guardian.agents.scoring import RiskScoringAgent
    from guardian.core.models import Component, Finding

    state = GuardianState(run_id="score")
    state.components["pkg:npm/lodash@4.17.15"] = Component(
        purl="pkg:npm/lodash@4.17.15",
        name="lodash",
        version="4.17.15",
        ecosystem="npm",
        scope="dev",
    )
    state.findings["vuln"] = Finding(
        id="vuln",
        type="vuln",
        component_purl="pkg:npm/lodash@4.17.15",
        score_breakdown={"cvss": 8.0},
    )

    result = RiskScoringAgent().run(state)

    assert result.findings["vuln"].score == 3.2
    assert result.findings["vuln"].score_breakdown["scope"] == 0.4


def test_remediation_never_auto_merges():
    from guardian.agents.remediation import RemediationAgent
    from guardian.core.models import Finding

    state = GuardianState(run_id="remediation")
    state.findings["vuln"] = Finding(
        id="vuln",
        type="vuln",
        component_purl="pkg:npm/test@1.0.0",
        confidence="High",
    )

    result = RemediationAgent().run(state)

    assert result.remediation_plans
    assert all(plan["merge"] is False for plan in result.remediation_plans)
    assert all(plan["human_approval_required"] for plan in result.remediation_plans)


def test_vex_report_generation(tmp_path):
    from guardian.agents.report import ReportAgent
    from guardian.core.models import Finding

    state = GuardianState(run_id="vex")
    state.findings["vuln"] = Finding(
        id="vuln",
        type="vuln",
        component_purl="pkg:npm/test@1.0.0",
    )
    output = tmp_path / "report.vex.json"

    result = ReportAgent().write_vex(state, output)

    assert result == output
    assert '"vulnerabilities"' in output.read_text()


def test_groq_invalid_json_is_reported():
    from guardian.agents.inference import GroqInferenceAgent
    from guardian.core.gemini import GeminiClient

    class FakeGroq:
        api_key = "test"
        model = "test-model"

        def complete(self, system_prompt, user_prompt, temperature=0.1):
            return "not json"

    state = GuardianState(run_id="invalid-groq")

    result = GroqInferenceAgent(
        FakeGroq(),
        GeminiClient(api_key=""),
    ).run(state)

    assert result.coverage["llm"] == "invalid_json"
    assert "llm_error" in result.coverage


def test_gemini_fallback_is_used_when_groq_fails():
    from guardian.agents.inference import GroqInferenceAgent

    class FailingGroq:
        api_key = "test"
        model = "groq-test"

        def complete(self, system_prompt, user_prompt, temperature=0.1):
            raise RuntimeError("Groq unavailable")

    class WorkingGemini:
        api_key = "test"
        model = "gemini-test"

        def complete(self, system_prompt, user_prompt, temperature=0.1):
            return '{"priority":"proxy-addr","human_approval_required":true}'

    state = GuardianState(run_id="fallback")

    result = GroqInferenceAgent(FailingGroq(), WorkingGemini()).run(state)

    assert result.coverage["gemini"] == "complete"
    assert result.approvals[0]["provider"] == "gemini"
    assert result.approvals[0]["analysis"]["human_approval_required"] is True


def test_supervisor_exposes_langgraph_node_topology():
    supervisor = Supervisor()

    assert len(supervisor.agents) == 12
    assert supervisor.graph is not None
    assert hasattr(supervisor.graph, "invoke")
    assert [agent.name for agent in supervisor.agents] == [
        "ingestion",
        "dependency_graph",
        "vulnerability_intelligence",
        "package_reputation",
        "supply_chain_anomaly",
        "container_cicd",
        "reachability",
        "risk_scoring",
        "remediation",
        "evidence_critic",
        "groq_inference",
        "report",
    ]
