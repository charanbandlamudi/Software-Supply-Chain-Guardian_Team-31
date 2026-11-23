"""End-to-end test on the Werkzeug 2.0.1 scenario with fake sources/LLM (no network)."""
import json

from langgraph.types import Command

from guardian_v2.adapters import adapt, delta
from guardian_v2.dedup import merge_advisories
from guardian_v2.workflow import GuardianDeps, build_workflow

WZ = "pkg:pypi/werkzeug@2.0.1"
FLASK = "pkg:pypi/flask@2.0.1"
VERSIONS = [{"version": v, "yanked": False} for v in
            ["2.0.1", "2.0.2", "2.1.0", "2.2.2", "2.2.3", "2.3.8", "3.0.0", "3.0.1",
             "3.0.3", "3.0.6", "3.1.0rc1", "3.1.3"]]


def ingestion(state):
    return {"components": {
        FLASK: {"direct": True, "scope": "prod", "registry_versions": []},
        WZ: {"direct": True, "scope": "prod"}}}


def dependency_graph(state):
    return {"edges": [{"from": FLASK, "to": WZ, "constraint": ">=2.0", "scope": "prod"}]}


def grype(payload):
    raw = [
        {"source": "grype", "id": "GHSA-xg9f-g7g7-2323", "aliases": ["CVE-2023-25577"], "purl": WZ,
         "ranges": None, "fixed": ["2.2.3"], "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "score": 7.5},
         "severity": "High", "evidence_id": "EV-grype-1"},
        {"source": "grype", "id": "GHSA-hrfv-mqp8-q5rw", "aliases": ["CVE-2023-46136"], "purl": WZ,
         "ranges": None, "fixed": ["3.0.1", "2.3.8"], "cvss": {"vector": "x", "score": 7.5},
         "severity": "High", "evidence_id": "EV-grype-2"},
    ]
    ev = {e: {"id": e} for e in ("EV-grype-1", "EV-grype-2")}
    return {"raw_advisories": raw, "evidence": ev, "coverage": {"source:grype": "ok"}}


def ghsa(payload):
    raw = [
        {"source": "ghsa", "id": "GHSA-xg9f-g7g7-2323", "aliases": ["CVE-2023-25577"], "purl": WZ,
         "ranges": [{"introduced": "0", "fixed": "2.2.3"}], "fixed": ["2.2.3"],
         "cvss": {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "score": 7.5},
         "severity": "high", "evidence_id": "EV-ghsa-1"},
        {"source": "ghsa", "id": "GHSA-hrfv-mqp8-q5rw", "aliases": ["CVE-2023-46136"], "purl": WZ,
         "ranges": [{"introduced": "0", "fixed": "2.3.8"}, {"introduced": "3.0.0", "fixed": "3.0.1"}],
         "fixed": ["2.3.8", "3.0.1"], "cvss": {"vector": "x", "score": 5.7},
         "severity": "moderate", "evidence_id": "EV-ghsa-1"},
        {"source": "ghsa", "id": "GHSA-2g68-c3qc-8985", "aliases": ["CVE-2024-34069"], "purl": WZ,
         "ranges": [{"introduced": "0", "fixed": "3.0.3"}], "fixed": ["3.0.3"],
         "cvss": {"vector": "x", "score": 7.5}, "severity": "high", "evidence_id": "EV-ghsa-1"},
    ]
    return {"raw_advisories": raw, "evidence": {"EV-ghsa-1": {"id": "EV-ghsa-1"}},
            "coverage": {"source:ghsa": "ok"}}


def broken_source(payload):
    raise TimeoutError("nvd down")


def reputation(state):
    return {"components": {WZ: {"registry_versions": VERSIONS}}}


def reachability(state):
    return {"components": {WZ: {"reachability": {"state": "reachable", "evidence_ids": ["EV-ast-1"]}}},
            "evidence": {"EV-ast-1": {"id": "EV-ast-1", "uri": "app/upload.py:42"}}}


CALLS = {"n": 0}


def fake_llm(messages):
    CALLS["n"] += 1
    fid = "VULN::CVE-2023-25577::" + WZ
    if CALLS["n"] == 1:  # hallucinates an ID, a fake version and fake evidence
        return json.dumps([{"finding_id": fid, "statement": "Also see CVE-2099-0001; actively exploited.",
                            "evidence_ids": ["EV-made-up"], "facts": {"target_version": "9.9.9"}}])
    return "```json\n" + json.dumps({"claims": [{
        "finding_id": fid, "statement": "CVE-2023-25577 is reachable via the upload route.",
        "evidence_ids": ["EV-ghsa-1", "EV-ast-1"], "facts": {"cvss": 7.5, "target_version": "3.0.3"}}]}) + "\n```"


def validator(plan, state):
    return {"build": "pass", "tests": "pass",
            "after_components": [p.replace("2.0.1", plan["target_version"]) if "werkzeug" in p else p
                                 for p in state["components"]],
            "after_finding_ids": []}


def make():
    return build_workflow(GuardianDeps(
        ingestion=ingestion, dependency_graph=dependency_graph, reputation=reputation,
        reachability=reachability,
        sources={"grype": grype, "ghsa": ghsa, "nvd": broken_source},
        kev_catalog=lambda: {}, epss_lookup=lambda cves: {c: {"epss": 0.01, "percentile": 0.5} for c in cves},
        llm_call=fake_llm, validator=validator))


def test_end_to_end():
    app = make()
    cfg = {"configurable": {"thread_id": "t1"}}
    app.invoke({"run_id": "r1", "inputs": {}}, cfg)
    snap = app.get_state(cfg)
    assert snap.next == ("human_approval",)          # paused at the human gate
    plan = snap.values["remediation_plans"]["PLAN::" + WZ]
    assert plan["target_version"] == "3.0.3"           # smallest version clearing all 3 advisories
    assert plan["latest_safe"] == "3.1.3"              # rc excluded
    assert plan["compatibility"]["verdict"] == "major_bump_needs_tests"
    assert plan["merge"] is False

    final = app.invoke(Command(resume={"decisions": {"PLAN::" + WZ: "approve"}, "reviewer": "alice"}), cfg)
    rep = final["report"]
    ids = [f["id"] for f in rep["findings"]]
    assert len(ids) == 3                                # 5 raw records -> 3 unique issues
    top = next(f for f in rep["findings"] if f["canonical_id"] == "CVE-2023-25577")
    assert top["sources"] == ["ghsa", "grype"] and top["paths"]
    assert top["reachability_state"] == "reachable"
    assert top["ai_inferences"][0]["kind"] == "inference"
    sev = next(f for f in rep["findings"] if f["canonical_id"] == "CVE-2023-46136")
    assert any(c["field"] == "severity" for c in sev["source_conflicts"])
    assert rep["coverage"]["source:nvd"].startswith("failed")   # degraded, not crashed
    assert final["critic_attempts"] == 2 and CALLS["n"] == 2    # one rejection, one retry
    assert rep["approvals"][0]["reviewer"] == "alice"
    v = rep["validation"]["PLAN::" + WZ]
    assert v["tests"] == "pass" and "pkg:pypi/werkzeug@3.0.3" in v["sbom_diff"]["added"]


def test_critic_rejects_hallucination():
    from guardian_v2.critic import verify_claims
    state = {"findings": {"F": {"canonical_id": "CVE-2023-25577", "aliases": ["GHSA-xg9f-g7g7-2323"],
                                "evidence_ids": ["E1"], "cvss": {"score": 7.5}, "component_purl": WZ}},
             "evidence": {"E1": {}}, "remediation_plans": {}}
    v = verify_claims([{"finding_id": "F", "statement": "See CVE-2021-0001, actively exploited",
                        "evidence_ids": ["E1"], "facts": {"cvss": 9.8}}], state)
    reasons = " ".join(v["rejected"][0]["reasons"])
    assert "CVE-2021-0001" in reasons and "cvss" in reasons and "KEV" in reasons


def test_not_affected_by_ranges_is_dropped():
    raw = [{"source": "ghsa", "id": "GHSA-x", "aliases": [], "purl": "pkg:pypi/werkzeug@3.1.3",
            "ranges": [{"introduced": "0", "fixed": "3.0.3"}], "fixed": ["3.0.3"]}]
    assert merge_advisories(raw) == {}


def test_adapter_returns_delta_only():
    def v1_node(state):
        state["components"]["pkg:npm/a@1"] = {"direct": True}
        state["edges"].append({"from": "x", "to": "y"})
        return state
    node = adapt(v1_node)
    out = node({"components": {"pkg:npm/b@1": {}}, "edges": [{"from": "p", "to": "q"}], "run_id": "r"})
    assert out == {"components": {"pkg:npm/a@1": {"direct": True}}, "edges": [{"from": "x", "to": "y"}]}
    assert delta({"a": 1}, {"a": 1}) == {}


def test_osv_normalize():
    from guardian_v2.sources.osv import normalize
    vuln = {"id": "GHSA-xg9f-g7g7-2323", "aliases": ["CVE-2023-25577", "PYSEC-2023-58"],
            "affected": [{"package": {"ecosystem": "PyPI", "name": "Werkzeug"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.3"}]}]}],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}]}
    recs = normalize(vuln, WZ, "EV-osv-1")
    assert recs[0]["ranges"] == [{"introduced": "0", "fixed": "2.2.3"}]
    merged = merge_advisories(recs + [dict(recs[0], source="ghsa", id="CVE-2023-25577", aliases=[])])
    assert list(merged) == ["CVE-2023-25577::" + WZ]
