from guardian.core.evidence_store import EvidenceStore


def test_evidence_store_hashes_payload(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.db")

    evidence = store.add(
        kind="tool_output",
        source="test",
        uri="file://test",
        payload={"affected": True},
    )

    stored = store.get(evidence["id"])
    assert stored is not None
    assert stored["sha256"] == evidence["sha256"]
    assert '"affected": true' in stored["payload"]
