import json

from guardian_v2.audit import append_entry, verify_chain
from guardian_v2.policy import evaluate_tool_call


def test_audit_chain_round_trip_and_tamper_detection():
    entries = []
    append_entry(entries, "agent:test", "scan", "osv.scan", {}, {"allow": True})
    append_entry(entries, "human:alice", "approve", "git.open_pr", {"draft": True},
                 {"allow": True})
    assert verify_chain(entries) == (True, None)
    entries[1]["actor"] = "human:bob"
    assert verify_chain(entries)[0] is False


def test_tool_firewall_denies_merge_public_publish_and_egress():
    denied = evaluate_tool_call({"tool": "git.merge", "args": {}, "egress_hosts": ["evil.example"]})
    assert denied["allow"] is False
    assert any("human-only" in r for r in denied["deny_reason"])
    assert any("egress" in r for r in denied["deny_reason"])


def test_mutation_requires_gate1_and_secret_args_are_denied():
    mutation = evaluate_tool_call({"tool": "pkg.apply", "args": {"branch": "main"},
                                   "approval": {"gate1": False}})
    assert mutation["allow"] is False
    secret = evaluate_tool_call({"tool": "osv.scan", "args": {"token": "ghp_abcdefghijklmnop"},
                                "egress_hosts": []})
    assert secret["allow"] is False
