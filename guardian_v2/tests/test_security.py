from pathlib import Path
import json

from guardian_v2.agents import gate
from guardian_v2 import providers


def test_auto_approve_argument_removed():
    run_guardian = Path(__file__).parents[1] / "run_guardian.py"
    text = run_guardian.read_text()
    assert "--auto-approve" not in text
    assert "demo-reviewer" not in text


def test_container_sandbox_has_hardening(tmp_path):
    work = tmp_path / "sandbox"
    work.mkdir()
    args = gate._container_args(
        "docker",
        work,
        "python:3.12-slim",
        ["python", "-c", "print('ok')"],
    )
    assert "--network=none" in args
    assert "--read-only" in args
    assert "--cap-drop=ALL" in args
    assert "--security-opt=no-new-privileges" in args
    assert "--user" in args
    assert "65532:65532" in args


def test_safe_copy_rejects_absolute_and_traversal(tmp_path):
    project = tmp_path / "project"
    work = tmp_path / "work"
    project.mkdir()
    work.mkdir()
    (project / "safe").mkdir()

    assert gate._safe_copy_directory(project, work, "../outside") is False
    assert gate._safe_copy_directory(project, work, str(project / "safe")) is False
    assert gate._safe_copy_directory(project, work, "safe") is True


def test_gemini_uses_header_not_query(monkeypatch):
    calls = {}

    def fake_post(url, body, headers):
        calls["url"] = url
        calls["headers"] = headers
        return {"candidates": [{"content": {"parts": [{"text": "{}"}]}}]}

    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(providers, "_post", fake_post)

    assert providers.gemini([{"role": "user", "content": "test"}]) == "{}"
    assert "key=" not in calls["url"]
    assert calls["headers"]["x-goog-api-key"] == "test-key"


def test_approval_requires_interrupt(monkeypatch):
    seen = {}

    def fake_interrupt(payload):
        seen.update(payload)
        return {"all": "reject", "reviewer": "reviewer"}

    monkeypatch.setattr(gate, "interrupt", fake_interrupt)
    state = {
        "components": {},
        "remediation_plans": {
            "PLAN": {"status": "proposed", "component": "pkg:npm/a@1", "action": "upgrade",
                     "target_version": "2", "attempt": 1, "rationale": "test"},
        },
    }

    result = gate.run_approval(state, {})

    assert "Approve these remediation plans?" in seen["question"]
    assert result.delta["remediation_plans"]["PLAN"]["status"] == "rejected"
