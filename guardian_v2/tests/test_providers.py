"""ProviderPool: round-robin across LLM providers, failover, cooldowns."""
import pytest

from guardian_v2.providers import ProviderPool


def fake(name, log, fail=None):
    def fn(messages):
        log.append(name)
        if fail:
            raise RuntimeError(fail)
        return f"{name}-ok"
    return fn


def test_alternates_providers_per_call():
    log = []
    pool = ProviderPool([("gemini", fake("gemini", log)), ("groq", fake("groq", log))])
    assert [pool([]) for _ in range(4)] == ["gemini-ok", "groq-ok", "gemini-ok", "groq-ok"]
    assert pool.stats["gemini"]["ok"] == 2 and pool.stats["groq"]["ok"] == 2


def test_rate_limited_provider_fails_over_and_cools_down():
    log = []
    pool = ProviderPool([("gemini", fake("gemini", log, "HTTP 429: quota, try again in 30s")),
                         ("groq", fake("groq", log))])
    assert pool([]) == "groq-ok"            # gemini's turn: 429 -> immediate failover to groq
    assert pool([]) == "groq-ok"            # groq's turn
    assert pool([]) == "groq-ok"            # gemini's turn again, but it is cooling down: skipped
    assert log == ["gemini", "groq", "groq", "groq"]
    assert pool.stats["gemini"]["rate_limited"] == 1


def test_all_cooling_down_raises_with_retry_hint():
    log = []
    pool = ProviderPool([("gemini", fake("gemini", log, "HTTP 503: high demand")),
                         ("groq", fake("groq", log, "HTTP 429: try again in 12.5s"))])
    with pytest.raises(RuntimeError) as err:
        pool([])
    assert "try again in" in str(err.value) and "429" in str(err.value)


def test_bad_json_400_does_not_cool_down():
    log = []
    pool = ProviderPool([("groq", fake("groq", log, "HTTP 400: json_validate_failed")),
                         ("gemini", fake("gemini", log))])
    assert pool([]) == "gemini-ok"
    assert "groq" not in pool.cooldown_until
