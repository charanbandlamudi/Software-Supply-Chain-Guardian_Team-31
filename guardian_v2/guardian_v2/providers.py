"""LLM provider chain: Anthropic -> Groq -> Gemini, whichever keys are set.
Each provider gets messages [{"role", "content"}] and returns text."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path


def _load_dotenv() -> None:
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parents[2] / ".env",
        Path(__file__).resolve().parents[2] / "agent" / ".env",
    ]
    for env_path in candidates:
        if not env_path.is_file():
            continue
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip("\"'")
            if key and key not in os.environ:
                os.environ[key] = value
        return


def _post(url, body, headers):
    # An explicit User-Agent is required: Groq's Cloudflare front rejects Python's default
    # "Python-urllib" agent with HTTP 403 (error code 1010).
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "supply-chain-guardian/2.0", **headers})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:   # keep the provider's error message (never the request/key)
        raise RuntimeError(f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:300]}") from None


def anthropic(messages):
    system = "\n".join(m["content"] for m in messages if m["role"] == "system")
    rest = [m for m in messages if m["role"] != "system"]
    data = _post("https://api.anthropic.com/v1/messages",
                 {"model": os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6"), "max_tokens": 2000,
                  "system": system, "messages": rest},
                 {"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01"})
    return "".join(b.get("text", "") for b in data["content"])


def groq(messages):
    data = _post("https://api.groq.com/openai/v1/chat/completions",
                 {"model": os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"), "messages": messages,
                  "temperature": 0.1, "response_format": {"type": "json_object"}},
                 {"Authorization": f"Bearer {os.environ['GROQ_API_KEY']}"})
    return data["choices"][0]["message"]["content"]


def gemini(messages):
    # "*-latest" aliases track Google's current models; pinned versions (2.0, 2.5) get retired (HTTP 404).
    # If the main model is overloaded (503) or gone (404), try the lighter fallback model(s) before
    # giving up, so Gemini stays in the rotation during Flash demand spikes.
    models = [os.getenv("GEMINI_MODEL", "gemini-flash-latest")] + [
        m.strip() for m in os.getenv("GEMINI_FALLBACK_MODELS", "gemini-flash-lite-latest").split(",") if m.strip()]
    text = "\n\n".join(f"{m['role'].upper()}:\n{m['content']}" for m in messages)
    last = None
    for model in dict.fromkeys(models):
        try:
            data = _post(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                         {"contents": [{"parts": [{"text": text}]}],
                          "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"}},
                         {"x-goog-api-key": os.environ["GEMINI_API_KEY"]})
            gemini.last_model = model             # which model actually answered (main or fallback)
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except RuntimeError as exc:
            last = exc
            if not any(code in str(exc) for code in ("HTTP 503", "HTTP 404")):
                raise                                # 429 / auth errors apply to the whole key
    raise last


def _default_model(name: str) -> str | None:
    return {"groq": os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
            "anthropic": os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
            "gemini": os.getenv("GEMINI_MODEL", "gemini-flash-latest")}.get(name)


class ProviderPool:
    """Round-robin over the configured LLM providers with failover and per-provider cooldowns.

    Call N goes to provider N % len(providers) (e.g. gemini, groq, gemini, ...), which spreads load
    across free-tier rate limits. If that provider fails, the others are tried immediately and the
    failing one is put on cooldown: the wait it asks for on HTTP 429, 30 s on 5xx/timeouts, 10 min
    on 401/403/404 (bad key / retired model). Providers on cooldown are skipped; if all are cooling
    down, the error names the shortest wait ("429 ... try again in Ns") so callers can back off.
    """

    def __init__(self, chain: list[tuple[str, object]]):
        import threading
        self.chain = chain
        self.names = [n for n, _ in chain]
        self._next = 0
        self._lock = threading.Lock()
        self.cooldown_until: dict[str, float] = {}
        self.stats = {n: {"calls": 0, "ok": 0, "failed": 0, "rate_limited": 0} for n in self.names}
        self.last_served: dict | None = None     # {"provider", "model"} of the most recent successful call

    @staticmethod
    def _wait_for(err: str) -> float:
        import re
        m = re.search(r"try again in ([\d.]+)s", err) or re.search(r'"retryDelay":\s*"([\d.]+)s"', err)
        if m:
            return float(m.group(1)) + 1.0
        if "HTTP 429" in err:
            return 20.0
        if re.search(r"HTTP (401|403|404)", err):
            return 600.0
        if re.search(r"HTTP 5\d\d", err) or "timed out" in err.lower() or "URLError" in err:
            return 30.0
        return 0.0                                  # e.g. 400 bad JSON: no cooldown, just try the next one

    def __call__(self, messages):
        import time
        with self._lock:
            start = self._next
            self._next = (self._next + 1) % len(self.chain)
        order = self.chain[start:] + self.chain[:start]
        now = time.monotonic()
        ready = [(n, f) for n, f in order if self.cooldown_until.get(n, 0) <= now]
        errors = []
        for name, fn in ready:
            self.stats[name]["calls"] += 1
            try:
                out = fn(messages)
                self.stats[name]["ok"] += 1
                self.last_served = {"provider": name, "model": getattr(fn, "last_model", None) or _default_model(name)}
                return out
            except Exception as exc:
                err = str(exc)
                self.stats[name]["failed"] += 1
                self.stats[name]["rate_limited"] += "429" in err
                self.stats[name]["last_error"] = err[:160]
                wait = self._wait_for(err)
                if wait:
                    self.cooldown_until[name] = time.monotonic() + wait
                errors.append(f"{name}: {err[:200]}")
        waits = [t - time.monotonic() for t in self.cooldown_until.values() if t > time.monotonic()]
        hint = f" (HTTP 429: all providers cooling down; try again in {max(1.0, min(waits)):.1f}s)" if waits else ""
        raise RuntimeError("all LLM providers failed: " + "; ".join(errors or ["all on cooldown"]) + hint)


def default_chain():
    """Returns (call_fn, provider_names) or (None, []) when no key is configured.

    Providers with a key are used round-robin with failover (ProviderPool). Order comes from
    GUARDIAN_LLM_ORDER (default "gemini,groq,anthropic"); GUARDIAN_LLM_MODE=fallback restores the old
    behaviour of always trying the first provider first.
    """
    _load_dotenv()
    available = {"anthropic": (anthropic, "ANTHROPIC_API_KEY"), "groq": (groq, "GROQ_API_KEY"),
                 "gemini": (gemini, "GEMINI_API_KEY")}
    order = [n.strip() for n in os.getenv("GUARDIAN_LLM_ORDER", "gemini,groq,anthropic").split(",") if n.strip()]
    order += [n for n in available if n not in order]
    chain = [(n, available[n][0]) for n in order if n in available and os.getenv(available[n][1])]
    if not chain:
        return None, []
    if os.getenv("GUARDIAN_LLM_MODE", "round_robin") == "fallback":
        def call(messages):
            errors = []
            for name, fn in chain:
                try:
                    return fn(messages)
                except Exception as exc:
                    errors.append(f"{name}: {exc}")
            raise RuntimeError("all LLM providers failed: " + "; ".join(errors))
        return call, [n for n, _ in chain]
    return ProviderPool(chain), [n for n, _ in chain]
