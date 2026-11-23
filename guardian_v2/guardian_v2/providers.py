"""LLM provider chain: Anthropic -> Groq -> Gemini, whichever keys are set.
Each provider gets messages [{"role", "content"}] and returns text."""
from __future__ import annotations

import json
import os
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
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


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
                 {"model": os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"), "messages": messages,
                  "temperature": 0.1, "response_format": {"type": "json_object"}},
                 {"Authorization": f"Bearer {os.environ['GROQ_API_KEY']}"})
    return data["choices"][0]["message"]["content"]


def gemini(messages):
    model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
    text = "\n\n".join(f"{m['role'].upper()}:\n{m['content']}" for m in messages)
    data = _post(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                 {"contents": [{"parts": [{"text": text}]}],
                  "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"}},
                 {"x-goog-api-key": os.environ["GEMINI_API_KEY"]})
    return data["candidates"][0]["content"]["parts"][0]["text"]


def default_chain():
    """Returns (call_fn, provider_names) or (None, []) when no key is configured."""
    _load_dotenv()
    chain = [(n, f) for n, f, k in (("anthropic", anthropic, "ANTHROPIC_API_KEY"),
                                     ("groq", groq, "GROQ_API_KEY"),
                                     ("gemini", gemini, "GEMINI_API_KEY")) if os.getenv(k)]
    if not chain:
        return None, []

    def call(messages):
        errors = []
        for name, fn in chain:
            try:
                return fn(messages)
            except Exception as exc:
                errors.append(f"{name}: {exc}")
        raise RuntimeError("all LLM providers failed: " + "; ".join(errors))
    return call, [n for n, _ in chain]
