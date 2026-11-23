import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def load_dotenv(path: Path | None = None) -> None:
    env_path = path or Path(__file__).resolve().parents[2] / ".env"
    if not env_path.is_file():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value


class GeminiClient:
    """Gemini REST client used as an inference fallback."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
    ):
        if api_key is None:
            load_dotenv()
            api_key = os.getenv("GEMINI_API_KEY")
        self.api_key = api_key
        self.model = model or os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
        self.base_url = os.getenv(
            "GEMINI_BASE_URL",
            "https://generativelanguage.googleapis.com/v1beta",
        )

    def complete(self, system_prompt: str, user_prompt: str, temperature: float = 0.1) -> str:
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY is not configured")
        body = json.dumps({
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "temperature": temperature,
                "responseMimeType": "application/json",
            },
        }).encode("utf-8")
        url = f"{self.base_url}/models/{self.model}:generateContent"
        request = Request(
            url,
            data=body,
            headers={
                "x-goog-api-key": self.api_key,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=60) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            raise RuntimeError(
                f"Gemini HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')}"
            ) from exc
        except URLError as exc:
            raise RuntimeError(f"Gemini connection failed: {exc.reason}") from exc
        candidates = payload.get("candidates", [])
        if not candidates:
            raise RuntimeError("Gemini returned no candidates")
        parts = candidates[0].get("content", {}).get("parts", [])
        if not parts:
            raise RuntimeError("Gemini returned no content")
        return parts[0].get("text", "")
