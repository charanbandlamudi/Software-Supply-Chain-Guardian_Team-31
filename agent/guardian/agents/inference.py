from guardian.agents.base import BaseAgent
from guardian.core.groq import GroqClient
from guardian.core.gemini import GeminiClient
from guardian.core.models import GuardianState
import json


class GroqInferenceAgent(BaseAgent):
    name = "groq_inference"

    def __init__(
        self,
        client: GroqClient | None = None,
        fallback_client: GeminiClient | None = None,
    ):
        self.client = client or GroqClient()
        self.fallback_client = fallback_client or GeminiClient()

    def run(self, state: GuardianState) -> GuardianState:
        try:
            prompt = {
                "run_id": state.run_id,
                "findings": [finding.to_dict() for finding in state.findings.values()],
                "coverage": state.coverage,
            }
            system_prompt = (
                "Return JSON only. Correlate security findings and recommend actions. "
                "Use only supplied evidence. Never claim certainty beyond the data."
            )
            user_prompt = json.dumps(prompt, sort_keys=True)
            provider = None
            model = None
            groq_error = None

            if self.client.api_key:
                try:
                    result = self.client.complete(system_prompt, user_prompt)
                    provider = "groq"
                    model = self.client.model
                except (RuntimeError, ValueError, KeyError) as exc:
                    groq_error = str(exc)
            else:
                groq_error = "GROQ_API_KEY is not configured"

            if provider is None and self.fallback_client.api_key:
                try:
                    result = self.fallback_client.complete(system_prompt, user_prompt)
                    provider = "gemini"
                    model = self.fallback_client.model
                    state.coverage["groq"] = "fallback_to_gemini"
                    state.coverage["groq_error"] = groq_error
                except (RuntimeError, ValueError, KeyError) as exc:
                    state.coverage["groq"] = "error"
                    state.coverage["groq_error"] = groq_error or str(exc)
                    state.coverage["gemini_error"] = str(exc)
                    return state
            elif provider is None:
                state.coverage["groq"] = "awaiting_api_key"
                state.coverage["groq_error"] = groq_error
                state.coverage["gemini"] = "awaiting_api_key"
                return state
            try:
                analysis = json.loads(result)
            except json.JSONDecodeError as exc:
                state.coverage["llm"] = "invalid_json"
                state.coverage["llm_error"] = str(exc)
                return state
            if isinstance(analysis, list):
                analysis = {"findings": analysis}
            if not isinstance(analysis, dict):
                state.coverage["llm"] = "invalid_json"
                state.coverage["llm_error"] = "response was not a JSON object"
                return state
            state.approvals.append({
                "provider": provider,
                "model": model,
                "analysis": analysis,
                "human_approval_required": True,
            })
            state.coverage["llm"] = "complete"
            if provider == "groq":
                state.coverage["groq"] = "complete"
            else:
                state.coverage["gemini"] = "complete"
        except (RuntimeError, ValueError, KeyError) as exc:
            state.coverage["groq"] = "error"
            state.coverage["groq_error"] = str(exc)
        return state
