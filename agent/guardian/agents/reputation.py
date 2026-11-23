from guardian.agents.base import BaseAgent
from guardian.core.evidence_store import EvidenceStore
from guardian.core.models import GuardianState
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from http.client import InvalidURL
import json
from concurrent.futures import ThreadPoolExecutor, as_completed


class PackageReputationAgent(BaseAgent):
    name = "package_reputation"

    def run(self, state: GuardianState) -> GuardianState:
        store = EvidenceStore(":memory:")
        candidates = [
            component
            for component in list(state.components.values())[:25]
            if component.ecosystem in ("npm", "pypi")
            and component.name
            and component.name not in ("unknown", "")
        ]

        def check(component):
            try:
                if component.ecosystem == "npm":
                    url = f"https://registry.npmjs.org/{component.name}"
                else:
                    url = f"https://pypi.org/pypi/{component.name}/{component.version}/json"
                request = Request(url, headers={"Accept": "application/json", "User-Agent": "Guardian/0.1"})
                with urlopen(request, timeout=5) as response:
                    payload = json.loads(response.read().decode("utf-8"))
                return component.ecosystem, url, payload
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError, InvalidURL, ValueError):
                return None

        checked = 0
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(check, component) for component in candidates]
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    ecosystem, uri, payload = result
                    evidence = store.add(
                        kind="api_response",
                        source=f"{ecosystem}_registry",
                        uri=uri,
                        payload=payload,
                    )
                    state.evidence[evidence["id"]] = evidence
                    checked += 1
        store.close()
        state.coverage["package_reputation"] = f"{checked}_checked"
        return state
