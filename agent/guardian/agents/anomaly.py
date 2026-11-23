from guardian.agents.base import BaseAgent
from guardian.core.models import Finding, GuardianState
from pathlib import Path
import json
import re


class SupplyChainAnomalyAgent(BaseAgent):
    name = "supply_chain_anomaly"

    def run(self, state: GuardianState) -> GuardianState:
        popular_roots = {"flask", "werkzeug", "lodash", "requests", "jinja2", "pyyaml"}
        evidence_ids = []
        from guardian.core.evidence_store import EvidenceStore
        store = EvidenceStore(":memory:")
        for input_path in state.inputs:
            path = Path(input_path)
            if not path.is_file():
                continue
            text = path.read_text(errors="replace")
            if path.name == "package.json":
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    payload = {}
                for section in ("dependencies", "devDependencies", "optionalDependencies"):
                    for name in payload.get(section, {}):
                        if name not in popular_roots:
                            continue
                        if len(name) >= 6:
                            suspect = re.sub(r"[aeiou]", "", name)
                            if suspect and suspect != name:
                                evidence = store.add(
                                    kind="detector_output",
                                    source="supply_chain_anomaly",
                                    uri=str(path),
                                    payload={"detector": "typosquat", "package": name},
                                )
                                evidence_ids.append(evidence["id"])
                                state.evidence[evidence["id"]] = evidence
                for name, spec in {**payload.get("dependencies", {}),
                                   **payload.get("devDependencies", {})}.items():
                    manifest = json.dumps(payload)
                    if re.search(r'"(preinstall|install|postinstall)"', manifest):
                        finding_id = f"ANOMALY-{name}-install-script"
                        evidence = store.add(
                            kind="detector_output",
                            source="supply_chain_anomaly",
                            uri=str(path),
                            payload={"detector": "install_script", "package": name},
                        )
                        evidence_ids.append(evidence["id"])
                        state.evidence[evidence["id"]] = evidence
                        state.findings[finding_id] = state.findings.get(
                            finding_id,
                            Finding(
                                id=finding_id,
                                type="install_script",
                                component_purl=f"pkg:npm/{name}",
                            ),
                        )
            for line in text.splitlines():
                if '"integrity"' in line or "resolved_url" in line:
                    evidence = store.add(
                        kind="detector_output",
                        source="supply_chain_anomaly",
                        uri=str(path),
                        payload={"detector": "lockfile_review", "file": path.name},
                    )
                    evidence_ids.append(evidence["id"])
                    state.evidence[evidence["id"]] = evidence
        for finding in state.findings.values():
            if finding.type in ("install_script", "lockfile"):
                finding.verified_evidence.extend(
                    evidence_id for evidence_id in evidence_ids
                    if evidence_id not in finding.verified_evidence
                )
        state.coverage["anomaly_evidence_count"] = str(len(evidence_ids))
        store.close()
        state.coverage["supply_chain_anomaly"] = "complete"
        return state
