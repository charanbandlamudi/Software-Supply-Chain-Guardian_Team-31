import json
from pathlib import Path

from guardian.agents.base import BaseAgent
from guardian.core.models import GuardianState


class ReportAgent(BaseAgent):
    name = "report"

    def run(self, state: GuardianState) -> GuardianState:
        state.coverage["report"] = "generated"
        return state

    def write_json(self, state: GuardianState, output_path: str | Path) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state.to_dict(), indent=2, sort_keys=True))
        return path

    def write_sarif(self, state: GuardianState, output_path: str | Path) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        results = []
        for finding in sorted(state.findings.values(), key=lambda item: item.score, reverse=True):
            results.append({
                "ruleId": finding.type,
                "level": "error" if finding.score >= 7 else "warning",
                "message": {"text": f"{finding.type} for {finding.component_purl}"},
                "properties": {
                    "score": finding.score,
                    "confidence": finding.confidence,
                },
            })
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "Software Supply Chain Guardian", "rules": []}},
                "results": results,
            }],
        }
        path.write_text(json.dumps(sarif, indent=2))
        return path

    def write_vex(self, state: GuardianState, output_path: str | Path) -> Path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        vulnerabilities = []
        for finding in state.findings.values():
            vulnerabilities.append({
                "bom-ref": finding.component_purl,
                "id": finding.id,
                "analysis": {
                    "state": "exploitable" if finding.status == "open" else finding.status,
                    "detail": finding.recommendation.get("severity", finding.type),
                },
            })
        vex = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "vulnerabilities": vulnerabilities,
        }
        path.write_text(json.dumps(vex, indent=2, sort_keys=True))
        return path
