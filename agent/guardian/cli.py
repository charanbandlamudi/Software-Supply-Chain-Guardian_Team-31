import argparse
from pathlib import Path

from guardian.orchestrator import Supervisor
from guardian.agents.report import ReportAgent


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Guardian agent pipeline")
    parser.add_argument("inputs", nargs="+")
    parser.add_argument("--output", default="guardian-report.json")
    args = parser.parse_args()

    state = Supervisor().run(args.inputs)
    report_agent = ReportAgent()
    report_agent.write_json(state, args.output)
    sarif_path = Path(args.output).with_suffix(".sarif")
    report_agent.write_sarif(state, sarif_path)
    vex_path = Path(args.output).with_suffix(".vex.json")
    report_agent.write_vex(state, vex_path)
    print(f"Wrote {Path(args.output).resolve()}")


if __name__ == "__main__":
    main()
