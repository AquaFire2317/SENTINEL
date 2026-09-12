"""Command-line demo entry point."""

import json
import sys

from sentinel.evaluation.loader import load_scenario
from sentinel.evaluation.workflow import EvaluationWorkflow
from sentinel.logging import configure_logging


def main() -> None:
    configure_logging()
    scenario_id = sys.argv[1] if len(sys.argv) > 1 else "poisoned_supplier_email_exfiltration"
    scenario = load_scenario(scenario_id)
    report = EvaluationWorkflow().run(scenario)
    print(json.dumps(report.model_dump(mode="json"), indent=2))


if __name__ == "__main__":
    main()
