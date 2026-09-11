"""Command-line demo entry point."""

import json

from sentinel.evaluation.workflow import EvaluationWorkflow
from sentinel.logging import configure_logging


def main() -> None:
    configure_logging()
    report = EvaluationWorkflow().run()
    print(json.dumps(report.model_dump(mode="json"), indent=2))


if __name__ == "__main__":
    main()
