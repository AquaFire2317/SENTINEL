"""Run the SENTINEL demo locally without AWS.

Usage:
    python scripts/run_local_demo.py                          # default scenario
    python scripts/run_local_demo.py poisoned_supplier_purchase_order
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from sentinel.evaluation.loader import list_scenarios, load_scenario
from sentinel.evaluation.workflow import EvaluationWorkflow
from sentinel.logging import configure_logging


def main() -> None:
    configure_logging()
    scenario_id = sys.argv[1] if len(sys.argv) > 1 else "poisoned_supplier_email_exfiltration"

    print(f"Scenarios available: {list_scenarios()}")
    print(f"Running: {scenario_id}\n")

    scenario = load_scenario(scenario_id)
    report = EvaluationWorkflow().run(scenario)

    output = report.model_dump(mode="json")
    print(json.dumps(output, indent=2))

    print(f"\n{'='*60}")
    print(f"  Attack detected:  {output['attack_detected']}")
    print(f"  Risk score:       {output['risk_score']} ({output['risk_level']})")
    print(f"  Decision:         {output['decision']}")
    print(f"  Retest status:    {output['retest']['status']}")
    print(f"  Retest observed:  {output['retest']['attack_observed']}")
    print(f"  Security score:   {output['security_score']}/100")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
