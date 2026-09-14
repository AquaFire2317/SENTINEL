"""AWS Lambda worker that runs one SENTINEL evaluation.

Invoked by the Step Functions state machine (or directly). Input is a JSON
object with an optional ``scenario_id``. Output is the serialized evaluation
report, and the run's security audit is persisted to DynamoDB when configured.
"""

from __future__ import annotations

from typing import Any

from sentinel.api.handler import regressions, repository
from sentinel.evaluation.loader import ScenarioNotFoundError, load_scenario
from sentinel.evaluation.workflow import CANONICAL_SCENARIO, EvaluationWorkflow


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    scenario_id = (event or {}).get("scenario_id")
    if scenario_id:
        try:
            scenario = load_scenario(str(scenario_id))
        except ScenarioNotFoundError as error:
            return {"status": "ERROR", "error": str(error)}
    else:
        scenario = CANONICAL_SCENARIO

    report = EvaluationWorkflow().run(scenario)
    repository.save(report)
    regressions.add_from_report(report, scenario)

    # Persist the durable security audit when the repository supports it.
    save_audit = getattr(repository, "save_security_audit", None)
    if callable(save_audit):
        try:
            save_audit(report.run_id, report.audit)
        except Exception:
            import logging

            logging.getLogger("sentinel.worker").exception("Failed to persist audit trail")

    return {
        "status": "COMPLETED",
        "run_id": report.run_id,
        "scenario_id": report.scenario_id,
        "decision": report.decision,
        "risk_score": report.risk_score,
        "security_score": report.security_score,
        "regression_added": report.regression_added,
        "report": report.model_dump(mode="json"),
    }
