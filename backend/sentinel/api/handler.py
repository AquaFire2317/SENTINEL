"""Minimal API Gateway-compatible handler and local HTTP contract."""

import json
from typing import Any

from sentinel.evaluation.regression import RegressionSuite
from sentinel.evaluation.workflow import CANONICAL_SCENARIO, EvaluationWorkflow
from sentinel.persistence.memory import ReportRepository

repository = ReportRepository()
regressions = RegressionSuite()


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Handle the MVP REST routes without requiring a web framework."""

    method = event.get("requestContext", {}).get("http", {}).get("method", event.get("httpMethod", "GET"))
    path = event.get("rawPath", event.get("path", "/"))
    if method == "POST" and path == "/runs":
        report = EvaluationWorkflow().run(CANONICAL_SCENARIO)
        repository.save(report)
        regressions.add_from_report(report, CANONICAL_SCENARIO)
        return _response(202, {"run_id": report.run_id, "status": "COMPLETED", "report": report.model_dump(mode="json")})
    if method == "GET" and path.startswith("/runs/"):
        report = repository.get(path.rsplit("/", 1)[-1])
        return _response(200, report.model_dump(mode="json")) if report else _response(404, {"error": "run not found"})
    if method == "GET" and path == "/regressions":
        return _response(200, {"cases": [case.model_dump(mode="json") for case in regressions.list()]})
    return _response(404, {"error": "route not found"})


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body),
    }
