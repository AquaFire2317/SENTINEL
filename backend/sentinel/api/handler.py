"""API Gateway-compatible handler and local HTTP contract.

Routes (``/api`` prefix is optional and handled by the router):
    GET  /health          - Liveness probe (no auth required)
    GET  /config          - Non-secret runtime configuration
    GET  /providers       - Model provider catalogue + configuration status
    GET  /agents          - Guarded agent(s) and their live provider/model
    GET  /tools           - Registered tool catalogue
    GET  /policies        - Active enforcement rules
    GET  /scenarios       - Attack scenario catalogue
    GET  /scenarios/{id}  - One attack scenario
    POST /runs            - Run an evaluation workflow (optional scenario_id)
    GET  /runs            - List completed runs
    GET  /runs/{run_id}   - Retrieve a completed report
    GET  /regressions     - List recorded regression cases
    GET  /events          - All security events across all runs
    GET  /stats           - Aggregate security metrics
"""

from __future__ import annotations

import json
import threading
from typing import Any

from sentinel.api.catalog import (
    agent_catalog,
    config_catalog,
    policy_catalog,
    tool_catalog,
)
from sentinel.contracts.workflow import AttackScenario
from sentinel.evaluation.loader import (
    ScenarioNotFoundError,
    list_scenario_catalog,
    load_scenario,
    load_scenario_raw,
)
from sentinel.evaluation.regression import RegressionSuite
from sentinel.evaluation.workflow import CANONICAL_SCENARIO, EvaluationWorkflow
from sentinel.persistence.factory import build_report_repository

API_VERSION = "0.3.0"

repository = build_report_repository()
regressions = RegressionSuite()
_lock = threading.RLock()


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Handle the REST routes without requiring a web framework."""
    from sentinel.api.router import (
        json_body,
        normalize_path,
        request_method,
    )

    method = request_method(event)
    path = normalize_path(event)

    if method == "GET" and path == "/health":
        return _response(200, {"status": "healthy", "version": API_VERSION})

    if method == "GET" and path == "/config":
        return _response(200, config_catalog())

    if method == "GET" and path == "/providers":
        from sentinel.integrations.providers import list_providers

        return _response(200, {"providers": list_providers()})

    if method == "GET" and path == "/agents":
        return _response(200, {"agents": agent_catalog()})

    if method == "GET" and path == "/tools":
        return _response(200, {"tools": tool_catalog(_tool_call_counts())})

    if method == "GET" and path == "/policies":
        return _response(200, {"policies": policy_catalog()})

    if method == "GET" and path == "/scenarios":
        return _response(200, {"scenarios": list_scenario_catalog()})

    if method == "GET" and path.startswith("/scenarios/"):
        scenario_id = path.split("/", 2)[-1]
        try:
            scenario = load_scenario_raw(scenario_id)
        except ScenarioNotFoundError as error:
            return _response(404, {"error": str(error)})
        return _response(200, scenario)

    if method == "POST" and path == "/runs":
        return _create_run(json_body(event))

    if method == "GET" and path == "/runs":
        return _response(200, {"runs": _run_summaries()})

    if method == "GET" and path.startswith("/runs/"):
        run_id = path.rsplit("/", 1)[-1]
        if not run_id:
            return _response(400, {"error": "Invalid run_id"})
        report = repository.get(run_id)
        return (
            _response(200, report.model_dump(mode="json"))
            if report
            else _response(404, {"error": "run not found"})
        )

    if method == "GET" and path == "/regressions":
        with _lock:
            cases = [case.model_dump(mode="json") for case in regressions.list()]
        return _response(200, {"cases": cases})

    if method == "GET" and path == "/events":
        return _response(200, {"events": _all_events()})

    if method == "GET" and path == "/stats":
        return _response(200, _stats())

    return _response(404, {"error": "route not found"})


def _create_run(body: dict[str, Any]) -> dict[str, Any]:
    scenario_id = body.get("scenario_id") if isinstance(body, dict) else None
    scenario: AttackScenario
    if scenario_id:
        try:
            scenario = load_scenario(str(scenario_id))
        except ScenarioNotFoundError as error:
            return _response(404, {"error": str(error)})
        except ValueError as error:
            return _response(422, {"error": f"Invalid scenario: {error}"})
    else:
        scenario = CANONICAL_SCENARIO

    try:
        report = EvaluationWorkflow().run(scenario)
    except Exception as error:  # noqa: BLE001 - API-level error handling
        return _response(500, {"error": f"Workflow failed: {type(error).__name__}: {error}"})

    with _lock:
        repository.save(report)
        regressions.add_from_report(report, scenario)
    return _response(
        202,
        {
            "run_id": report.run_id,
            "status": "COMPLETED",
            "report": report.model_dump(mode="json"),
        },
    )


def _reports() -> list[Any]:
    return repository.list()


def _run_summaries() -> list[dict[str, Any]]:
    reports = _reports()
    reports = sorted(reports, key=lambda r: r.run_id, reverse=True)
    return [
        {
            "run_id": report.run_id,
            "scenario_id": report.scenario_id,
            "decision": report.decision,
            "risk_score": report.risk_score,
            "risk_level": report.risk_level,
            "attack_detected": report.attack_detected,
            "regression_added": report.regression_added,
            "security_score": report.security_score,
        }
        for report in reports
    ]


def _all_events() -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for report in _reports():
        for audit_event in report.audit:
            events.append(
                {
                    "event_id": audit_event.event_id,
                    "event_type": audit_event.event_type,
                    "message": audit_event.message,
                    "data": audit_event.data,
                    "run_id": audit_event.run_id,
                    "timestamp": audit_event.timestamp,
                }
            )
    return events


def _decision_events() -> list[Any]:
    return [
        event
        for report in _reports()
        for event in report.audit
        if event.event_type == "DECISION"
    ]


def _tool_call_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for name in ("search_suppliers", "get_supplier_details", "compare_prices",
                 "create_purchase_order", "send_email"):
        counts[name] = 0
    for event in _decision_events():
        message = event.message
        for name in counts:
            if name in message:
                counts[name] += 1
    return counts


def _stats() -> dict[str, Any]:
    reports = _reports()
    total_events = 0
    allowed = blocked = escalated = high_risk = 0
    decisions: dict[str, int] = {}
    for event in _decision_events():
        total_events += 1
        decision = str(event.data.get("decision", ""))
        decisions[decision] = decisions.get(decision, 0) + 1
        risk = event.data.get("risk", {})
        score = risk.get("score", 0) if isinstance(risk, dict) else 0
        if decision == "ALLOW":
            allowed += 1
        elif decision == "BLOCK":
            blocked += 1
        elif decision == "ESCALATE":
            escalated += 1
        if isinstance(score, int) and score >= 75:
            high_risk += 1
    return {
        "total_runs": len(reports),
        "total_events": total_events,
        "allowed": allowed,
        "blocked": blocked,
        "escalated": escalated,
        "high_risk": high_risk,
        "decisions": decisions,
    }


def _response(status_code: int, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"content-type": "application/json"},
        "body": json.dumps(body, default=str),
    }
