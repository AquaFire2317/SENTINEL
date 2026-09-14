"""Tests for the read-only API endpoints and /api prefix routing."""

import json

from sentinel.api.handler import handler
from sentinel.api.router import normalize_path


def _get(path):
    return handler({"httpMethod": "GET", "path": path})


def _post(path, body):
    return handler({"httpMethod": "POST", "path": path, "body": json.dumps(body)})


def test_default_api_base_is_importable_and_threaded():
    # The server is a ThreadingHTTPServer; importing it must not bind a port.
    from sentinel.dev_server import SentinelHandler, SPAHandler

    assert SPAHandler.serve_frontend is True
    assert SentinelHandler.serve_frontend is False


def test_normalize_path_strips_api_prefix_and_trailing_slash():
    assert normalize_path({"path": "/api/health"}) == "/health"
    assert normalize_path({"path": "/api"}) == "/"
    assert normalize_path({"path": "/runs/"}) == "/runs"
    assert normalize_path({"rawPath": "/api/scenarios/x", "path": "/ignored"}) == "/scenarios/x"


def test_health_accepts_api_prefix():
    response = _get("/api/health")
    assert response["statusCode"] == 200


def test_read_endpoints_return_expected_shapes():
    assert "providers" in json.loads(_get("/api/providers")["body"])
    assert "tools" in json.loads(_get("/api/tools")["body"])
    assert "policies" in json.loads(_get("/api/policies")["body"])
    assert "agents" in json.loads(_get("/api/agents")["body"])
    assert "scenarios" in json.loads(_get("/api/scenarios")["body"])
    config = json.loads(_get("/api/config")["body"])
    assert config["model"]["provider"] == "local"
    assert config["policy_version"]


def test_tools_endpoint_lists_allowlisted_tools():
    tools = json.loads(_get("/api/tools")["body"])["tools"]
    names = {tool["name"] for tool in tools}
    assert {"send_email", "create_purchase_order"} <= names
    assert all(tool["status"] == "protected" for tool in tools)


def test_scenarios_catalog_includes_metadata():
    scenarios = json.loads(_get("/api/scenarios")["body"])["scenarios"]
    ids = {s["scenario_id"] for s in scenarios}
    assert "poisoned_supplier_email_exfiltration" in ids
    entry = next(s for s in scenarios if s["scenario_id"] == "poisoned_supplier_email_exfiltration")
    assert entry["description"]
    assert entry["expected_result"]


def test_run_honours_scenario_id():
    response = _post(
        "/api/runs", {"scenario_id": "poisoned_supplier_purchase_order"}
    )
    assert response["statusCode"] == 202
    report = json.loads(response["body"])["report"]
    assert report["scenario_id"] == "poisoned_supplier_purchase_order"


def test_run_with_unknown_scenario_returns_404():
    response = _post("/api/runs", {"scenario_id": "does-not-exist"})
    assert response["statusCode"] == 404


def test_run_without_scenario_uses_canonical():
    response = _post("/api/runs", {})
    assert response["statusCode"] == 202
    report = json.loads(response["body"])["report"]
    assert report["scenario_id"] == "poisoned_supplier_email_exfiltration"


def test_runs_list_and_detail_roundtrip():
    created = json.loads(_post("/api/runs", {})["body"])
    run_id = created["run_id"]

    listing = json.loads(_get("/api/runs")["body"])["runs"]
    assert any(run["run_id"] == run_id for run in listing)

    detail = _get(f"/api/runs/{run_id}")
    assert detail["statusCode"] == 200
    assert json.loads(detail["body"])["run_id"] == run_id


def test_scenario_detail_endpoint():
    response = _get("/api/scenarios/poisoned_supplier_email_exfiltration")
    assert response["statusCode"] == 200
    assert json.loads(response["body"])["scenario_id"] == "poisoned_supplier_email_exfiltration"


def test_scenario_detail_unknown_returns_404():
    assert _get("/api/scenarios/nope")["statusCode"] == 404
