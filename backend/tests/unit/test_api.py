import json

from sentinel.api.handler import handler, regressions, repository


def test_post_run_returns_report_and_populates_regressions():
    response = handler({"httpMethod": "POST", "path": "/runs"})
    body = json.loads(response["body"])

    assert response["statusCode"] == 202
    assert body["report"]["decision"] == "BLOCK"
    assert body["report"]["retest"]["status"] == "PASSED"
    assert repository.get(body["run_id"]) is not None
    assert regressions.list()


def test_get_unknown_run_returns_not_found():
    response = handler({"httpMethod": "GET", "path": "/runs/not-real"})

    assert response["statusCode"] == 404


def test_get_regressions_returns_json():
    response = handler({"httpMethod": "GET", "path": "/regressions"})

    assert response["statusCode"] == 200
    assert "cases" in json.loads(response["body"])


def test_get_events_empty_before_run():
    # Fresh repo has no events
    old_reports = repository._reports.copy()
    repository._reports.clear()
    try:
        response = handler({"httpMethod": "GET", "path": "/events"})
        body = json.loads(response["body"])
        assert response["statusCode"] == 200
        assert body["events"] == []
    finally:
        repository._reports.update(old_reports)


def test_get_events_returns_audit_after_run():
    response = handler({"httpMethod": "POST", "path": "/runs"})
    assert response["statusCode"] == 202

    response = handler({"httpMethod": "GET", "path": "/events"})
    body = json.loads(response["body"])
    assert response["statusCode"] == 200
    assert len(body["events"]) > 0
    # Each event should have required fields
    event = body["events"][0]
    assert "event_id" in event
    assert "event_type" in event
    assert "message" in event
    assert "data" in event
    assert "run_id" in event
    assert "timestamp" in event


def test_get_stats_empty_before_run():
    old_reports = repository._reports.copy()
    repository._reports.clear()
    try:
        response = handler({"httpMethod": "GET", "path": "/stats"})
        body = json.loads(response["body"])
        assert response["statusCode"] == 200
        assert body["total_runs"] == 0
        assert body["total_events"] == 0
        assert body["allowed"] == 0
        assert body["blocked"] == 0
        assert body["escalated"] == 0
    finally:
        repository._reports.update(old_reports)


def test_get_stats_after_run():
    response = handler({"httpMethod": "POST", "path": "/runs"})
    assert response["statusCode"] == 202

    response = handler({"httpMethod": "GET", "path": "/stats"})
    body = json.loads(response["body"])
    assert response["statusCode"] == 200
    assert body["total_runs"] >= 1
    assert body["total_events"] > 0
    assert body["blocked"] > 0  # canonical attack should be blocked


def test_health_returns_ok():
    response = handler({"httpMethod": "GET", "path": "/health"})
    body = json.loads(response["body"])
    assert response["statusCode"] == 200
    assert body["status"] == "healthy"
    assert "version" in body


def test_unknown_route_returns_404():
    response = handler({"httpMethod": "GET", "path": "/nonexistent"})
    assert response["statusCode"] == 404
