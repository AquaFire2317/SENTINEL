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
