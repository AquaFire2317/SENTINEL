"""Vercel serverless entry point for the SENTINEL API.

Exposes a WSGI (Flask) app so Vercel's Python runtime can detect it, then hands
every ``/api/*`` request to the shared :func:`sentinel.api.router.dispatch`.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from flask import Flask
from flask import Response as FlaskResponse
from flask import request

# Make the backend package importable in the Vercel build.
_backend_dir = os.path.join(os.path.dirname(__file__), "..", "backend")
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from sentinel.api.router import dispatch  # noqa: E402

app = Flask(__name__)


def _build_event(path: str, method: str, body: str | None) -> dict[str, Any]:
    return {
        "httpMethod": method,
        "path": path,
        "rawPath": path,
        "body": body,
        "isBase64Encoded": False,
        "requestContext": {"http": {"method": method, "path": path}},
    }


@app.after_request
def _add_headers(response: FlaskResponse) -> FlaskResponse:
    try:
        from sentinel.config.settings import get_settings

        origin = get_settings().cors_origin or "*"
    except Exception:  # noqa: BLE001 - never break responses over config
        origin = "*"
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/<path:path>", methods=["GET", "POST", "OPTIONS"])
@app.route("/api", defaults={"path": ""}, methods=["GET", "POST", "OPTIONS"])
def catch_all(path: str) -> FlaskResponse:
    method = request.method
    if method == "OPTIONS":
        return FlaskResponse(status=204)

    full_path = request.path or "/"
    raw = request.get_data(as_text=True) or None
    event = _build_event(full_path, method, raw)

    result = dispatch(event)
    status = int(result.get("statusCode", 200))
    body = result.get("body", "{}")
    content_type = (result.get("headers") or {}).get("content-type", "application/json")
    if not isinstance(body, str):
        import json

        body = json.dumps(body)
    return FlaskResponse(response=body, status=status, content_type=content_type)
