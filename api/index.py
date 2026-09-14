"""Vercel serverless function: SENTINEL API.

Zero-dependency WSGI app using only stdlib. No Flask needed.
Dispatches /api/* routes to the existing SENTINEL backend handlers.
"""

import json
import os
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Bootstrap backend imports
# ---------------------------------------------------------------------------
_backend_dir = os.path.join(os.path.dirname(__file__), "..", "backend")
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from sentinel.api.approval_handler import approval_handler
from sentinel.api.handler import handler as api_handler

# ---------------------------------------------------------------------------
# WSGI helpers
# ---------------------------------------------------------------------------

_CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Cache-Control": "no-store",
}


def _json_response(
    environ: dict[str, Any],
    start_response: Any,
    status: str,
    body: dict[str, Any],
) -> list[bytes]:
    payload = json.dumps(body).encode()
    headers = list(_CORS_HEADERS.items()) + [
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(payload))),
    ]
    start_response(status, headers)
    return [payload]


def _route(path: str, method: str, body_text: str | None) -> dict[str, Any]:
    event: dict[str, Any] = {
        "httpMethod": method,
        "path": path,
        "rawPath": path,
        "body": body_text,
        "requestContext": {"http": {"method": method}},
    }
    if path.startswith("/approvals"):
        return approval_handler(event)
    return api_handler(event)


# ---------------------------------------------------------------------------
# WSGI application (Vercel auto-detects this callable)
# ---------------------------------------------------------------------------

def application(environ: dict[str, Any], start_response: Any) -> list[bytes]:
    method = environ.get("REQUEST_METHOD", "GET")
    raw_path = environ.get("PATH_INFO", "/")

    if method == "OPTIONS":
        return _json_response(environ, start_response, "204 No Content", {})

    # Read request body
    content_length = int(environ.get("CONTENT_LENGTH") or 0)
    body_text = environ["wsgi.input"].read(content_length).decode() if content_length else None

    # Route — strip /api prefix if present
    path = raw_path
    if path.startswith("/api"):
        path = path[4:] or "/"

    result = _route(path, method, body_text)
    status_code = result.get("statusCode", 200)
    body_str = result.get("body", "{}")

    status_map = {200: "200 OK", 201: "201 Created", 400: "400 Bad Request", 404: "404 Not Found"}
    status = status_map.get(status_code, f"{status_code} Unknown")

    payload = body_str.encode()
    headers = list(_CORS_HEADERS.items()) + [
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(payload))),
    ]
    start_response(status, headers)
    return [payload]


# Vercel also looks for "app" as the WSGI entry point
app = application
