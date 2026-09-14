"""Unified request router shared by the local server, Vercel, and Lambda.

All three entry points speak slightly different shapes:

- The local ``HTTPServer`` passes ``{"httpMethod", "path", "body"}``.
- API Gateway (REST) uses ``httpMethod``/``path``.
- API Gateway (HTTP API) and Vercel use ``requestContext.http.method`` plus
  ``rawPath``.

They also disagree on whether the ``/api`` prefix is present. Normalizing that
here means one handler implementation serves every deployment target.
"""

from __future__ import annotations

import json
from typing import Any


def normalize_path(event: dict[str, Any]) -> str:
    """Return the route path with any ``/api`` prefix and trailing slash removed."""
    path = (
        event.get("rawPath")
        or event.get("path")
        or event.get("requestContext", {}).get("http", {}).get("path")
        or "/"
    )
    path = str(path).split("?", 1)[0]
    if path == "/api":
        path = "/"
    elif path.startswith("/api/"):
        path = path[len("/api") :]
    if len(path) > 1:
        path = path.rstrip("/")
    return path or "/"


def request_method(event: dict[str, Any]) -> str:
    """Return the upper-cased HTTP method for any supported event shape."""
    method = (
        event.get("httpMethod")
        or event.get("requestContext", {}).get("http", {}).get("method")
        or "GET"
    )
    return str(method).upper()


def request_body(event: dict[str, Any]) -> str | None:
    """Return the raw request body as text, if any."""
    body = event.get("body")
    if body is None:
        return None
    if isinstance(body, (dict, list)):
        return json.dumps(body)
    if event.get("isBase64Encoded"):
        import base64

        try:
            return base64.b64decode(body).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
    return str(body)


def json_body(event: dict[str, Any]) -> dict[str, Any]:
    """Parse the request body as a JSON object, returning ``{}`` when absent/invalid."""
    raw = request_body(event)
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def dispatch(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    """Route an event to the approval or API handler."""
    from sentinel.api.approval_handler import approval_handler
    from sentinel.api.handler import handler as api_handler

    path = normalize_path(event)
    if path == "/approvals" or path.startswith("/approvals/"):
        return approval_handler(event, context)
    return api_handler(event, context)
