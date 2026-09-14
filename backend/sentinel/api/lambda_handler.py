"""AWS Lambda entry point for the SENTINEL HTTP API.

API Gateway (both REST v1 and HTTP API v2) events are normalized by
:func:`sentinel.api.router.dispatch`, so this is a thin adapter.
"""

from __future__ import annotations

from typing import Any


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    from sentinel.api.router import dispatch

    return dispatch(event, context)
