"""Production-ready HTTP server for SENTINEL.

Serves the JSON API and, optionally, the built single-page frontend from the
same origin (so the browser's ``/api/*`` calls need no proxy).

Usage:
    python -m sentinel.dev_server                    # API only
    python -m sentinel.dev_server --serve-frontend   # API + static frontend
    python -m sentinel.dev_server --port 3000
    SENTINEL_PORT=3000 python -m sentinel.dev_server
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from sentinel.api.router import dispatch
from sentinel.config.settings import get_settings

logger = logging.getLogger("sentinel.server")

_DEFAULT_FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
_MAX_BODY_BYTES = 1_000_000


def _frontend_dist() -> Path:
    configured = get_settings().frontend_dist or os.environ.get("SENTINEL_FRONTEND_DIST")
    return Path(configured).resolve() if configured else _DEFAULT_FRONTEND_DIST


class SentinelHandler(BaseHTTPRequestHandler):
    """Routes API calls to SENTINEL handlers; serves static assets when enabled."""

    server_version = "SentinelHTTP/0.3"
    serve_frontend = False

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._send_cors_headers()
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ------------------------------------------------------------- dispatch

    def _handle(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = unquote(parsed.path)

        if (
            method == "GET"
            and self.serve_frontend
            and not _is_api_path(path)
            and self._serve_frontend(path)
        ):
            return

        start = time.monotonic()
        try:
            body = self._read_body()
            event: dict[str, Any] = {
                "httpMethod": method,
                "path": path,
                "rawPath": path,
                "body": body or None,
                "isBase64Encoded": False,
                "requestContext": {"http": {"method": method, "path": path}},
            }
            result = dispatch(event)
            self._write_response(result)
            elapsed = (time.monotonic() - start) * 1000
            logger.info("%s %s -> %s (%.0fms)", method, parsed.path,
                        result.get("statusCode", 200), elapsed)
        except Exception:
            logger.exception("Unhandled error processing %s %s", method, self.path)
            self._write_response(
                {"statusCode": 500, "body": json.dumps({"error": "Internal server error"})}
            )

    def _read_body(self) -> str:
        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            return ""
        if length <= 0:
            return ""
        if length > _MAX_BODY_BYTES:
            raise ValueError("Request body too large")
        return self.rfile.read(length).decode("utf-8", errors="replace")

    def _write_response(self, result: dict[str, Any]) -> None:
        status = int(result.get("statusCode", 200))
        raw_body = result.get("body", "{}")
        payload = raw_body.encode("utf-8") if isinstance(raw_body, str) else json.dumps(raw_body).encode()
        headers = result.get("headers", {}) or {}

        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self._send_cors_headers()
        self._send_security_headers()
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    # ------------------------------------------------------------- frontend

    def _serve_frontend(self, path: str) -> bool:
        dist = _frontend_dist()
        if not dist.is_dir():
            return False
        relative = path.lstrip("/") or "index.html"
        candidate = (dist / relative).resolve()
        if not str(candidate).startswith(str(dist)):
            return False  # path traversal attempt
        if candidate.is_file():
            self._serve_file(candidate, immutable="/assets/" in str(candidate))
            return True
        index = dist / "index.html"
        if index.is_file():
            self._serve_file(index, immutable=False)
            return True
        return False

    def _serve_file(self, path: Path, *, immutable: bool) -> None:
        try:
            content = path.read_bytes()
        except OSError:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", _content_type(path))
        self.send_header("Content-Length", str(len(content)))
        self.send_header(
            "Cache-Control",
            "public, max-age=31536000, immutable" if immutable else "no-store",
        )
        self._send_cors_headers()
        self._send_security_headers()
        self.end_headers()
        self.wfile.write(content)

    # -------------------------------------------------------------- headers

    def _cors_origin(self) -> str:
        return get_settings().cors_origin or "*"

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", self._cors_origin())
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Vary", "Origin")

    def _send_security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")

    def log_message(self, format: str, *args: Any) -> None:
        path = str(args[0]) if args else ""
        if "/assets/" in path:
            return
        logger.info(format, *args)


class SPAHandler(SentinelHandler):
    """Handler that also serves the built frontend for non-API routes."""

    serve_frontend = True


def _is_api_path(path: str) -> bool:
    if path in {
        "/api",
        "/health",
        "/config",
        "/providers",
        "/agents",
        "/tools",
        "/policies",
        "/scenarios",
        "/runs",
        "/regressions",
        "/events",
        "/stats",
        "/approvals",
    }:
        return True
    prefixes = (
        "/api/",
        "/runs/",
        "/scenarios/",
        "/approvals/",
    )
    return path.startswith(prefixes)


def _content_type(path: Path) -> str:
    return {
        ".html": "text/html; charset=utf-8",
        ".js": "application/javascript; charset=utf-8",
        ".mjs": "application/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".json": "application/json",
        ".svg": "image/svg+xml",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".webp": "image/webp",
        ".ico": "image/x-icon",
        ".woff2": "font/woff2",
        ".woff": "font/woff",
        ".map": "application/json",
        ".txt": "text/plain; charset=utf-8",
    }.get(path.suffix.lower(), "application/octet-stream")


def _resolve_port(argv: list[str]) -> int:
    settings = get_settings()
    port = settings.port
    if "--port" in argv:
        index = argv.index("--port")
        if index + 1 < len(argv):
            port = int(argv[index + 1])
    elif os.environ.get("SENTINEL_PORT"):
        port = int(os.environ["SENTINEL_PORT"])
    else:
        for token in argv:
            if token.isdigit():
                port = int(token)
                break
    return port


def main() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    argv = sys.argv[1:]
    serve_frontend = "--serve-frontend" in argv or settings.serve_frontend
    port = _resolve_port(argv)
    host = settings.host

    handler_class = SPAHandler if serve_frontend else SentinelHandler
    server = ThreadingHTTPServer((host, port), handler_class)

    logger.info("SENTINEL API server listening on http://%s:%d", host, port)
    if serve_frontend:
        dist = _frontend_dist()
        if dist.is_dir():
            logger.info("Serving frontend from %s", dist)
        else:
            logger.warning("Frontend dist not found at %s - serving API only", dist)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
