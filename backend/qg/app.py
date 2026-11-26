"""FastAPI wiring: security headers, limits, error mapping, routers and the optional static site."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from qg.core import Core
from qg.errors import QGError
from qg.ids import new_id
from qg.policy.engine import PolicyUnavailable
from qg.storage.db import StorageUnavailable

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; "
    "connect-src 'self'; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'"
)
SECURITY_HEADERS = [
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
]
MAX_JSON_BODY = 256 * 1024
MAX_CHUNK_BODY = 1_048_576 + 28 + 1024


class GuardMiddleware:
    """Pure ASGI: request id, security headers, QG-Receipt, body size limits, request log line."""

    def __init__(self, app: Any, core: Core) -> None:
        self.app = app
        self.core = core

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = new_id("req")
        scope.setdefault("state", {})["request_id"] = request_id
        path = scope.get("path", "")
        limit = MAX_CHUNK_BODY if "/chunks/" in path and scope.get("method") == "PUT" else MAX_JSON_BODY
        headers = dict(scope.get("headers") or [])
        tls = scope.get("scheme") == "https"
        status_holder = {"status": 0}

        async def send_wrapped(message: dict) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                hs = [(k, v) for k, v in message.get("headers", []) if k.lower() not in (b"server",)]
                hs += SECURITY_HEADERS
                hs.append((b"qg-request-id", request_id.encode()))
                rid = scope["state"].get("receipt_id")
                if rid:
                    hs.append((b"qg-receipt", rid.encode()))
                if path.startswith("/api/"):
                    hs.append((b"cache-control", b"no-store"))
                if tls:
                    hs.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                message = {**message, "headers": hs}
            await send(message)

        cl = headers.get(b"content-length")
        if cl is not None:
            try:
                too_big = int(cl) > limit
            except ValueError:
                too_big = True
            if too_big:
                await self._reject(scope, send_wrapped, request_id)
                return
        seen = 0
        overflow = False

        async def receive_limited() -> dict:
            nonlocal seen, overflow
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    overflow = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        await self.app(scope, receive_limited, send_wrapped)

    async def _reject(self, scope: dict, send: Any, request_id: str) -> None:
        err = QGError("QG_INVALID_INPUT", "body_too_large")
        body = json.dumps(err.body(request_id)).encode()
        await send({"type": "http.response.start", "status": 400,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


def _rid(request: Request) -> str:
    return request.scope.get("state", {}).get("request_id", "")


def error_response(request: Request, err: QGError) -> JSONResponse:
    if err.receipt_id is None:
        err.receipt_id = getattr(request.state, "receipt_id", None) if err.code != "QG_INVALID_INPUT" else None
    headers = {"Retry-After": str(err.retry_after)} if err.retry_after else None
    return JSONResponse(err.body(_rid(request)), status_code=err.status, headers=headers)


def create_app(core: Core) -> FastAPI:
    app = FastAPI(
        title="QuantumGuard API",
        version="1",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        swagger_ui_oauth2_redirect_url=None,
    )
    app.state.core = core

    @app.exception_handler(QGError)
    async def qg_error(request: Request, exc: QGError) -> JSONResponse:
        return error_response(request, exc)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        return error_response(request, QGError("QG_INVALID_INPUT", "invalid_field"))

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == 405:
            return error_response(request, QGError("QG_NOT_FOUND", "not_found"))
        if exc.status_code == 404:
            return error_response(request, QGError("QG_NOT_FOUND", "not_found"))
        return error_response(request, QGError("QG_INVALID_INPUT", "bad_request"))

    @app.exception_handler(PolicyUnavailable)
    async def policy_down(request: Request, exc: PolicyUnavailable) -> JSONResponse:
        return error_response(request, QGError("QG_UNAVAILABLE_FAIL_CLOSED", "policy_unavailable"))

    @app.exception_handler(StorageUnavailable)
    async def storage_down(request: Request, exc: StorageUnavailable) -> JSONResponse:
        return error_response(request, QGError("QG_UNAVAILABLE_FAIL_CLOSED", "storage_unavailable"))

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception) -> JSONResponse:
        core.log_event("unhandled_error", error=type(exc).__name__, path=request.url.path)
        return error_response(request, QGError("QG_UNAVAILABLE_FAIL_CLOSED", "internal"))

    from qg.api import routers

    for r in routers():
        app.include_router(r)

    if core.settings.web_dist is not None:
        _mount_static(app, core.settings.web_dist)
    else:
        @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
        async def fallback(path: str) -> Response:
            raise QGError("QG_NOT_FOUND", "not_found")

    app.add_middleware(GuardMiddleware, core=core)
    return app


def _mount_static(app: FastAPI, dist: Path) -> None:
    root = dist.resolve()
    index = root / "index.html"

    @app.api_route("/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
    async def static(path: str) -> Response:
        if path.startswith("api/") or path == "api" or path == "healthz":
            raise QGError("QG_NOT_FOUND", "not_found")
        target = (root / path).resolve()
        if path and target.is_file() and target.is_relative_to(root):
            return FileResponse(target)
        if index.is_file():
            return FileResponse(index, headers={"cache-control": "no-cache"})
        raise QGError("QG_NOT_FOUND", "not_found")

    @app.api_route("/{path:path}", methods=["POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
    async def other(path: str) -> Response:
        raise QGError("QG_NOT_FOUND", "not_found")
