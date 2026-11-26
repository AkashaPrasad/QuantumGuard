"""FastAPI wiring: security headers, limits, error mapping, routers and the optional static site."""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import MutableMapping
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
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
BODY_READ_TIMEOUT = 30.0  # seconds to wait for each piece of a request body
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
            try:
                message = await asyncio.wait_for(receive(), timeout=BODY_READ_TIMEOUT)
            except TimeoutError as exc:
                raise QGError("QG_INVALID_INPUT", "body_timeout") from exc
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    overflow = True
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        started = time.monotonic()
        try:
            await self.app(scope, receive_limited, send_wrapped)
        finally:
            route = scope.get("route")
            self.core.log_event(
                "request",
                request_id=request_id,
                method=scope.get("method"),
                route=getattr(route, "path", None) or ("static" if not path.startswith("/api/") else "unmatched"),
                status=status_holder["status"],
                duration_ms=round((time.monotonic() - started) * 1000, 3),
                receipt_id=scope["state"].get("receipt_id"),
            )

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
        # Routes are registered flat (each APIRoute already carries its router prefix) so the route table
        # is a plain list of APIRoute objects for OpenAPI export and route-inventory checks.
        app.router.routes.extend(r.routes)

    if core.settings.web_dist is not None:
        app.mount("/", SPAStaticFiles(directory=str(core.settings.web_dist)), name="site")

    app.add_middleware(GuardMiddleware, core=core)
    return app


class SPAStaticFiles(StaticFiles):
    """The built site at /, with index.html for client-side routes. Never answers for /api/* or /healthz."""

    async def get_response(self, path: str, scope: MutableMapping[str, Any]) -> Response:
        if path == "api" or path.startswith("api/") or path == "healthz":
            raise StarletteHTTPException(status_code=404)
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code != 404 or scope.get("method") not in ("GET", "HEAD"):
                raise
            response = await super().get_response("index.html", scope)
            response.headers["cache-control"] = "no-cache"
            return response


_production_app: FastAPI | None = None


def __getattr__(name: str) -> Any:
    """`qg.app:app` for ASGI servers (the container entrypoint): built from the environment on first use,
    with background checkpointing started. `python -m qg.server` is the equivalent command."""
    global _production_app
    if name != "app":
        raise AttributeError(name)
    if _production_app is None:
        from qg.config import Settings

        core = Core(Settings.from_env())
        core.log_event("server_start", port=core.settings.port, demo=core.settings.demo,
                       policy_bundle_hash=core.policy.hash)
        core.start_background()
        _production_app = create_app(core)
    return _production_app
