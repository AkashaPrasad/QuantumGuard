"""Gateway: every non-public route depends on `gateway(action)`. Deny by default.

Order of checks (spec/SUITE.md section 6): session -> MAC -> sequence -> device status -> automatic
responses -> rate limit -> policy availability. Handlers then call `authorize()` for the policy decision
and re-check liveness inside their own transaction with `live()`.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from fastapi import Depends, Request
from pydantic import BaseModel, ConfigDict, ValidationError
from starlette.concurrency import run_in_threadpool

from qg.clock import fmt, parse
from qg.core import Core
from qg.crypto import kdf
from qg.crypto.encoding import EncodingError, b64u_decode, parse_strict
from qg.crypto.suite import SESSION_TTL_SECONDS
from qg.crypto.transcripts import mac_input, request_hash
from qg.errors import QGError
from qg.policy.engine import Decision, PolicyUnavailable

_SEQ_RE = re.compile(r"^[1-9][0-9]{0,15}$")
MAX_SEQ = 2**53 - 1
SESSION_RATE = (20.0, 60.0)  # tokens per second, burst
THROTTLED_RATE = (0.1, 2.0)
MAX_JSON_DEPTH = 16


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_max_length=16384)


@dataclass
class Ctx:
    session_id: str
    device_id: str
    user_id: str
    roles: list[str]
    user_status: str
    request_hash: str
    method: str
    path: str
    body: bytes
    state: Any
    receipt_ids: list[str] = field(default_factory=list)

    @property
    def subject(self) -> dict[str, str | None]:
        return {"user_id": self.user_id, "device_id": self.device_id, "session_id": self.session_id}

    def set_receipt(self, receipt_id: str) -> None:
        self.receipt_ids.append(receipt_id)
        self.state.receipt_id = receipt_id


def core_of(request: Request) -> Core:
    return request.app.state.core


def raw_target(request: Request) -> str:
    raw = request.scope.get("raw_path") or request.scope["path"].encode()
    target = raw.decode("latin-1")
    qs = request.scope.get("query_string") or b""
    return target + ("?" + qs.decode("latin-1") if qs else "")


def _depth(value: Any, d: int = 0) -> int:
    if d > MAX_JSON_DEPTH:
        return d
    if isinstance(value, dict):
        return max([_depth(v, d + 1) for v in value.values()] or [d + 1])
    if isinstance(value, list):
        return max([_depth(v, d + 1) for v in value] or [d + 1])
    return d


def parse_json(body: bytes, model: type[BaseModel]) -> Any:
    try:
        obj = parse_strict(body or b"")
    except (EncodingError, UnicodeDecodeError) as exc:
        raise QGError("QG_INVALID_INPUT", "invalid_json") from exc
    if _depth(obj) > MAX_JSON_DEPTH:
        raise QGError("QG_INVALID_INPUT", "too_deep")
    if isinstance(obj, dict) and "suite" in obj and obj["suite"] != "QG-1" and "suite" in model.model_fields:
        raise QGError("QG_BAD_SUITE", "bad_suite")
    try:
        return model.model_validate_json(body)  # JSON mode: strict types, nested objects allowed
    except ValidationError as exc:
        raise QGError("QG_INVALID_INPUT", "invalid_field") from exc


def json_body(model: type[BaseModel]) -> Any:
    async def dep(request: Request) -> Any:
        raw = await request.body()
        request.state.raw_body = raw
        try:
            return parse_json(raw, model)
        except QGError as exc:
            if exc.code == "QG_BAD_SUITE":
                ctx = getattr(request.state, "ctx", None)
                subject = ctx.subject if ctx else {"user_id": None, "device_id": None, "session_id": None}
                await run_in_threadpool(core_of(request).emit_now, "bad_suite", subject, None, route=request.url.path)
            raise

    dep.__qg_body__ = model  # type: ignore[attr-defined]
    return Depends(dep)


def body_openapi(model: type[BaseModel]) -> dict[str, Any]:
    return {
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": {"$ref": f"#/components/schemas/{model.__name__}"}}},
        }
    }


# ---- authentication ----------------------------------------------------------------------------


def _deny_revoked_attempt(core: Core, request: Request, ended: sqlite3.Row, action: str | None, rh: str) -> QGError:
    """A request on a session that revocation ended: record the denied attempt (QG-R001)."""
    with core.db.tx() as conn:
        subject = {"user_id": ended["user_id"], "device_id": ended["device_id"], "session_id": ended["session_id"]}
        rc = core.receipt(conn, action=action or "access", decision="deny", reason="device_revoked", subject=subject,
                          request_hash=rh, resource=request.url.path[:200])
        receipt_id = rc["id"]
        core.record_denied_attempt(conn, ended["device_id"], receipt_id)
        core.emit(conn, "revoked_device_attempt", subject, [receipt_id])
    request.state.receipt_id = receipt_id
    return QGError("QG_DENY_REVOKED", "device_revoked", receipt_id=receipt_id)


def authenticate(core: Core, request: Request, body: bytes, receipt_action: str | None) -> Ctx:
    h = request.headers
    sid, seq_s, mac_s = h.get("qg-session"), h.get("qg-seq"), h.get("qg-mac")
    if not sid or not seq_s or not mac_s:
        raise QGError("QG_NO_SESSION", "missing_session")
    if len(sid) > 64 or not _SEQ_RE.match(seq_s) or int(seq_s) > MAX_SEQ:
        raise QGError("QG_NO_SESSION" if len(sid) > 64 else "QG_INVALID_INPUT", "bad_session_headers")
    seq = int(seq_s)
    method, path = request.method.upper(), raw_target(request)
    mi = mac_input(method, path, seq, body)
    rh = request_hash(method, path, seq, body)
    now = core.clock.now()
    fresh_end = False

    with core.db.tx() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (sid,)).fetchone()
        k_mac = core.secrets.mac(sid)
        if row is None or k_mac is None:
            ended = conn.execute("SELECT * FROM ended_sessions WHERE session_id = ?", (sid,)).fetchone()
            if ended is not None and ended["reason"] == "auto_response":
                qdev = conn.execute("SELECT status FROM devices WHERE device_id = ?", (ended["device_id"],)).fetchone()
                if qdev is not None and qdev["status"] == "quarantined":
                    raise QGError("QG_QUARANTINED", "device_quarantined")
            if ended is not None and ended["reason"] in ("revoked", "report_lost"):
                dev = conn.execute("SELECT status FROM devices WHERE device_id = ?", (ended["device_id"],)).fetchone()
                if dev is not None and dev["status"] == "revoked":
                    revoked_row = ended
                else:
                    revoked_row = None
            else:
                revoked_row = None
            if revoked_row is None:
                raise QGError("QG_NO_SESSION", "unknown_session")
        else:
            revoked_row = None
            idle_deadline = parse(row["last_used_at"]) + timedelta(seconds=SESSION_TTL_SECONDS)
            if now >= idle_deadline or now >= parse(row["hard_expires_at"]):
                core.end_sessions(conn, where="session_id = ?", params=(sid,), reason="expired")
                expired = True
            else:
                expired = False
    if revoked_row is not None:
        raise _deny_revoked_attempt(core, request, revoked_row, receipt_action, rh)
    if expired:
        raise QGError("QG_NO_SESSION", "session_expired")

    try:
        tag = b64u_decode(mac_s, length=48)
    except EncodingError:
        tag = b""
    subject = {"user_id": row["user_id"], "device_id": row["device_id"], "session_id": sid}
    if not kdf.verify_hmac384(k_mac, mi, tag):
        core.emit_now("mac_failure", subject, kind="request_mac")
        raise QGError("QG_BAD_MAC", "bad_mac")

    with core.db.tx() as conn:
        row = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (sid,)).fetchone()
        if row is None:
            raise QGError("QG_NO_SESSION", "unknown_session")
        if seq <= row["last_seq"]:
            core.end_sessions(conn, where="session_id = ?", params=(sid,), reason="replay")
            replay = True
        else:
            replay = False
            conn.execute("UPDATE sessions SET last_seq = ?, last_used_at = ? WHERE session_id = ?",
                         (seq, fmt(now), sid))
            conn.execute("UPDATE devices SET last_seen_at = ? WHERE device_id = ?", (fmt(now), row["device_id"]))
        dev = conn.execute("SELECT status FROM devices WHERE device_id = ?", (row["device_id"],)).fetchone()
        user = conn.execute("SELECT status FROM users WHERE user_id = ?", (row["user_id"],)).fetchone()
        roles = core.directory.roles(conn, row["user_id"])
        responses = core.active_responses(conn, session_id=sid, device_id=row["device_id"], user_id=row["user_id"])
        if not replay and row["fresh_required"]:
            core.end_sessions(conn, where="session_id = ?", params=(sid,), reason="fresh_session_required")
            fresh_end = True
    if replay:
        core.emit_now("replay", subject, seq=seq, last_seq=row["last_seq"])
        raise QGError("QG_REPLAY", "replay")
    if fresh_end:
        raise QGError("QG_NO_SESSION", "fresh_session_required")
    if dev is None or dev["status"] == "revoked":
        raise QGError("QG_DENY_REVOKED", "device_revoked")

    ctx = Ctx(sid, row["device_id"], row["user_id"], roles, user["status"], rh, method, path, body, request.state)
    request.state.ctx = ctx
    throttled = False
    for r in responses:
        if r["action"] in ("quarantine_device", "end_session") and r["scope_kind"] in ("device", "session"):
            raise QGError("QG_QUARANTINED", "auto_response")
        if r["action"] == "throttle":
            throttled = True
    if dev["status"] == "quarantined":
        raise QGError("QG_QUARANTINED", "device_quarantined")
    rate, burst = THROTTLED_RATE if throttled else SESSION_RATE
    wait = core.buckets.take(f"s:{sid}", rate, burst, core.clock.monotonic())
    if wait > 0:
        raise QGError("QG_RATE_LIMITED", "throttled" if throttled else "rate_limited", retry_after=max(1, int(wait) + 1))
    if not core.policy.available():
        raise QGError("QG_UNAVAILABLE_FAIL_CLOSED", "policy_unavailable")
    return ctx


async def qg_gateway(request: Request) -> Ctx:
    """The one gateway callable. Every non-public route has it in its dependency tree."""
    body = await request.body()
    action = getattr(request.state, "qg_receipt_action", None)
    return await run_in_threadpool(authenticate, core_of(request), request, body, action)


qg_gateway.__qg_gateway__ = True  # type: ignore[attr-defined]
gateway_dependency = qg_gateway


def gateway(receipt_action: str | None = None) -> Any:
    """Dependency for every non-public route. `receipt_action` names the receipt action used when a
    revoked device's attempt on this route is recorded."""

    async def qg_route_action(request: Request) -> None:
        request.state.qg_receipt_action = receipt_action

    async def qg_gateway_bound(_: None = Depends(qg_route_action), ctx: Ctx = Depends(qg_gateway)) -> Ctx:
        return ctx

    return Depends(qg_gateway_bound)


# ---- authorisation -----------------------------------------------------------------------------


def authorize(
    core: Core,
    conn: sqlite3.Connection,
    ctx: Ctx,
    action: str,
    facts: dict[str, Any] | None = None,
    *,
    receipt_action: str | None = None,
    resource: str | None = None,
    hide: bool = False,
    key_epoch: int = 0,
) -> Decision:
    """Policy decision. On deny: write a receipt when `receipt_action` is set (committed even though the
    request fails), then raise QG_NOT_FOUND when `hide` else QG_DENY_POLICY."""
    dev = conn.execute("SELECT status FROM devices WHERE device_id = ?", (ctx.device_id,)).fetchone()
    user = conn.execute("SELECT status FROM users WHERE user_id = ?", (ctx.user_id,)).fetchone()
    base = {
        "user_active": user is not None and user["status"] in ("active", "quarantined"),
        "device_active": dev is not None and dev["status"] == "active",
    }
    all_facts = {**base, **(facts or {})}
    try:
        decision = core.policy.decide(ctx.roles, action, all_facts)
    except PolicyUnavailable as exc:
        raise QGError("QG_UNAVAILABLE_FAIL_CLOSED", "policy_unavailable") from exc
    if decision.allow:
        return decision
    rid = None
    if receipt_action:
        rid = core.deny_receipt(ctx, receipt_action, "policy_denied", resource, decision.matched_rules, key_epoch)
    core.emit_now("denied", ctx.subject, [rid] if rid else [], code="QG_NOT_FOUND" if hide else "QG_DENY_POLICY",
                  action=action)
    if hide:
        raise QGError("QG_NOT_FOUND", "not_found", receipt_id=rid)
    raise QGError("QG_DENY_POLICY", "policy_denied", receipt_id=rid)


def live(core: Core, conn: sqlite3.Connection, ctx: Ctx) -> None:
    """Re-check inside the handler's transaction that the session and device are still live. Revocation
    deletes sessions in its own transaction, so after it commits this check fails."""
    row = conn.execute(
        "SELECT d.status FROM sessions s JOIN devices d ON d.device_id = s.device_id WHERE s.session_id = ?",
        (ctx.session_id,),
    ).fetchone()
    if row is None or row[0] == "revoked":
        action = getattr(ctx.state, "qg_receipt_action", None) or "access"
        rid = core.deny_receipt(ctx, action, "device_revoked", ctx.path.split("?", 1)[0][:200])
        core.db.after_tx(lambda: core.record_denied_attempt_now(ctx.device_id, rid))
        raise QGError("QG_DENY_REVOKED", "device_revoked", receipt_id=rid)
    if row[0] == "quarantined":
        raise QGError("QG_QUARANTINED", "device_quarantined")


def not_found() -> QGError:
    return QGError("QG_NOT_FOUND", "not_found")


def receipt_header(ctx: Ctx, receipt: dict[str, Any]) -> str:
    ctx.set_receipt(receipt["id"])
    return receipt["id"]


JsonDict = dict[str, Any]
Handler = Callable[..., Any]


def dumps(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"))
