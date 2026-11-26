"""Alerts, scoped responses, inbound security signals and the overview (spec/API.md section 8)."""

from __future__ import annotations

import json
import time
from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Request
from pydantic import Field

from qg.api.common import page_params, paginate
from qg.clock import fmt, parse
from qg.crypto.encoding import EncodingError, parse_strict
from qg.errors import QGError
from qg.gateway.http import Ctx, Strict, authorize, body_openapi, core_of, gateway, json_body, live
from qg.ids import is_id, new_id
from qg.incidents import service

router = APIRouter(prefix="/api/v1", tags=["alerts"])

CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
EVENT_TYPES = {
    CAEP + "session-revoked": "session_revoked",
    CAEP + "credential-change": "credential_change",
    CAEP + "device-compliance-change": "device_compliance",
    "urn:qg:event-type:privilege-observed": "privilege_observed",
}


def _alert_or_404(core, conn, alert_id: str) -> dict[str, Any]:  # noqa: ANN001
    view = core.alert_view(conn, alert_id) if is_id(alert_id, "alr") else None
    if view is None:
        raise QGError("QG_NOT_FOUND", "not_found")
    return view


@router.get("/alerts")
def list_alerts(request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    limit, before = page_params(request)
    st, rule = request.query_params.get("status"), request.query_params.get("rule_id")
    if st is not None and st not in ("open", "acknowledged"):
        raise QGError("QG_INVALID_INPUT", "bad_status")
    if rule is not None and (len(rule) != 7 or not rule.startswith("QG-R")):
        raise QGError("QG_INVALID_INPUT", "bad_rule")
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "alert.list")
        ids = [r[0] for r in conn.execute(
            "SELECT id FROM alerts WHERE (? IS NULL OR status = ?) AND (? IS NULL OR rule_id = ?) ORDER BY ts DESC, id",
            (st, st, rule, rule))]
        items = [core.alert_view(conn, i) for i in ids]
    return paginate(items, "id", limit, before)


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: str, request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "alert.read")
        view = _alert_or_404(core, conn, alert_id)
        view["receipts"] = [json.loads(r[0]) for rid in view["explanation"]["receipt_ids"]
                            for r in conn.execute("SELECT leaf FROM receipts WHERE id = ?", (rid,))]
        extra = conn.execute("SELECT extra FROM alerts WHERE id = ?", (alert_id,)).fetchone()[0]
        if view["rule_id"] == "QG-R007":
            view["path"] = (json.loads(extra) if extra else {}).get("path", [])
    return view


class Ack(Strict):
    note: Annotated[str, Field(max_length=500)] | None = None


@router.post("/alerts/{alert_id}/ack", openapi_extra=body_openapi(Ack))
def ack_alert(alert_id: str, request: Request, ctx: Ctx = gateway("alert.ack"), body: Ack = json_body(Ack)) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        d = authorize(core, conn, ctx, "alert.ack", receipt_action="alert.ack", resource=alert_id)
        view = _alert_or_404(core, conn, alert_id)
        if view["status"] == "acknowledged":
            raise QGError("QG_CONFLICT", "already_acknowledged")
        conn.execute("UPDATE alerts SET status = 'acknowledged', acknowledged_by = ? WHERE id = ?",
                     (ctx.user_id, alert_id))
        r = view["response"]
        if r and r["action"] == "freeze_key_release" and r["lifted_at"] is None:
            core.lift_response(conn, r["id"], ctx.user_id, body.note or "acknowledged")
        rc = core.receipt(conn, action="alert.ack", decision="allow", reason="acknowledged", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=alert_id, matched=d.matched_rules)
        out = core.alert_view(conn, alert_id)
    ctx.set_receipt(rc["id"])
    return out


class Lift(Strict):
    reason: Annotated[str, Field(min_length=1, max_length=500)]


@router.post("/responses/{response_id}/lift", openapi_extra=body_openapi(Lift))
def lift_response(response_id: str, request: Request, ctx: Ctx = gateway("response.lift"),
                  body: Lift = json_body(Lift)) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        row = conn.execute("SELECT * FROM responses WHERE id = ?", (response_id,)).fetchone() if is_id(
            response_id, "rsp") else None
        if row is None:
            raise QGError("QG_NOT_FOUND", "not_found")
        contained = contained_user(conn, row["scope_kind"], row["scope_id"])
        facts = {"self_lift": contained is not None and contained == ctx.user_id,
                 "contained_operator": contained is not None and "operator" in core.directory.roles(conn, contained)}
        try:
            d = authorize(core, conn, ctx, "response.lift", facts, receipt_action="response.lift", resource=response_id)
        except QGError as exc:
            if facts["self_lift"] and exc.code == "QG_DENY_POLICY":
                raise QGError("QG_DENY_POLICY", "self_lift", receipt_id=exc.receipt_id) from exc
            raise
        if row["lifted_at"] is not None:
            raise QGError("QG_CONFLICT", "already_lifted")
        core.lift_response(conn, response_id, ctx.user_id, body.reason)
        rc = core.receipt(conn, action="response.lift", decision="allow", reason="lifted", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=response_id, matched=d.matched_rules)
        out = core.alert_view(conn, row["alert_id"])
    ctx.set_receipt(rc["id"])
    return out


def contained_user(conn, scope_kind: str, scope_id: str | None) -> str | None:  # noqa: ANN001
    """The person an automatic response contains, if any (M4: they may not lift it themselves)."""
    if scope_id is None:
        return None
    if scope_kind == "identity":
        return scope_id
    if scope_kind == "device":
        row = conn.execute("SELECT user_id FROM devices WHERE device_id = ?", (scope_id,)).fetchone()
        return row[0] if row else None
    if scope_kind == "session":
        row = conn.execute("SELECT user_id FROM sessions WHERE session_id = ? UNION SELECT user_id FROM ended_sessions"
                           " WHERE session_id = ?", (scope_id, scope_id)).fetchone()
        return row[0] if row else None
    return None


# ---- signals -------------------------------------------------------------------------------------


def _parse_signal(raw: bytes) -> dict[str, Any]:
    try:
        body = parse_strict(raw)
    except (EncodingError, UnicodeDecodeError) as exc:
        raise QGError("QG_INVALID_INPUT", "invalid_json") from exc
    if not isinstance(body, dict) or set(body) != {"iss", "jti", "iat", "aud", "events"}:
        raise QGError("QG_INVALID_INPUT", "bad_set")
    if not (isinstance(body["iss"], str) and 0 < len(body["iss"]) <= 200 and isinstance(body["jti"], str)
            and 0 < len(body["jti"]) <= 128 and isinstance(body["iat"], int) and body["aud"] == "quantumguard"
            and isinstance(body["events"], dict) and len(body["events"]) == 1):
        raise QGError("QG_INVALID_INPUT", "bad_set")
    (etype, ev), = body["events"].items()
    if etype not in EVENT_TYPES or not isinstance(ev, dict):
        raise QGError("QG_INVALID_INPUT", "unknown_event_type")
    subj = ev.get("subject")
    if not isinstance(subj, dict) or subj.get("format") != "opaque" or not isinstance(subj.get("id"), str):
        raise QGError("QG_INVALID_INPUT", "bad_subject")
    if not isinstance(ev.get("event_timestamp"), int):
        raise QGError("QG_INVALID_INPUT", "bad_event_timestamp")
    kind = EVENT_TYPES[etype]
    allowed = {"subject", "event_timestamp", "reason_admin", "reason_user", "initiating_entity"}
    if kind == "credential_change":
        allowed |= {"credential_type", "change_type"}
        if ev.get("credential_type") != "device" or ev.get("change_type") != "revoke":
            raise QGError("QG_INVALID_INPUT", "unsupported_change")
    elif kind == "device_compliance":
        allowed |= {"previous_status", "current_status"}
        if ev.get("current_status") not in ("compliant", "not-compliant"):
            raise QGError("QG_INVALID_INPUT", "bad_status")
    elif kind == "privilege_observed":
        allowed |= {"role"}
        if ev.get("role") not in ("admin", "operator", "auditor", "employee"):
            raise QGError("QG_INVALID_INPUT", "bad_role")
    if set(ev) - allowed:
        raise QGError("QG_INVALID_INPUT", "unknown_field")
    return {"body": body, "type": etype, "kind": kind, "event": ev, "subject_id": subj["id"]}


@router.post("/signals", openapi_extra={"requestBody": {"required": True, "content": {"application/json": {
    "schema": {"type": "object", "description": "Security Event Token claims (spec/SUITE.md section 14)"}}}}})
def post_signal(request: Request, ctx: Ctx = gateway("signal.receive")) -> dict:
    started = time.monotonic()
    core = core_of(request)
    sig = _parse_signal(ctx.body)
    ev, kind, subject_id = sig["event"], sig["kind"], sig["subject_id"]
    with core.db.tx() as conn:
        live(core, conn, ctx)
        d = authorize(core, conn, ctx, "signal.send", receipt_action="signal.receive")
        dup = conn.execute("SELECT id FROM signals WHERE jti = ?", (sig["body"]["jti"],)).fetchone()
        if dup is not None:
            return {"signal_id": dup[0], "accepted": True, "duplicate": True}
        is_dev, is_user = is_id(subject_id, "dev"), is_id(subject_id, "usr")
        dev = conn.execute("SELECT * FROM devices WHERE device_id = ?", (subject_id,)).fetchone() if is_dev else None
        user = conn.execute("SELECT * FROM users WHERE user_id = ?", (subject_id,)).fetchone() if is_user else None
        if dev is None and user is None:
            raise QGError("QG_NOT_FOUND", "not_found")
        if kind in ("credential_change", "device_compliance") and dev is None:
            raise QGError("QG_INVALID_INPUT", "subject_must_be_device")
        if kind == "privilege_observed" and user is None:
            raise QGError("QG_INVALID_INPUT", "subject_must_be_user")
        newest = conn.execute("SELECT MAX(event_ts) FROM signals WHERE subject_id = ? AND event_type = ? AND applied = 1",
                              (subject_id, sig["type"])).fetchone()[0]
        apply = newest is None or ev["event_timestamp"] >= newest
        signal_id = new_id("sig")
        rc = core.receipt(conn, action="signal.receive", decision="allow", reason="applied" if apply else "out_of_order",
                          subject=ctx.subject, request_hash=ctx.request_hash, resource=subject_id,
                          matched=d.matched_rules)
        conn.execute("INSERT INTO signals (id, jti, iss, event_type, subject_id, event_ts, received_at, applied, body)"
                     " VALUES (?,?,?,?,?,?,?,?,?)",
                     (signal_id, sig["body"]["jti"], sig["body"]["iss"], sig["type"], subject_id, ev["event_timestamp"],
                      core.clock.iso(), int(apply), json.dumps(sig["body"])))
        if apply:
            if kind == "session_revoked":
                where, val = ("device_id = ?", subject_id) if dev is not None else ("user_id = ?", subject_id)
                core.end_sessions(conn, where=where, params=(val,), reason="signal")
            elif kind == "credential_change" and dev["status"] != "revoked":
                cpt = fmt(min(parse(fmt(_ts(ev["event_timestamp"]))), core.clock.now()))
                service.revoke(core, conn, device_id=subject_id, compromise_time=cpt, reported_by=ctx.user_id,
                               note=str(ev.get("reason_admin", "credential-change signal"))[:500], via="signal",
                               subject=ctx.subject, request_hash=ctx.request_hash, started=started)
            elif kind == "device_compliance":
                bad = ev["current_status"] == "not-compliant"
                frm, to = ("active", "quarantined") if bad else ("quarantined", "active")
                if conn.execute("UPDATE devices SET status = ? WHERE device_id = ? AND status = ?",
                                (to, subject_id, frm)).rowcount:
                    if bad:
                        core.end_sessions(conn, where="device_id = ?", params=(subject_id,), reason="signal")
                        conn.execute("UPDATE leases SET cancelled = 1 WHERE device_id = ?", (subject_id,))
                    core.directory.publish(conn, "compliance_signal")
            elif kind == "privilege_observed":
                conn.execute("INSERT OR REPLACE INTO observed_roles (user_id, role, observed_at) VALUES (?,?,?)",
                             (subject_id, ev["role"], core.clock.iso()))
                core.emit(conn, "privilege_observed", {"user_id": subject_id, "device_id": None, "session_id": None},
                          [rc["id"]], role=ev["role"], source=sig["body"]["iss"])
    ctx.set_receipt(rc["id"])
    return {"signal_id": signal_id, "accepted": True, "duplicate": False}


def _ts(seconds: int):  # noqa: ANN202
    from datetime import UTC, datetime

    try:
        return datetime.fromtimestamp(seconds, UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise QGError("QG_INVALID_INPUT", "bad_event_timestamp") from exc


@router.get("/signals")
def list_signals(request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    limit, before = page_params(request)
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "signal.list")
        items = [{"signal_id": r["id"], "jti": r["jti"], "iss": r["iss"], "event_type": r["event_type"],
                  "subject_id": r["subject_id"], "event_timestamp": r["event_ts"], "received_at": r["received_at"],
                  "applied": bool(r["applied"])}
                 for r in conn.execute("SELECT * FROM signals ORDER BY received_at DESC, id LIMIT 1000")]
    return paginate(items, "signal_id", limit, before)


# ---- overview ------------------------------------------------------------------------------------


@router.get("/overview")
def overview(request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "overview.read")
        now = core.clock.now()
        since = fmt(now - timedelta(hours=24))
        buckets: dict[str, dict[str, Any]] = {}
        for r in conn.execute("SELECT substr(ts, 1, 13) AS h, decision, COUNT(*) FROM receipts WHERE ts >= ?"
                              " GROUP BY h, decision", (since,)):
            b = buckets.setdefault(r[0], {"hour": r[0] + ":00:00.000Z", "allow": 0, "deny": 0})
            b[r[1]] = r[2]
        last = conn.execute("SELECT time_to_enforce_ms FROM incidents ORDER BY reported_at DESC LIMIT 1").fetchone()
        incidents = conn.execute("SELECT * FROM incidents WHERE closed_at IS NULL").fetchall()
        return {
            "active_devices": conn.execute("SELECT COUNT(*) FROM devices WHERE status = 'active'").fetchone()[0],
            "revoked_devices": conn.execute("SELECT COUNT(*) FROM devices WHERE status = 'revoked'").fetchone()[0],
            "pending_rekeys": conn.execute("SELECT COUNT(*) FROM rekey_jobs WHERE status IN ('pending', 'in_progress')"
                                           ).fetchone()[0],
            "open_alerts": conn.execute("SELECT COUNT(*) FROM alerts WHERE status = 'open'").fetchone()[0],
            "open_incidents": len(incidents),
            "last_time_to_enforce_ms": last[0] if last else None,
            "directory_epoch": core.directory.current_epoch(conn),
            "tree_size": core.log.size,
            "decisions_by_hour": [buckets[k] for k in sorted(buckets)],
        }
