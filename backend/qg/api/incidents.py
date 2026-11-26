"""Report lost, operator revoke, incidents, exposure, proof bundle and close."""

from __future__ import annotations

import time
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Request
from pydantic import Field

from qg.api.common import page_params, paginate
from qg.api.devices import visible_device
from qg.clock import fmt, parse
from qg.errors import QGError
from qg.gateway.http import Ctx, Strict, authorize, body_openapi, core_of, gateway, json_body, live
from qg.ids import is_id
from qg.incidents import service

router = APIRouter(prefix="/api/v1", tags=["incidents"])

TimeStr = Annotated[str, Field(min_length=20, max_length=40)]


def _past_time(core, text: str) -> str:  # noqa: ANN001
    try:
        t = parse(text)
    except ValueError as exc:
        raise QGError("QG_INVALID_INPUT", "bad_time") from exc
    now = core.clock.now()
    if t > now + timedelta(seconds=60) or t < now - timedelta(days=365):
        raise QGError("QG_INVALID_INPUT", "bad_time")
    return fmt(min(t, now))


class ReportLost(Strict):
    lost_at: TimeStr
    note: Annotated[str, Field(max_length=500)] | None = None


class Revoke(Strict):
    compromise_time: TimeStr
    reason: Annotated[str, Field(min_length=1, max_length=500)]


@router.post("/devices/{device_id}/report-lost", openapi_extra=body_openapi(ReportLost))
def report_lost(device_id: str, request: Request, ctx: Ctx = gateway("device.report_lost"),
                body: ReportLost = json_body(ReportLost)) -> dict:
    started = time.monotonic()
    core = core_of(request)
    lost_at = _past_time(core, body.lost_at)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        row = visible_device(core, conn, ctx, device_id)
        authorize(core, conn, ctx, "device.report_lost", {"owner": row["user_id"] == ctx.user_id},
                  receipt_action="device.report_lost", resource=device_id, hide=row["user_id"] != ctx.user_id)
        if device_id == ctx.device_id:
            raise QGError("QG_INVALID_INPUT", "report_from_other_device")
        if row["status"] == "revoked":
            inc = conn.execute("SELECT * FROM incidents WHERE device_id = ?", (device_id,)).fetchone()
            rc = core.receipt(conn, action="device.report_lost", decision="allow", reason="already_revoked",
                              subject=ctx.subject, request_hash=ctx.request_hash, resource=device_id)
            ctx.set_receipt(rc["id"])
            return service.result_for(core, conn, inc, rc["id"])
        result = service.revoke(core, conn, device_id=device_id, compromise_time=lost_at, reported_by=ctx.user_id,
                                note=body.note or "", via="report_lost", subject=ctx.subject,
                                request_hash=ctx.request_hash, started=started)
    ctx.set_receipt(result["receipt_id"])
    core.log_event("device_revoked", incident_id=result["incident_id"], device_id=device_id,
                   time_to_enforce_ms=result["time_to_enforce_ms"])
    return result


@router.post("/devices/{device_id}/revoke", openapi_extra=body_openapi(Revoke))
def revoke_device(device_id: str, request: Request, ctx: Ctx = gateway("device.revoke"),
                  body: Revoke = json_body(Revoke)) -> dict:
    started = time.monotonic()
    core = core_of(request)
    cpt = _past_time(core, body.compromise_time)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        row = visible_device(core, conn, ctx, device_id)
        authorize(core, conn, ctx, "device.revoke", receipt_action="device.revoke", resource=device_id)
        if row["status"] == "revoked":
            inc = conn.execute("SELECT * FROM incidents WHERE device_id = ?", (device_id,)).fetchone()
            rc = core.receipt(conn, action="device.revoke", decision="allow", reason="rescoped", subject=ctx.subject,
                              request_hash=ctx.request_hash, resource=device_id, matched=["P-OPERATOR"])
            if inc is not None and inc["compromise_time"] != cpt:
                service.rescope(core, conn, inc, cpt, rc["id"])
                inc = conn.execute("SELECT * FROM incidents WHERE id = ?", (inc["id"],)).fetchone()
            ctx.set_receipt(rc["id"])
            return service.result_for(core, conn, inc, rc["id"])
        result = service.revoke(core, conn, device_id=device_id, compromise_time=cpt, reported_by=ctx.user_id,
                                note=body.reason, via="revoke", subject=ctx.subject, request_hash=ctx.request_hash,
                                started=started)
    ctx.set_receipt(result["receipt_id"])
    core.log_event("device_revoked", incident_id=result["incident_id"], device_id=device_id,
                   time_to_enforce_ms=result["time_to_enforce_ms"])
    return result


def _incident(core, conn, ctx: Ctx, incident_id: str, action: str = "incident.read"):  # noqa: ANN001, ANN202
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone() if is_id(
        incident_id, "inc") else None
    if row is None:
        raise QGError("QG_NOT_FOUND", "not_found")
    own = row["user_id"] == ctx.user_id
    allowed_all = core.policy.decide(ctx.roles, "incident.read_all", {"user_active": True, "device_active": True}).allow
    if action == "incident.read":
        if not (own or allowed_all):
            raise QGError("QG_NOT_FOUND", "not_found")
        if not allowed_all:
            authorize(core, conn, ctx, "incident.read", {"owner": own}, hide=True)
    else:
        if not (own or allowed_all):
            raise QGError("QG_NOT_FOUND", "not_found")
        authorize(core, conn, ctx, action)
    return row


@router.get("/incidents")
def list_incidents(request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    limit, before = page_params(request)
    st = request.query_params.get("status")
    if st is not None and st not in ("open", "rekeying", "contained", "closed"):
        raise QGError("QG_INVALID_INPUT", "bad_status")
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "incident.list")
        all_ok = core.policy.decide(ctx.roles, "incident.read_all", {"user_active": True, "device_active": True}).allow
        rows = conn.execute("SELECT * FROM incidents WHERE ? OR user_id = ? ORDER BY reported_at DESC, id",
                            (all_ok, ctx.user_id)).fetchall()
        items = [service.summary(conn, r) for r in rows]
    items = [i for i in items if st is None or i["status"] == st]
    return paginate(items, "id", limit, before)


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        return service.detail(conn, _incident(core, conn, ctx, incident_id))


@router.get("/incidents/{incident_id}/exposure")
def get_exposure(incident_id: str, request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        return service.exposure(conn, _incident(core, conn, ctx, incident_id))


@router.get("/incidents/{incident_id}/bundle")
def get_bundle(incident_id: str, request: Request, ctx: Ctx = gateway("bundle.export")) -> dict:
    from qg.incidents.bundle import build_bundle

    core = core_of(request)
    with core.db.tx() as conn:
        _incident(core, conn, ctx, incident_id, "incident.bundle")
        rc = core.receipt(conn, action="bundle.export", decision="allow", reason="exported", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=incident_id)
        service.timeline(core, conn, incident_id, "bundle_exported", rc["id"], "Proof bundle exported.")
        core.log.checkpoint(conn, force=True)
    ctx.set_receipt(rc["id"])
    return build_bundle(core, incident_id)


class Close(Strict):
    pass


@router.post("/incidents/{incident_id}/close")
def close_incident(incident_id: str, request: Request, ctx: Ctx = gateway("incident.close")) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        inc = _incident(core, conn, ctx, incident_id, "incident.close")
        if inc["closed_at"]:
            raise QGError("QG_CONFLICT", "already_closed")
        c = service.counts(conn, incident_id)
        exposed_pending = conn.execute("SELECT 1 FROM incident_files WHERE incident_id = ? AND rekey = 'pending'"
                                       " AND category IN ('exposed', 'held') LIMIT 1", (incident_id,)).fetchone()
        if exposed_pending or c["pending"]:
            raise QGError("QG_CONFLICT", "rekey_pending")
        rc = core.receipt(conn, action="incident.close", decision="allow", reason="closed", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=incident_id, matched=["P-OPERATOR"])
        conn.execute("UPDATE incidents SET closed_at = ?, status = 'closed' WHERE id = ?", (core.clock.iso(), incident_id))
        service.timeline(core, conn, incident_id, "closed", rc["id"], "Incident closed by an operator.")
        out = service.detail(conn, conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone())
    ctx.set_receipt(rc["id"])
    return out
