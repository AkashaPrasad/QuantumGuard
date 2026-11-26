"""Devices (spec/API.md section 7): list, rename, report lost, revoke."""

from __future__ import annotations

import json
import sqlite3
from typing import Annotated, Any

from fastapi import APIRouter, Request
from pydantic import Field

from qg.api.common import page_params, paginate
from qg.core import Core
from qg.errors import QGError
from qg.gateway.http import Ctx, Strict, authorize, body_openapi, core_of, gateway, json_body, live
from qg.ids import is_id

router = APIRouter(prefix="/api/v1", tags=["devices"])


def device_view(conn: sqlite3.Connection, row: sqlite3.Row, current_device: str | None) -> dict[str, Any]:
    inc = conn.execute(
        "SELECT id FROM incidents WHERE device_id = ? AND status != 'closed'", (row["device_id"],)
    ).fetchone()
    name = conn.execute("SELECT name FROM users WHERE user_id = ?", (row["user_id"],)).fetchone()
    return {
        "device_id": row["device_id"],
        "user_id": row["user_id"],
        "user_name": name[0] if name else None,
        "name": row["name"],
        "status": row["status"],
        "created_at": row["created_at"],
        "last_seen_at": row["last_seen_at"],
        "is_current": row["device_id"] == current_device,
        "open_incident_id": inc[0] if inc else None,
    }


def visible_device(core: Core, conn: sqlite3.Connection, ctx: Ctx, device_id: str) -> sqlite3.Row:
    """Owner, or a role that may see all devices; otherwise QG_NOT_FOUND (no existence leak)."""
    if not is_id(device_id, "dev"):
        raise QGError("QG_NOT_FOUND", "not_found")
    row = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    if row is None:
        raise QGError("QG_NOT_FOUND", "not_found")
    if row["user_id"] != ctx.user_id and not set(ctx.roles) & {"operator", "admin", "auditor"}:
        raise QGError("QG_NOT_FOUND", "not_found")
    return row


@router.get("/devices")
def list_devices(request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    limit, before = page_params(request)
    scope = request.query_params.get("scope", "own")
    if scope not in ("own", "all"):
        raise QGError("QG_INVALID_INPUT", "bad_scope")
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "device.list_all" if scope == "all" else "device.list")
        if scope == "all":
            rows = conn.execute("SELECT * FROM devices ORDER BY created_at DESC, device_id").fetchall()
        else:
            rows = conn.execute("SELECT * FROM devices WHERE user_id = ? ORDER BY created_at DESC, device_id",
                                (ctx.user_id,)).fetchall()
        items = [device_view(conn, r, ctx.device_id) for r in rows]
    return paginate(items, "device_id", limit, before)


class DeviceRename(Strict):
    name: Annotated[str, Field(min_length=1, max_length=64)]


@router.patch("/devices/{device_id}", openapi_extra=body_openapi(DeviceRename))
def rename_device(device_id: str, request: Request, ctx: Ctx = gateway("device.rename"),
                  body: DeviceRename = json_body(DeviceRename)) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        row = visible_device(core, conn, ctx, device_id)
        authorize(core, conn, ctx, "device.rename", {"owner": row["user_id"] == ctx.user_id},
                  receipt_action="device.rename", resource=device_id)
        if row["status"] == "revoked":
            raise QGError("QG_CONFLICT", "already_revoked")
        cert = json.loads(row["certificate"])
        new_cert = core.directory.certificate(
            device_id=device_id, user_id=row["user_id"], name=body.name, kem_pk=bytes(row["kem_pk"]),
            sig_pk=bytes(row["sig_pk"]), created_at=cert["created_at"], expires_at=cert["expires_at"],
            directory_epoch=cert["directory_epoch"],
        )
        conn.execute("UPDATE devices SET name = ?, certificate = ? WHERE device_id = ?",
                     (body.name, json.dumps(new_cert), device_id))
        core.directory.publish(conn, "rename")
        rc = core.receipt(conn, action="device.rename", decision="allow", reason="renamed", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=device_id, matched=["P-DEVICE-OWNER"])
        ctx.set_receipt(rc["id"])
        row = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        return device_view(conn, row, ctx.device_id)
