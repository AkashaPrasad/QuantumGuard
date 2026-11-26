"""Service identities, the signed service key set and rotation (spec/API.md section 9, workflow 2).

A caller attributes a request to a service key with the `QG-Service-Key: key_...` header. A retired key
answers QG_DENY_POLICY / key_retired and raises QG-R010; a decoy key raises QG-R004."""

from __future__ import annotations

import sqlite3
from datetime import timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Request
from pydantic import Field

from qg.api.common import page_params, paginate
from qg.clock import fmt
from qg.core import Core
from qg.crypto.sign import MLDSAKey
from qg.errors import QGError
from qg.gateway.http import Ctx, Strict, authorize, body_openapi, core_of, gateway, json_body, live
from qg.ids import is_id, new_id

router = APIRouter(prefix="/api/v1", tags=["services"])

RETIRING_SECONDS = 600


def service_view(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    keys = [{"key_id": k["key_id"], "alg": k["alg"], "status": k["status"], "created_at": k["created_at"],
             "retired_at": k["retired_at"]}
            for k in conn.execute("SELECT * FROM service_keys WHERE service_id = ? ORDER BY created_at, key_id",
                                  (row["service_id"],))]
    return {"service_id": row["service_id"], "name": row["name"], "status": row["status"], "keys": keys}


def retire_due(core: Core, conn: sqlite3.Connection) -> bool:
    """Move retiring keys past their grace period to retired. Returns True when the key set changed."""
    cutoff = fmt(core.clock.now() - timedelta(seconds=RETIRING_SECONDS))
    n = conn.execute("UPDATE service_keys SET status = 'retired', retired_at = ? WHERE status = 'retiring'"
                     " AND retired_at IS NOT NULL AND retired_at <= ?", (core.clock.iso(), cutoff)).rowcount
    return n > 0


def check_service_key(core: Core, ctx: Ctx, request: Request) -> None:
    key_id = request.headers.get("qg-service-key")
    if key_id is None:
        return
    with core.db.tx() as conn:
        if retire_due(core, conn):
            core.publish_keyset(conn)
        row = conn.execute("SELECT k.status, s.is_decoy FROM service_keys k JOIN services s ON s.service_id ="
                           " k.service_id WHERE k.key_id = ?", (key_id,)).fetchone() if is_id(key_id, "key") else None
    if row is None:
        raise QGError("QG_INVALID_INPUT", "unknown_key")
    if row["is_decoy"]:
        rid = core.deny_receipt(ctx, "access", "decoy_key", key_id)
        core.emit_now("decoy_touched", ctx.subject, [rid], key_id=key_id, kind="service key")
        raise QGError("QG_DENY_POLICY", "policy_denied", receipt_id=rid)
    if row["status"] == "retired":
        rid = core.deny_receipt(ctx, "access", "key_retired", key_id)
        core.emit_now("retired_key_used", ctx.subject, [rid], key_id=key_id)
        raise QGError("QG_DENY_POLICY", "key_retired", receipt_id=rid)


@router.get("/services")
def list_services(request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    limit, before = page_params(request)
    check_service_key(core, ctx, request)
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "service.list")
        if retire_due(core, conn):
            core.publish_keyset(conn)
        items = [service_view(conn, r) for r in conn.execute(
            "SELECT * FROM services WHERE is_decoy = 0 ORDER BY created_at, service_id")]
    return paginate(items, "service_id", limit, before)


class ServiceCreate(Strict):
    name: Annotated[str, Field(min_length=1, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$")]


def _new_key(core: Core, conn: sqlite3.Connection, service_id: str) -> str:
    key_id = new_id("key")
    # The service's private key would live with the service; the prototype keeps only the public half.
    conn.execute("INSERT INTO service_keys (key_id, service_id, alg, public_key, status, created_at) VALUES"
                 " (?,?,?,?,?,?)", (key_id, service_id, "ML-DSA-65", MLDSAKey.generate().public_key, "active",
                                    core.clock.iso()))
    return key_id


@router.post("/services", openapi_extra=body_openapi(ServiceCreate))
def create_service(request: Request, ctx: Ctx = gateway("service.create"),
                   body: ServiceCreate = json_body(ServiceCreate)) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        d = authorize(core, conn, ctx, "service.create", receipt_action="service.create")
        if conn.execute("SELECT 1 FROM services WHERE name = ?", (body.name,)).fetchone():
            raise QGError("QG_CONFLICT", "name_taken")
        sid = new_id("svc")
        conn.execute("INSERT INTO services (service_id, name, status, created_at) VALUES (?,?,?,?)",
                     (sid, body.name, "active", core.clock.iso()))
        _new_key(core, conn, sid)
        core.publish_keyset(conn)
        rc = core.receipt(conn, action="service.create", decision="allow", reason="created", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=sid, matched=d.matched_rules)
        out = service_view(conn, conn.execute("SELECT * FROM services WHERE service_id = ?", (sid,)).fetchone())
    ctx.set_receipt(rc["id"])
    return out


class Rotate(Strict):
    reason: Annotated[str, Field(min_length=1, max_length=500)]
    emergency: bool = False


@router.post("/services/{service_id}/rotate", openapi_extra=body_openapi(Rotate))
def rotate_service(service_id: str, request: Request, ctx: Ctx = gateway("service.rotate"),
                   body: Rotate = json_body(Rotate)) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        row = conn.execute("SELECT * FROM services WHERE service_id = ? AND is_decoy = 0", (service_id,)).fetchone() \
            if is_id(service_id, "svc") else None
        if row is None:
            raise QGError("QG_NOT_FOUND", "not_found")
        d = authorize(core, conn, ctx, "service.rotate", {"emergency": body.emergency},
                      receipt_action="service.rotate", resource=service_id)
        now = core.clock.iso()
        if body.emergency:
            conn.execute("UPDATE service_keys SET status = 'retired', retired_at = ? WHERE service_id = ? AND status"
                         " IN ('active', 'retiring')", (now, service_id))
        else:
            conn.execute("UPDATE service_keys SET status = 'retired', retired_at = COALESCE(retired_at, ?) WHERE"
                         " service_id = ? AND status = 'retiring'", (now, service_id))
            conn.execute("UPDATE service_keys SET status = 'retiring', retired_at = ? WHERE service_id = ? AND"
                         " status = 'active'", (now, service_id))
        _new_key(core, conn, service_id)
        keyset = core.publish_keyset(conn)
        rc = core.receipt(conn, action="service.rotate", decision="allow",
                          reason="emergency_rotation" if body.emergency else "rotated", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=service_id, matched=d.matched_rules)
        out = service_view(conn, row)
        out["keyset_epoch"] = keyset["epoch"]
    ctx.set_receipt(rc["id"])
    return out
