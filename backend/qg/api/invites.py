"""Invites (spec/API.md section 5)."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Request, Response
from pydantic import Field

from qg.api.common import page_params, paginate
from qg.clock import parse
from qg.crypto.encoding import canon
from qg.directory.service import ROLES
from qg.errors import QGError
from qg.gateway.http import Ctx, Strict, authorize, body_openapi, core_of, gateway, json_body, live
from qg.ids import is_id, new_id

router = APIRouter(prefix="/api/v1", tags=["invites"])

PRIVILEGED = {"admin", "operator"}


class InviteCreate(Strict):
    user_id: Annotated[str, Field(max_length=26)] | None = None
    name: Annotated[str, Field(min_length=1, max_length=80)] | None = None
    roles: Annotated[list[Annotated[str, Field(max_length=16)]], Field(max_length=4)] | None = None


@router.post("/invites", openapi_extra=body_openapi(InviteCreate))
def create_invite(request: Request, ctx: Ctx = gateway("invite.create"),
                  body: InviteCreate = json_body(InviteCreate)) -> dict:
    core = core_of(request)
    existing = body.user_id is not None
    if existing == (body.name is not None or body.roles is not None):
        raise QGError("QG_INVALID_INPUT", "user_id_or_name")
    with core.db.tx() as conn:
        live(core, conn, ctx)
        if existing:
            if not is_id(body.user_id, "usr"):
                raise QGError("QG_INVALID_INPUT", "bad_user_id")
            authorize(core, conn, ctx, "invite.create", {"self": body.user_id == ctx.user_id},
                      receipt_action="invite.create", resource=body.user_id, hide=True)
            user = conn.execute("SELECT status FROM users WHERE user_id = ?", (body.user_id,)).fetchone()
            if user is None or user["status"] == "disabled":
                raise QGError("QG_NOT_FOUND", "not_found")
            inv = core.create_invite(conn, body.user_id, ctx.user_id, ctx.device_id)
            rc = core.receipt(conn, action="invite.create", decision="allow", reason="invite_created",
                              subject=ctx.subject, request_hash=ctx.request_hash, resource=inv["invite_id"],
                              matched=["P-INVITE-SELF" if body.user_id == ctx.user_id else "P-ADMIN-PEOPLE"])
            ctx.set_receipt(rc["id"])
            return inv
        roles = sorted(set(body.roles or []))
        if not body.name or not roles or any(r not in ROLES for r in roles):
            raise QGError("QG_INVALID_INPUT", "bad_roles")
        d = authorize(core, conn, ctx, "invite.create", {"self": False}, receipt_action="invite.create")
        uid = new_id("usr")
        if set(roles) & PRIVILEGED:
            # privileged people need an approved change before they exist
            change_id = new_id("chg")
            role = sorted(set(roles) & PRIVILEGED)[0]
            doc = {"directory_epoch": core.directory.current_epoch(conn), "file_id": None,
                   "reason": "Invite a new person with a privileged role", "role": role, "suite": "QG-1",
                   "target_user_id": uid, "type": "role_grant"}
            conn.execute(
                "INSERT INTO changes (id, type, target_user_id, role, file_id, reason, requested_by, requested_device,"
                " requested_at, status, approvals_required, change_doc, signature, invite_name) VALUES"
                " (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (change_id, "role_grant", uid, role, None, doc["reason"], ctx.user_id, ctx.device_id,
                 core.clock.iso(), "pending", 1, json.dumps({**doc, "roles": roles}), "", body.name),
            )
            canon(doc)
            rc = core.receipt(conn, action="change.request", decision="allow", reason="change_requested",
                              subject=ctx.subject, request_hash=ctx.request_hash, resource=change_id,
                              matched=d.matched_rules)
            ctx.set_receipt(rc["id"])
            return {"change_id": change_id}
        conn.execute("INSERT INTO users (user_id, name, status, created_at) VALUES (?,?,?,?)",
                     (uid, body.name, "active", core.clock.iso()))
        for r in roles:
            conn.execute("INSERT INTO user_roles (user_id, role, granted_at, source) VALUES (?,?,?,?)",
                         (uid, r, core.clock.iso(), "invite"))
        core.directory.publish(conn, "invite_person")
        inv = core.create_invite(conn, uid, ctx.user_id, ctx.device_id)
        rc = core.receipt(conn, action="invite.create", decision="allow", reason="invite_created",
                          subject=ctx.subject, request_hash=ctx.request_hash, resource=inv["invite_id"],
                          matched=d.matched_rules)
        ctx.set_receipt(rc["id"])
        return inv


def _status(core, row) -> str:  # noqa: ANN001
    if row["status"] == "pending" and parse(row["expires_at"]) <= core.clock.now():
        return "expired"
    return row["status"]


@router.get("/invites")
def list_invites(request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    limit, before = page_params(request)
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "invite.list")
        admin = "admin" in ctx.roles
        rows = conn.execute(
            "SELECT i.*, u.name AS user_name FROM invites i JOIN users u ON u.user_id = i.user_id"
            " WHERE (? OR i.user_id = ? OR i.created_by = ?) ORDER BY i.created_at DESC, i.invite_id",
            (admin, ctx.user_id, ctx.user_id),
        ).fetchall()
        items = [
            {"invite_id": r["invite_id"], "user_id": r["user_id"], "user_name": r["user_name"],
             "created_by": r["created_by"], "expires_at": r["expires_at"], "status": _status(core, r)}
            for r in rows
        ]
    return paginate(items, "invite_id", limit, before)


@router.delete("/invites/{invite_id}", status_code=204, response_class=Response)
def cancel_invite(invite_id: str, request: Request, ctx: Ctx = gateway()) -> Response:
    core = core_of(request)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        row = conn.execute("SELECT * FROM invites WHERE invite_id = ?", (invite_id,)).fetchone()
        visible = row is not None and ("admin" in ctx.roles or row["created_by"] == ctx.user_id)
        if not visible:
            raise QGError("QG_NOT_FOUND", "not_found")
        authorize(core, conn, ctx, "invite.cancel", {"self": row["created_by"] == ctx.user_id}, hide=True)
        if row["status"] != "pending":
            raise QGError("QG_CONFLICT", "not_pending")
        conn.execute("UPDATE invites SET status = 'cancelled' WHERE invite_id = ?", (invite_id,))
    return Response(status_code=204)
