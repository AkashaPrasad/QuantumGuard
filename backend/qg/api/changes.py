"""Signed change requests with approvals (spec/API.md section 8) and recovery release (section 9)."""

from __future__ import annotations

import json
import sqlite3
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Request
from pydantic import Field

from qg.api.common import page_params, paginate
from qg.core import Core
from qg.crypto import aead
from qg.crypto.encoding import EncodingError, b64u, b64u_decode, canon
from qg.crypto.kdf import sha256
from qg.crypto.sign import mldsa_verify
from qg.crypto.suite import RECOVERY_DEVICE_ID, SUITE
from qg.directory.service import ROLES
from qg.errors import QGError
from qg.gateway.http import Ctx, Strict, authorize, body_openapi, core_of, gateway, json_body, live
from qg.ids import is_id, new_id

router = APIRouter(prefix="/api/v1", tags=["changes"])

B64 = Annotated[str, Field(min_length=1, max_length=8192, pattern=r"^[A-Za-z0-9_-]+$")]
Id26 = Annotated[str, Field(min_length=26, max_length=26)]


def approvals_required(ctype: str, role: str | None) -> int:
    """spec/API.md 8: admin/operator grants need 1, recovery releases 2, everything else 0."""
    if ctype == "recovery_release":
        return 2
    if ctype == "role_grant" and role in ("admin", "operator"):
        return 1
    return 0


def change_view(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    def uname(uid: str) -> str | None:
        r = conn.execute("SELECT name FROM users WHERE user_id = ?", (uid,)).fetchone()
        return r[0] if r else None

    doc = json.loads(row["change_doc"])
    statement = {k: doc[k] for k in ("directory_epoch", "file_id", "reason", "role", "suite", "target_user_id", "type")}
    return {
        "id": row["id"],
        "type": row["type"],
        "target_user": {"user_id": row["target_user_id"], "name": uname(row["target_user_id"]) or row["invite_name"]},
        "role": row["role"],
        "file_id": row["file_id"],
        "reason": row["reason"],
        "requested_by": {"user_id": row["requested_by"], "name": uname(row["requested_by"]),
                         "device_id": row["requested_device"]},
        "requested_at": row["requested_at"],
        "status": row["status"],
        "approvals": [{"user_id": a["user_id"], "name": uname(a["user_id"]), "device_id": a["device_id"], "at": a["at"],
                       "signature": a["signature"]}
                      for a in conn.execute("SELECT * FROM change_approvals WHERE change_id = ? ORDER BY at",
                                            (row["id"],))],
        "approvals_required": row["approvals_required"],
        "change": statement,
        "change_hash": b64u(sha256(canon(statement))),
        "signature": row["signature"],
    }


def apply_change(core: Core, conn: sqlite3.Connection, row: sqlite3.Row, ctx: Ctx) -> None:
    now = core.clock.iso()
    doc = json.loads(row["change_doc"])
    target = row["target_user_id"]
    if row["type"] == "role_grant":
        if conn.execute("SELECT 1 FROM users WHERE user_id = ?", (target,)).fetchone() is None:
            # a privileged person invited through POST /invites: created once approved
            conn.execute("INSERT INTO users (user_id, name, status, created_at) VALUES (?,?,?,?)",
                         (target, row["invite_name"] or "New person", "active", now))
            for r in doc.get("roles", [row["role"]]):
                conn.execute("INSERT OR IGNORE INTO user_roles (user_id, role, granted_at, change_id, source)"
                             " VALUES (?,?,?,?,?)", (target, r, now, row["id"], "signed"))
        else:
            conn.execute("INSERT OR REPLACE INTO user_roles (user_id, role, granted_at, change_id, source)"
                         " VALUES (?,?,?,?,?)", (target, row["role"], now, row["id"], "signed"))
        core.directory.publish(conn, "role_grant")
    elif row["type"] == "role_revoke":
        conn.execute("DELETE FROM user_roles WHERE user_id = ? AND role = ?", (target, row["role"]))
        core.directory.publish(conn, "role_revoke")
    conn.execute("UPDATE changes SET status = 'applied', applied_at = ? WHERE id = ?", (now, row["id"]))
    approvers = [a[0] for a in conn.execute("SELECT user_id FROM change_approvals WHERE change_id = ?", (row["id"],))]
    core.emit(conn, "grant_applied", {"user_id": target, "device_id": None, "session_id": None}, [],
              change_id=row["id"], type=row["type"], role=row["role"], requested_by=row["requested_by"],
              approvers=approvers)


class ChangeStatement(Strict):
    directory_epoch: int
    file_id: Id26 | None
    reason: Annotated[str, Field(min_length=1, max_length=500)]
    role: Literal["admin", "auditor", "employee", "operator"] | None
    suite: Literal["QG-1"]
    target_user_id: Id26
    type: Literal["role_grant", "role_revoke", "recovery_release"]


class ChangeCreate(Strict):
    change: ChangeStatement
    signature: B64


@router.get("/changes")
def list_changes(request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    limit, before = page_params(request)
    st = request.query_params.get("status")
    if st is not None and st not in ("pending", "applied", "rejected"):
        raise QGError("QG_INVALID_INPUT", "bad_status")
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "change.list")
        rows = conn.execute("SELECT * FROM changes WHERE ? IS NULL OR status = ? ORDER BY requested_at DESC, id",
                            (st, st)).fetchall()
        items = [change_view(conn, r) for r in rows]
    return paginate(items, "id", limit, before)


@router.post("/changes", openapi_extra=body_openapi(ChangeCreate))
def create_change(request: Request, ctx: Ctx = gateway("change.request"),
                  body: ChangeCreate = json_body(ChangeCreate)) -> dict:
    core = core_of(request)
    c = body.change
    statement = c.model_dump()
    if c.type in ("role_grant", "role_revoke") and (c.role not in ROLES or c.file_id is not None):
        raise QGError("QG_INVALID_INPUT", "bad_change")
    if c.type == "recovery_release" and (c.file_id is None or c.role is not None):
        raise QGError("QG_INVALID_INPUT", "bad_change")
    try:
        sig = b64u_decode(body.signature)
    except EncodingError:
        sig = b""
    with core.db.tx() as conn:
        live(core, conn, ctx)
        d = authorize(core, conn, ctx, "change.request", receipt_action="change.request")
        sig_pk = conn.execute("SELECT sig_pk FROM devices WHERE device_id = ?", (ctx.device_id,)).fetchone()[0]
        target = conn.execute("SELECT status FROM users WHERE user_id = ?", (c.target_user_id,)).fetchone()
        file_ok = c.file_id is None or conn.execute(
            "SELECT 1 FROM files WHERE file_id = ? AND deleted = 0 AND is_decoy = 0 AND current_version > 0",
            (c.file_id,)).fetchone() is not None
        epoch_ok = core.directory.epoch_acceptable(conn, c.directory_epoch)
    if not sig or not mldsa_verify(bytes(sig_pk), sig, canon(statement), "change"):
        rid = core.deny_receipt(ctx, "change.request", "bad_signature", c.target_user_id)
        core.emit_now("signature_failure", ctx.subject, [rid], kind="change")
        raise QGError("QG_BAD_SIGNATURE", "bad_signature", receipt_id=rid)
    if target is None or not file_ok:
        raise QGError("QG_NOT_FOUND", "not_found")
    if not epoch_ok:
        rid = core.deny_receipt(ctx, "change.request", "stale_epoch", c.target_user_id)
        core.emit_now("stale_epoch", ctx.subject, [rid], epoch=c.directory_epoch)
        raise QGError("QG_STALE_EPOCH", "stale_epoch", receipt_id=rid)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        if c.type == "role_grant" and c.role in core.directory.roles(conn, c.target_user_id):
            raise QGError("QG_CONFLICT", "already_granted")
        if c.type == "role_revoke" and c.role not in core.directory.roles(conn, c.target_user_id):
            raise QGError("QG_CONFLICT", "not_granted")
        change_id = new_id("chg")
        required = approvals_required(c.type, c.role)
        conn.execute(
            "INSERT INTO changes (id, type, target_user_id, role, file_id, reason, requested_by, requested_device,"
            " requested_at, status, approvals_required, change_doc, signature) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (change_id, c.type, c.target_user_id, c.role, c.file_id, c.reason, ctx.user_id, ctx.device_id,
             core.clock.iso(), "pending", required, json.dumps(statement), body.signature),
        )
        rc = core.receipt(conn, action="change.request", decision="allow", reason="change_requested",
                          subject=ctx.subject, request_hash=ctx.request_hash, resource=change_id,
                          matched=d.matched_rules)
        row = conn.execute("SELECT * FROM changes WHERE id = ?", (change_id,)).fetchone()
        if required == 0:
            apply_change(core, conn, row, ctx)
            row = conn.execute("SELECT * FROM changes WHERE id = ?", (change_id,)).fetchone()
        out = change_view(conn, row)
    ctx.set_receipt(rc["id"])
    return out


class Approve(Strict):
    signature: B64


def _change(conn: sqlite3.Connection, change_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM changes WHERE id = ?", (change_id,)).fetchone() if is_id(change_id, "chg") else None
    if row is None:
        raise QGError("QG_NOT_FOUND", "not_found")
    return row


@router.post("/changes/{change_id}/approve", openapi_extra=body_openapi(Approve))
def approve_change(change_id: str, request: Request, ctx: Ctx = gateway("change.approve"),
                   body: Approve = json_body(Approve)) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        row = _change(conn, change_id)
        view = change_view(conn, row)
    self_approval = ctx.user_id in (row["requested_by"], row["target_user_id"])
    with core.db.tx() as conn:
        try:
            authorize(core, conn, ctx, "change.approve", {"self_approval": self_approval, "change_type": row["type"]},
                      receipt_action="change.approve", resource=change_id)
        except QGError as exc:
            if self_approval and exc.code == "QG_DENY_POLICY":
                raise QGError("QG_DENY_POLICY", "self_approval", receipt_id=exc.receipt_id) from exc
            raise
    if row["type"] != "recovery_release" and "admin" not in ctx.roles:
        rid = core.deny_receipt(ctx, "change.approve", "approver_not_admin", change_id)
        raise QGError("QG_DENY_POLICY", "policy_denied", receipt_id=rid)
    approval = {"change_hash": view["change_hash"], "change_id": change_id, "decision": "approve",
                "purpose": "approve", "suite": SUITE}
    try:
        sig = b64u_decode(body.signature)
    except EncodingError:
        sig = b""
    with core.db.tx() as conn:
        sig_pk = conn.execute("SELECT sig_pk FROM devices WHERE device_id = ?", (ctx.device_id,)).fetchone()[0]
    if not sig or not mldsa_verify(bytes(sig_pk), sig, canon(approval), "change"):
        rid = core.deny_receipt(ctx, "change.approve", "bad_signature", change_id)
        core.emit_now("signature_failure", ctx.subject, [rid], kind="approval")
        raise QGError("QG_BAD_SIGNATURE", "bad_signature", receipt_id=rid)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        row = _change(conn, change_id)
        if row["status"] != "pending":
            raise QGError("QG_CONFLICT", "not_pending")
        if conn.execute("SELECT 1 FROM change_approvals WHERE change_id = ? AND user_id = ?",
                        (change_id, ctx.user_id)).fetchone():
            raise QGError("QG_CONFLICT", "already_approved")
        conn.execute("INSERT INTO change_approvals (change_id, user_id, device_id, at, signature) VALUES (?,?,?,?,?)",
                     (change_id, ctx.user_id, ctx.device_id, core.clock.iso(), body.signature))
        rc = core.receipt(conn, action="change.approve", decision="allow", reason="approved", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=change_id)
        count = conn.execute("SELECT COUNT(*) FROM change_approvals WHERE change_id = ?", (change_id,)).fetchone()[0]
        if count >= row["approvals_required"]:
            apply_change(core, conn, row, ctx)
        out = change_view(conn, _change(conn, change_id))
    ctx.set_receipt(rc["id"])
    return out


class Reject(Strict):
    reason: Annotated[str, Field(min_length=1, max_length=500)]


@router.post("/changes/{change_id}/reject", openapi_extra=body_openapi(Reject))
def reject_change(change_id: str, request: Request, ctx: Ctx = gateway("change.reject"),
                  body: Reject = json_body(Reject)) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        d = authorize(core, conn, ctx, "change.reject", receipt_action="change.reject", resource=change_id)
        row = _change(conn, change_id)
        if row["status"] != "pending":
            raise QGError("QG_CONFLICT", "not_pending")
        conn.execute("UPDATE changes SET status = 'rejected', reject_reason = ? WHERE id = ?", (body.reason, change_id))
        rc = core.receipt(conn, action="change.reject", decision="allow", reason="rejected", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=change_id, matched=d.matched_rules)
        out = change_view(conn, _change(conn, change_id))
    ctx.set_receipt(rc["id"])
    return out


class Recover(Strict):
    change_id: Id26


@router.post("/files/{file_id}/recover", tags=["files"], openapi_extra=body_openapi(Recover))
def recover_file(file_id: str, request: Request, ctx: Ctx = gateway("recovery.release"),
                 body: Recover = json_body(Recover)) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        authorize(core, conn, ctx, "file.recover", {"decoy": False}, receipt_action="recovery.release",
                  resource=file_id)
        row = _change(conn, body.change_id)
        frow = conn.execute("SELECT * FROM files WHERE file_id = ? AND deleted = 0", (file_id,)).fetchone()
        if frow is None or row["file_id"] != file_id or row["type"] != "recovery_release":
            raise QGError("QG_NOT_FOUND", "not_found")
        if row["status"] != "applied":
            rid = core.deny_receipt(ctx, "recovery.release", "approvals_incomplete", file_id)
            raise QGError("QG_DENY_POLICY", "approvals_incomplete", receipt_id=rid)
        used = conn.execute("SELECT 1 FROM receipts WHERE action = 'recovery.release' AND decision = 'allow'"
                            " AND resource = ? AND reason_code = ?", (file_id, "released:" + body.change_id)).fetchone()
        if used:
            raise QGError("QG_CONFLICT", "already_used")
        version = frow["current_version"]
        slot = conn.execute("SELECT * FROM slots WHERE file_id = ? AND version = ? AND device_id = ?",
                            (file_id, version, RECOVERY_DEVICE_ID)).fetchone()
        ver = conn.execute("SELECT * FROM file_versions WHERE file_id = ? AND version = ?", (file_id, version)).fetchone()
        if slot is None or ver is None:
            raise QGError("QG_NOT_FOUND", "not_found")
        inner = json.loads(aead.unseal(core.keys.seal_master, slot["seal_epoch"],
                                       aead.seal_aad(slot["slot_id"], file_id, version, RECOVERY_DEVICE_ID,
                                                     slot["seal_epoch"]), bytes(slot["sealed"])))
        rc = core.receipt(conn, action="recovery.release", decision="allow", reason="released:" + body.change_id,
                          subject=ctx.subject, request_hash=ctx.request_hash, resource=file_id, key_epoch=version)
    ctx.set_receipt(rc["id"])
    return {"recovery_wrap": inner, "wrap_epoch": slot["wrap_epoch"], "manifest": json.loads(ver["manifest"]),
            "manifest_sig": ver["manifest_sig"], "signer_device_id": ver["committed_by_device"], "version": version}
