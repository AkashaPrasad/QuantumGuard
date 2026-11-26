"""Files: pending/commit upload, sealed slots, leases, chunk downloads, share, unshare, re-key queue
(spec/API.md section 6, spec/SUITE.md section 7)."""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Request, Response
from fastapi import Path as FastAPIPath
from pydantic import Field

from qg.api.common import page_params, paginate
from qg.clock import fmt, parse
from qg.core import Core
from qg.crypto import aead
from qg.crypto.encoding import EncodingError, b64u, b64u_decode, canon
from qg.crypto.sign import mldsa_verify
from qg.crypto.suite import CHUNK_BYTES, LEASE_SECONDS, MAX_FILE_BYTES, MAX_RECIPIENTS, RECOVERY_DEVICE_ID
from qg.errors import QGError
from qg.gateway.http import Ctx, Strict, authorize, body_openapi, core_of, gateway, json_body, live
from qg.ids import is_id, new_id

router = APIRouter(prefix="/api/v1", tags=["files"])

Classification = Literal["internal", "confidential", "restricted"]
SENSITIVE = ("confidential", "restricted")
B64 = Annotated[str, Field(min_length=1, max_length=8192, pattern=r"^[A-Za-z0-9_-]+$")]
DevId = Annotated[str, Field(min_length=26, max_length=26)]
# L2: integers beyond the safe range are input errors (400); in-range values that name nothing stay 404
PathInt = Annotated[int, FastAPIPath(ge=-(2**53 - 1), le=2**53 - 1)]


def expected_chunks(size: int) -> int:
    return max(1, -(-size // CHUNK_BYTES))


# ---- access helpers -----------------------------------------------------------------------------


def file_row(conn: sqlite3.Connection, file_id: str) -> sqlite3.Row | None:
    if not is_id(file_id, "fil"):
        return None
    return conn.execute("SELECT * FROM files WHERE file_id = ? AND deleted = 0", (file_id,)).fetchone()


def holds_slot(conn: sqlite3.Connection, file_id: str, version: int, device_id: str) -> bool:
    return conn.execute("SELECT 1 FROM slots WHERE file_id = ? AND version = ? AND device_id = ?",
                        (file_id, version, device_id)).fetchone() is not None


def person_has_slot(conn: sqlite3.Connection, file_id: str, user_id: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM slots s JOIN devices d ON d.device_id = s.device_id WHERE s.file_id = ? AND d.user_id = ?"
        " LIMIT 1", (file_id, user_id)).fetchone() is not None


def access(core: Core, conn: sqlite3.Connection, ctx: Ctx, file_id: str, action: str, *,
           receipt_action: str | None = None) -> tuple[sqlite3.Row, dict[str, Any]]:
    """Resolve a file the caller may see, run policy, and handle decoys. Invisible -> QG_NOT_FOUND."""
    row = file_row(conn, file_id)
    if row is not None and row["is_decoy"]:
        rid = core.deny_receipt(ctx, receipt_action or "slot.release", "decoy", file_id, ["D-DECOY"])
        core.emit_now("decoy_touched", ctx.subject, [rid], resource=file_id, kind="file")
        raise QGError("QG_DENY_POLICY", "policy_denied", receipt_id=rid)
    visible = row is not None and (row["owner_user_id"] == ctx.user_id or person_has_slot(conn, file_id, ctx.user_id))
    if not visible:
        rid = core.deny_receipt(ctx, receipt_action, "not_found", file_id) if receipt_action else None
        core.emit_now("denied", ctx.subject, [rid] if rid else [], code="QG_NOT_FOUND", action=action)
        raise QGError("QG_NOT_FOUND", "not_found", receipt_id=rid)
    facts = {
        "owner": row["owner_user_id"] == ctx.user_id,
        "has_slot": holds_slot(conn, file_id, row["current_version"], ctx.device_id),
        "decoy": bool(row["is_decoy"]),
        "classification": row["classification"],
    }
    authorize(core, conn, ctx, action, facts, receipt_action=receipt_action, resource=file_id,
              key_epoch=row["current_version"])
    return row, facts


def pending_rekey_recipients(conn: sqlite3.Connection, file_id: str, version: int) -> list[str] | None:
    """The exact recipient set a non-owner re-key must use: active devices holding a slot on the current version,
    or None when no re-key job is pending for that version."""
    job = conn.execute("SELECT 1 FROM rekey_jobs WHERE file_id = ? AND from_version = ? AND status IN"
                       " ('pending', 'in_progress') LIMIT 1", (file_id, version)).fetchone()
    if job is None:
        return None
    return [r[0] for r in conn.execute(
        "SELECT s.device_id FROM slots s JOIN devices d ON d.device_id = s.device_id WHERE s.file_id = ? AND"
        " s.version = ? AND d.status = 'active' ORDER BY s.device_id", (file_id, version))]


def rekey_state(conn: sqlite3.Connection, file_id: str) -> str:
    row = conn.execute("SELECT status FROM rekey_jobs WHERE file_id = ? AND status IN ('pending', 'in_progress')"
                       " ORDER BY created_at LIMIT 1", (file_id,)).fetchone()
    return row[0] if row else "none"


def file_view(conn: sqlite3.Connection, row: sqlite3.Row, device_id: str) -> dict[str, Any]:
    v = row["current_version"]
    ver = conn.execute("SELECT * FROM file_versions WHERE file_id = ? AND version = ?",
                       (row["file_id"], v if v else 1)).fetchone()
    owner = conn.execute("SELECT name FROM users WHERE user_id = ?", (row["owner_user_id"],)).fetchone()
    recipients = [
        {"device_id": r[0], "user_id": r[1], "user_name": r[2], "device_name": r[3]}
        for r in conn.execute(
            "SELECT s.device_id, d.user_id, u.name, d.name FROM slots s JOIN devices d ON d.device_id = s.device_id"
            " JOIN users u ON u.user_id = d.user_id WHERE s.file_id = ? AND s.version = ? ORDER BY s.device_id",
            (row["file_id"], v))
    ]
    return {
        "file_id": row["file_id"],
        "name": row["name"],
        "classification": row["classification"],
        "size_bytes": ver["size_bytes"] if ver else 0,
        "version": v,
        "chunk_count": ver["chunk_count"] if ver else 0,
        "owner": {"user_id": row["owner_user_id"], "name": owner[0] if owner else None},
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "recipients": recipients,
        "can_open": any(r["device_id"] == device_id for r in recipients),
        "rekey": rekey_state(conn, row["file_id"]),
    }


# ---- create, list, read, delete ------------------------------------------------------------------


class FileCreate(Strict):
    name: Annotated[str, Field(min_length=1, max_length=200)]
    classification: Classification
    size_bytes: Annotated[int, Field(ge=0, le=MAX_FILE_BYTES)]
    chunk_count: Annotated[int, Field(ge=1, le=MAX_FILE_BYTES // CHUNK_BYTES + 1)]


@router.post("/files", openapi_extra=body_openapi(FileCreate))
def create_file(request: Request, ctx: Ctx = gateway("file.create"), body: FileCreate = json_body(FileCreate)) -> dict:
    core = core_of(request)
    if body.chunk_count != expected_chunks(body.size_bytes):
        raise QGError("QG_INVALID_INPUT", "chunk_count")
    with core.db.tx() as conn:
        live(core, conn, ctx)
        d = authorize(core, conn, ctx, "file.create", {"classification": body.classification},
                      receipt_action="file.create")
        file_id = new_id("fil")
        now = core.clock.iso()
        conn.execute("INSERT INTO files (file_id, owner_user_id, name, classification, current_version, created_at,"
                     " updated_at) VALUES (?,?,?,?,0,?,?)",
                     (file_id, ctx.user_id, body.name, body.classification, now, now))
        conn.execute("INSERT INTO file_versions (file_id, version, status, reason, size_bytes, chunk_count, created_at,"
                     " created_by_device) VALUES (?,1,'pending','create',?,?,?,?)",
                     (file_id, body.size_bytes, body.chunk_count, now, ctx.device_id))
        rc = core.receipt(conn, action="file.create", decision="allow", reason="created", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=file_id, matched=d.matched_rules, key_epoch=1)
    ctx.set_receipt(rc["id"])
    return {"file_id": file_id, "version": 1}


@router.get("/files")
def list_files(request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    limit, before = page_params(request)
    q = (request.query_params.get("q") or "").strip().lower()
    cls = request.query_params.get("classification")
    if cls is not None and cls not in ("internal", "confidential", "restricted"):
        raise QGError("QG_INVALID_INPUT", "bad_classification")
    if len(q) > 200:
        raise QGError("QG_INVALID_INPUT", "bad_query")
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "file.list")
        rows = conn.execute(
            "SELECT DISTINCT f.* FROM files f LEFT JOIN slots s ON s.file_id = f.file_id AND s.version = f.current_version"
            " LEFT JOIN devices d ON d.device_id = s.device_id WHERE f.deleted = 0 AND f.is_decoy = 0"
            " AND (f.owner_user_id = ? OR d.user_id = ?) ORDER BY f.updated_at DESC, f.file_id",
            (ctx.user_id, ctx.user_id)).fetchall()
        items = [file_view(conn, r, ctx.device_id) for r in rows
                 if (not q or q in r["name"].lower()) and (cls is None or r["classification"] == cls)]
    return paginate(items, "file_id", limit, before)


@router.get("/files/{file_id}")
def get_file(file_id: str, request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        row, _ = access(core, conn, ctx, file_id, "file.read")
        view = file_view(conn, row, ctx.device_id)
        view["versions"] = [
            {"version": v["version"], "committed_at": v["committed_at"], "committed_by_device": v["committed_by_device"],
             "reason": v["reason"]}
            for v in conn.execute("SELECT * FROM file_versions WHERE file_id = ? AND status != 'pending'"
                                  " ORDER BY version DESC", (file_id,))
        ]
        view["activity"] = [json.loads(r[0]) for r in conn.execute(
            "SELECT leaf FROM receipts WHERE resource = ? ORDER BY leaf_index DESC LIMIT 20", (file_id,))]
    return view


@router.delete("/files/{file_id}", status_code=204, response_class=Response)
def delete_file(file_id: str, request: Request, ctx: Ctx = gateway("file.delete")) -> Response:
    core = core_of(request)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        row, _ = access(core, conn, ctx, file_id, "file.delete", receipt_action="file.delete")
        conn.execute("DELETE FROM slots WHERE file_id = ?", (file_id,))
        conn.execute("UPDATE leases SET cancelled = 1 WHERE file_id = ?", (file_id,))
        conn.execute("DELETE FROM file_versions WHERE file_id = ? AND status = 'pending'", (file_id,))
        conn.execute("UPDATE rekey_jobs SET status = 'cancelled' WHERE file_id = ? AND status != 'done'", (file_id,))
        conn.execute("UPDATE files SET deleted = 1, updated_at = ? WHERE file_id = ?", (core.clock.iso(), file_id))
        rc = core.receipt(conn, action="file.delete", decision="allow", reason="deleted", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=file_id, matched=["P-FILE-OWNER"])
        core.db.on_commit(lambda: core.blobs.delete_file(file_id))
    ctx.set_receipt(rc["id"])
    return Response(status_code=204)


# ---- versions and chunks -----------------------------------------------------------------------


class VersionCreate(Strict):
    reason: Literal["rekey", "update"]
    size_bytes: Annotated[int, Field(ge=0, le=MAX_FILE_BYTES)]
    chunk_count: Annotated[int, Field(ge=1, le=MAX_FILE_BYTES // CHUNK_BYTES + 1)]


@router.post("/files/{file_id}/versions", openapi_extra=body_openapi(VersionCreate))
def create_version(file_id: str, request: Request, ctx: Ctx = gateway(),
                   body: VersionCreate = json_body(VersionCreate)) -> dict:
    core = core_of(request)
    if body.chunk_count != expected_chunks(body.size_bytes):
        raise QGError("QG_INVALID_INPUT", "chunk_count")
    with core.db.tx() as conn:
        live(core, conn, ctx)
        row, facts = access(core, conn, ctx, file_id, "file.version")
        if row["current_version"] == 0:
            raise QGError("QG_CONFLICT", "not_committed")
        if body.reason == "update" and not facts["owner"]:
            raise QGError("QG_DENY_POLICY", "policy_denied")
        if body.reason == "rekey" and not facts["has_slot"]:
            raise QGError("QG_DENY_POLICY", "policy_denied")
        if body.reason == "rekey" and not facts["owner"] and \
                pending_rekey_recipients(conn, file_id, row["current_version"]) is None:
            rid = core.deny_receipt(ctx, "rekey.commit", "no_pending_rekey", file_id, key_epoch=row["current_version"])
            raise QGError("QG_DENY_POLICY", "no_pending_rekey", receipt_id=rid)
        nv = conn.execute("SELECT MAX(version) FROM file_versions WHERE file_id = ?", (file_id,)).fetchone()[0] + 1
        # one pending version at a time per file: an abandoned upload is replaced
        for old in conn.execute("SELECT version FROM file_versions WHERE file_id = ? AND status = 'pending'",
                                (file_id,)).fetchall():
            conn.execute("DELETE FROM file_versions WHERE file_id = ? AND version = ?", (file_id, old[0]))
            core.db.on_commit(lambda v=old[0]: core.blobs.delete_version(file_id, v))
        conn.execute("INSERT INTO file_versions (file_id, version, status, reason, size_bytes, chunk_count, created_at,"
                     " created_by_device) VALUES (?,?,'pending',?,?,?,?,?)",
                     (file_id, nv, body.reason, body.size_bytes, body.chunk_count, core.clock.iso(), ctx.device_id))
        if body.reason == "rekey":
            conn.execute("UPDATE rekey_jobs SET status = 'in_progress', claimed_by = ?, updated_at = ? WHERE file_id = ?"
                         " AND status = 'pending'", (ctx.device_id, core.clock.iso(), file_id))
            for inc in conn.execute("SELECT DISTINCT incident_id FROM rekey_jobs WHERE file_id = ? AND incident_id"
                                    " IS NOT NULL AND status = 'in_progress'", (file_id,)).fetchall():
                core.timeline(conn, inc[0], "rekey_started", None, f"Re-key of {row['name']} started.")
    return {"version": nv}


@router.put("/files/{file_id}/versions/{version}/chunks/{index}", status_code=204, response_class=Response,
            openapi_extra={"requestBody": {"required": True, "content": {"application/octet-stream": {
                "schema": {"type": "string", "format": "binary"}}}}})
def put_chunk(file_id: str, version: PathInt, index: PathInt, request: Request, ctx: Ctx = gateway()) -> Response:
    core = core_of(request)
    blob = ctx.body
    if not 28 <= len(blob) <= CHUNK_BYTES + 28:
        raise QGError("QG_INVALID_INPUT", "chunk_size")
    with core.db.tx() as conn:
        live(core, conn, ctx)
        row = file_row(conn, file_id)
        ver = conn.execute("SELECT * FROM file_versions WHERE file_id = ? AND version = ?",
                           (file_id, version)).fetchone() if row else None
        if row is None or ver is None or row["is_decoy"]:
            raise QGError("QG_NOT_FOUND", "not_found")
        own_upload = ver["created_by_device"] == ctx.device_id
        if not own_upload:
            access(core, conn, ctx, file_id, "chunk.write")
            raise QGError("QG_DENY_POLICY", "policy_denied")
        authorize(core, conn, ctx, "chunk.write", {"owner": row["owner_user_id"] == ctx.user_id,
                                                   "has_slot": holds_slot(conn, file_id, row["current_version"],
                                                                          ctx.device_id)})
        if ver["status"] != "pending":
            raise QGError("QG_CONFLICT", "already_committed")
        if not 0 <= index < ver["chunk_count"]:
            raise QGError("QG_INVALID_INPUT", "chunk_index")
    existing = core.blobs.get(file_id, version, index)
    if existing is not None:
        if existing != blob:
            raise QGError("QG_CONFLICT", "chunk_differs")
        return Response(status_code=204)
    try:
        core.blobs.put(file_id, version, index, blob)
    except OSError as exc:
        raise QGError("QG_UNAVAILABLE_FAIL_CLOSED", "storage_unavailable") from exc
    return Response(status_code=204)


class InnerWrap(Strict):
    xwing_ct: B64
    wrapped_dek: B64


class Wrap(InnerWrap):
    device_id: DevId


class Manifest(Strict):
    chunk_count: int
    ciphertext_sha256: B64
    classification: Classification
    directory_epoch: int
    file_id: Annotated[str, Field(max_length=26)]
    recipients: Annotated[list[DevId], Field(min_length=1, max_length=MAX_RECIPIENTS)]
    suite: Literal["QG-1"]
    version: int


class Commit(Strict):
    manifest: Manifest
    manifest_sig: B64
    wraps: Annotated[list[Wrap], Field(min_length=1, max_length=MAX_RECIPIENTS)]
    recovery_wrap: InnerWrap | None = None  # required once a recovery kit has been issued, absent before


def _check_wrap(w: InnerWrap) -> dict[str, str]:
    try:
        b64u_decode(w.xwing_ct, length=1120)
        b64u_decode(w.wrapped_dek, length=60)
    except EncodingError as exc:
        raise QGError("QG_INVALID_INPUT", "bad_wrap") from exc
    return {"xwing_ct": w.xwing_ct, "wrapped_dek": w.wrapped_dek}


def _check_recipients(core: Core, conn: sqlite3.Connection, ctx: Ctx, file_id: str, classification: str,
                      recipients: list[str], receipt_action: str) -> None:
    for did in recipients:
        dev = conn.execute("SELECT d.status, d.user_id, u.status AS ustatus FROM devices d JOIN users u"
                           " ON u.user_id = d.user_id WHERE d.device_id = ?", (did,)).fetchone()
        allowed = False
        if dev is not None:
            roles = core.directory.roles(conn, dev["user_id"])
            facts = {"device_active": dev["status"] == "active", "user_active": dev["ustatus"] == "active",
                     "classification": classification}
            allowed = core.policy.decide(roles, "file.receive", facts).allow
        if not allowed:
            rid = core.deny_receipt(ctx, receipt_action, "recipient_not_allowed", file_id)
            raise QGError("QG_DENY_POLICY", "recipient_not_allowed", receipt_id=rid)


def _seal_slot(core: Core, conn: sqlite3.Connection, file_id: str, version: int, device_id: str,
               inner: dict[str, str], wrap_epoch: int) -> None:
    slot_id = new_id("slt")
    epoch = core.keys.seal_epoch
    sealed = aead.seal(core.keys.seal_master, epoch, aead.seal_aad(slot_id, file_id, version, device_id, epoch), inner)
    conn.execute("INSERT INTO slots (slot_id, file_id, version, device_id, sealed, seal_epoch, wrap_epoch, created_at)"
                 " VALUES (?,?,?,?,?,?,?,?)",
                 (slot_id, file_id, version, device_id, sealed, epoch, wrap_epoch, core.clock.iso()))


@router.post("/files/{file_id}/versions/{version}/commit", openapi_extra=body_openapi(Commit))
def commit_version(file_id: str, version: PathInt, request: Request, ctx: Ctx = gateway("file.commit"),
                   body: Commit = json_body(Commit)) -> dict:
    core = core_of(request)
    m = body.manifest
    manifest = m.model_dump()
    recips = list(m.recipients)
    if recips != sorted(set(recips)) or RECOVERY_DEVICE_ID in recips:
        raise QGError("QG_INVALID_INPUT", "recipients_order")
    if sorted(w.device_id for w in body.wraps) != recips:
        raise QGError("QG_INVALID_INPUT", "wraps_mismatch")
    if m.file_id != file_id or m.version != version:
        raise QGError("QG_INVALID_INPUT", "manifest_mismatch")
    inners = {w.device_id: _check_wrap(w) for w in body.wraps}
    have_kit = core.recovery.get() is not None
    if have_kit != (body.recovery_wrap is not None):
        raise QGError("QG_INVALID_INPUT", "recovery_wrap_required" if have_kit else "no_recovery_key")
    recovery = _check_wrap(body.recovery_wrap) if body.recovery_wrap is not None else None
    try:
        sig = b64u_decode(body.manifest_sig)
    except EncodingError:
        sig = b""
    with core.db.tx() as conn:
        live(core, conn, ctx)
        row = file_row(conn, file_id)
        ver = conn.execute("SELECT * FROM file_versions WHERE file_id = ? AND version = ?",
                           (file_id, version)).fetchone() if row else None
        if row is None or ver is None or row["is_decoy"]:
            raise QGError("QG_NOT_FOUND", "not_found")
        if ver["created_by_device"] != ctx.device_id:
            access(core, conn, ctx, file_id, "file.commit")
            raise QGError("QG_DENY_POLICY", "policy_denied")
        facts = {"owner": row["owner_user_id"] == ctx.user_id,
                 "has_slot": holds_slot(conn, file_id, row["current_version"], ctx.device_id)}
        decision = authorize(core, conn, ctx, "file.commit", facts, receipt_action="file.commit", resource=file_id)
        if ver["status"] != "pending":
            raise QGError("QG_CONFLICT", "already_committed")
        sig_pk = conn.execute("SELECT sig_pk FROM devices WHERE device_id = ?", (ctx.device_id,)).fetchone()[0]
    if not sig or not mldsa_verify(bytes(sig_pk), sig, canon(manifest), "manifest"):
        rid = core.deny_receipt(ctx, "file.commit", "bad_signature", file_id)
        core.emit_now("signature_failure", ctx.subject, [rid], kind="manifest")
        raise QGError("QG_BAD_SIGNATURE", "bad_signature", receipt_id=rid)
    if m.classification != row["classification"] or m.chunk_count != ver["chunk_count"]:
        raise QGError("QG_INVALID_INPUT", "ciphertext_mismatch")
    blobs = []
    for i in range(ver["chunk_count"]):
        b = core.blobs.get(file_id, version, i)
        if b is None:
            raise QGError("QG_INVALID_INPUT", "ciphertext_mismatch")
        blobs.append(b)
    if b64u(aead.ciphertext_sha256(blobs)) != m.ciphertext_sha256 or core.blobs.count(file_id, version) != len(blobs):
        raise QGError("QG_INVALID_INPUT", "ciphertext_mismatch")
    reason = ver["reason"]
    action = "rekey.commit" if reason == "rekey" else "file.commit"
    with core.db.tx() as conn:
        live(core, conn, ctx)
        if not core.directory.epoch_acceptable(conn, m.directory_epoch):
            stale = True
        else:
            stale = False
    if stale:
        rid = core.deny_receipt(ctx, action, "stale_epoch", file_id)
        core.emit_now("stale_epoch", ctx.subject, [rid], epoch=m.directory_epoch)
        raise QGError("QG_STALE_EPOCH", "stale_epoch", receipt_id=rid)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        if reason == "rekey" and row["owner_user_id"] != ctx.user_id:
            # H1: a holder may only re-key a file that has a pending job, for exactly the remaining recipients
            expected = pending_rekey_recipients(conn, file_id, conn.execute(
                "SELECT current_version FROM files WHERE file_id = ?", (file_id,)).fetchone()[0])
            if expected is None or expected != recips:
                rid = core.deny_receipt(ctx, action, "recipient_not_allowed", file_id)
                raise QGError("QG_DENY_POLICY", "recipient_not_allowed", receipt_id=rid)
        _check_recipients(core, conn, ctx, file_id, m.classification, recips, action)
        ver = conn.execute("SELECT status FROM file_versions WHERE file_id = ? AND version = ?",
                           (file_id, version)).fetchone()
        if ver is None or ver["status"] != "pending":
            raise QGError("QG_CONFLICT", "already_committed")
        if not core.directory.epoch_acceptable(conn, m.directory_epoch):
            raise QGError("QG_STALE_EPOCH", "stale_epoch")
        old = conn.execute("SELECT current_version FROM files WHERE file_id = ?", (file_id,)).fetchone()[0]
        for did in recips:
            _seal_slot(core, conn, file_id, version, did, inners[did], m.directory_epoch)
        if recovery is not None:
            _seal_slot(core, conn, file_id, version, RECOVERY_DEVICE_ID, recovery, m.directory_epoch)
        now = core.clock.iso()
        conn.execute("UPDATE file_versions SET status = 'committed', manifest = ?, manifest_sig = ?,"
                     " ciphertext_sha256 = ?, committed_at = ?, committed_by_device = ? WHERE file_id = ? AND version = ?",
                     (json.dumps(manifest), body.manifest_sig, m.ciphertext_sha256, now, ctx.device_id, file_id, version))
        conn.execute("UPDATE files SET current_version = ?, updated_at = ? WHERE file_id = ?", (version, now, file_id))
        if old:
            conn.execute("UPDATE file_versions SET status = 'superseded' WHERE file_id = ? AND version = ?",
                         (file_id, old))
            conn.execute("DELETE FROM slots WHERE file_id = ? AND version = ?", (file_id, old))
            conn.execute("UPDATE leases SET cancelled = 1 WHERE file_id = ? AND version = ?", (file_id, old))
            core.db.on_commit(lambda: core.blobs.delete_version(file_id, old))
        rc = core.receipt(conn, action=action, decision="allow", reason="committed", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=file_id, matched=decision.matched_rules,
                          key_epoch=version)
        if reason == "rekey":
            core.finish_rekey(conn, file_id, version, rc["id"])
        frow = file_row(conn, file_id)
        view = file_view(conn, frow, ctx.device_id)
    ctx.set_receipt(rc["id"])
    return {"file": view, "receipt_id": rc["id"]}


# ---- key release -------------------------------------------------------------------------------


@router.get("/files/{file_id}/slot")
def get_slot(file_id: str, request: Request, ctx: Ctx = gateway("slot.release")) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        row, facts = access(core, conn, ctx, file_id, "slot.release", receipt_action="slot.release")
        version = row["current_version"]
        responses = core.active_responses(conn, session_id=ctx.session_id, device_id=ctx.device_id,
                                          user_id=ctx.user_id)
        user = conn.execute("SELECT status FROM users WHERE user_id = ?", (ctx.user_id,)).fetchone()
        frozen = any(r["action"] == "freeze_key_release" for r in responses)
        quarantined = row["classification"] in SENSITIVE and (
            user["status"] == "quarantined" or any(r["action"] == "quarantine_identity" for r in responses))
    if frozen or quarantined:
        rid = core.deny_receipt(ctx, "slot.release", "key_release_frozen" if frozen else "identity_quarantined",
                                file_id, key_epoch=version)
        if frozen:
            raise QGError("QG_UNAVAILABLE_FAIL_CLOSED", "key_release_frozen", receipt_id=rid)
        raise QGError("QG_QUARANTINED", "identity_quarantined", receipt_id=rid)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        slot = conn.execute("SELECT * FROM slots WHERE file_id = ? AND version = ? AND device_id = ?",
                            (file_id, version, ctx.device_id)).fetchone()
        if slot is None:
            raise QGError("QG_DENY_POLICY", "policy_denied")
        ver = conn.execute("SELECT * FROM file_versions WHERE file_id = ? AND version = ?",
                           (file_id, version)).fetchone()
        try:
            inner = json.loads(aead.unseal(core.keys.seal_master, slot["seal_epoch"],
                                           aead.seal_aad(slot["slot_id"], file_id, version, ctx.device_id,
                                                         slot["seal_epoch"]), bytes(slot["sealed"])))
        except aead.AeadError as exc:
            raise QGError("QG_UNAVAILABLE_FAIL_CLOSED", "seal_integrity") from exc
        lease_id = new_id("lse")
        expires = fmt(core.clock.now() + timedelta(seconds=LEASE_SECONDS))
        conn.execute("INSERT INTO leases (lease_id, session_id, device_id, file_id, version, expires_at)"
                     " VALUES (?,?,?,?,?,?)", (lease_id, ctx.session_id, ctx.device_id, file_id, version, expires))
        rc = core.receipt(conn, action="slot.release", decision="allow", reason="released", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=file_id,
                          matched=["P-FILE-HOLDER"], key_epoch=version)
        conn.execute("INSERT INTO releases (receipt_id, file_id, version, device_id, ts) VALUES (?,?,?,?,?)",
                     (rc["id"], file_id, version, ctx.device_id, rc["ts"]))
        core.emit(conn, "access", ctx.subject, [rc["id"]], resource=file_id, classification=row["classification"])
        manifest = json.loads(ver["manifest"])
    ctx.set_receipt(rc["id"])
    return {
        "slot_id": slot["slot_id"],
        "file_id": file_id,
        "version": version,
        "device_id": ctx.device_id,
        "wrap_epoch": slot["wrap_epoch"],
        "inner_wrap": inner,
        "manifest": manifest,
        "manifest_sig": ver["manifest_sig"],
        "signer_device_id": ver["committed_by_device"],
        "lease": {"lease_id": lease_id, "expires_at": expires},
        "receipt_id": rc["id"],
    }


@router.get("/files/{file_id}/chunks/{index}", response_class=Response)
def get_chunk(file_id: str, index: PathInt, request: Request, ctx: Ctx = gateway("chunk.read")) -> Response:
    core = core_of(request)
    lease_id = request.headers.get("qg-lease", "")
    with core.db.tx() as conn:
        live(core, conn, ctx)
        row = file_row(conn, file_id)
        lease = conn.execute("SELECT * FROM leases WHERE lease_id = ?", (lease_id,)).fetchone() if is_id(
            lease_id, "lse") else None
        recovery_lease = row is not None and lease is not None and lease["kind"] == "recovery"
        if row is None or not (recovery_lease or row["owner_user_id"] == ctx.user_id
                               or person_has_slot(conn, file_id, ctx.user_id)):
            raise QGError("QG_NOT_FOUND", "not_found")
        ok = (lease is not None and not lease["cancelled"] and lease["device_id"] == ctx.device_id
              and lease["session_id"] == ctx.session_id
              and lease["file_id"] == file_id and lease["version"] == row["current_version"]
              and parse(lease["expires_at"]) > core.clock.now()
              and (recovery_lease or holds_slot(conn, file_id, row["current_version"], ctx.device_id)))
        if ok:
            ver = conn.execute("SELECT chunk_count FROM file_versions WHERE file_id = ? AND version = ?",
                               (file_id, row["current_version"])).fetchone()
            if not 0 <= index < ver[0]:
                raise QGError("QG_NOT_FOUND", "not_found")
            rc = core.receipt(conn, action="chunk.read", decision="allow", reason="lease_valid", subject=ctx.subject,
                              request_hash=ctx.request_hash, resource=file_id, key_epoch=row["current_version"])
    if not ok:
        rid = core.deny_receipt(ctx, "chunk.read", "lease_expired", file_id)
        raise QGError("QG_LEASE_EXPIRED", "lease_expired", receipt_id=rid)
    blob = core.blobs.get(file_id, row["current_version"], index)
    if blob is None:
        raise QGError("QG_UNAVAILABLE_FAIL_CLOSED", "storage_unavailable")
    ctx.set_receipt(rc["id"])
    return Response(content=blob, media_type="application/octet-stream")


# ---- share and unshare ---------------------------------------------------------------------------


class ShareStatement(Strict):
    directory_epoch: int
    file_id: Annotated[str, Field(max_length=26)]
    recipients: Annotated[list[DevId], Field(min_length=1, max_length=MAX_RECIPIENTS)]
    suite: Literal["QG-1"]
    version: int


class Share(Strict):
    share: ShareStatement
    share_sig: B64
    wraps: Annotated[list[Wrap], Field(min_length=1, max_length=MAX_RECIPIENTS)]


@router.post("/files/{file_id}/share", openapi_extra=body_openapi(Share))
def share_file(file_id: str, request: Request, ctx: Ctx = gateway("file.share"), body: Share = json_body(Share)) -> dict:
    core = core_of(request)
    s = body.share
    recips = list(s.recipients)
    if recips != sorted(set(recips)) or sorted(w.device_id for w in body.wraps) != recips or s.file_id != file_id:
        raise QGError("QG_INVALID_INPUT", "share_mismatch")
    inners = {w.device_id: _check_wrap(w) for w in body.wraps}
    try:
        sig = b64u_decode(body.share_sig)
    except EncodingError:
        sig = b""
    with core.db.tx() as conn:
        live(core, conn, ctx)
        row, _ = access(core, conn, ctx, file_id, "file.share", receipt_action="file.share")
        sig_pk = conn.execute("SELECT sig_pk FROM devices WHERE device_id = ?", (ctx.device_id,)).fetchone()[0]
        current = row["current_version"]
    if not sig or not mldsa_verify(bytes(sig_pk), sig, canon(s.model_dump()), "share"):
        rid = core.deny_receipt(ctx, "file.share", "bad_signature", file_id)
        core.emit_now("signature_failure", ctx.subject, [rid], kind="share")
        raise QGError("QG_BAD_SIGNATURE", "bad_signature", receipt_id=rid)
    if s.version != current:
        raise QGError("QG_CONFLICT", "version_changed")
    with core.db.tx() as conn:
        epoch_ok = core.directory.epoch_acceptable(conn, s.directory_epoch)
    if not epoch_ok:
        rid = core.deny_receipt(ctx, "file.share", "stale_epoch", file_id)
        core.emit_now("stale_epoch", ctx.subject, [rid], epoch=s.directory_epoch)
        raise QGError("QG_STALE_EPOCH", "stale_epoch", receipt_id=rid)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        _check_recipients(core, conn, ctx, file_id, row["classification"], recips, "file.share")
        if conn.execute("SELECT current_version FROM files WHERE file_id = ?", (file_id,)).fetchone()[0] != current:
            raise QGError("QG_CONFLICT", "version_changed")
        for did in recips:
            if holds_slot(conn, file_id, current, did):
                raise QGError("QG_CONFLICT", "already_shared")
            _seal_slot(core, conn, file_id, current, did, inners[did], s.directory_epoch)
        conn.execute("UPDATE files SET updated_at = ? WHERE file_id = ?", (core.clock.iso(), file_id))
        rc = core.receipt(conn, action="file.share", decision="allow", reason="shared", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=file_id, matched=["P-FILE-HOLDER"],
                          key_epoch=current)
        view = file_view(conn, file_row(conn, file_id), ctx.device_id)
    ctx.set_receipt(rc["id"])
    return {"file": view, "receipt_id": rc["id"]}


class Unshare(Strict):
    user_id: Annotated[str, Field(min_length=26, max_length=26)]


@router.post("/files/{file_id}/unshare", openapi_extra=body_openapi(Unshare))
def unshare_file(file_id: str, request: Request, ctx: Ctx = gateway("file.unshare"),
                 body: Unshare = json_body(Unshare)) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        row, _ = access(core, conn, ctx, file_id, "file.unshare", receipt_action="file.unshare")
        if body.user_id == row["owner_user_id"]:
            raise QGError("QG_INVALID_INPUT", "cannot_unshare_owner")
        devs = [r[0] for r in conn.execute("SELECT device_id FROM devices WHERE user_id = ?", (body.user_id,))]
        removed = 0
        for did in devs:
            removed += conn.execute("DELETE FROM slots WHERE file_id = ? AND device_id = ?", (file_id, did)).rowcount
            conn.execute("UPDATE leases SET cancelled = 1 WHERE file_id = ? AND device_id = ?", (file_id, did))
        if removed == 0:
            raise QGError("QG_NOT_FOUND", "not_found")
        core.queue_rekey(conn, file_id, row["current_version"], "unshare", None)
        rc = core.receipt(conn, action="file.unshare", decision="allow", reason="unshared", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=file_id, matched=["P-FILE-OWNER"],
                          key_epoch=row["current_version"])
        view = file_view(conn, file_row(conn, file_id), ctx.device_id)
    ctx.set_receipt(rc["id"])
    return {"file": view, "receipt_id": rc["id"]}


# ---- re-key queue --------------------------------------------------------------------------------


@router.get("/rekey/pending")
def rekey_pending(request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "rekey.list")
        rekeys = []
        order = {"exposed": 0, "held": 1, "unshare": 2}
        jobs = conn.execute(
            "SELECT j.*, f.name, f.current_version FROM rekey_jobs j JOIN files f ON f.file_id = j.file_id"
            " WHERE j.status IN ('pending', 'in_progress') AND f.deleted = 0 AND j.from_version = f.current_version"
            " ORDER BY j.created_at").fetchall()
        seen = set()
        for j in sorted(jobs, key=lambda j: order.get(j["reason"], 9)):
            if j["file_id"] in seen or not holds_slot(conn, j["file_id"], j["current_version"], ctx.device_id):
                continue
            seen.add(j["file_id"])
            recipients = [r[0] for r in conn.execute(
                "SELECT s.device_id FROM slots s JOIN devices d ON d.device_id = s.device_id WHERE s.file_id = ?"
                " AND s.version = ? AND d.status = 'active' ORDER BY s.device_id", (j["file_id"], j["current_version"]))]
            rekeys.append({"file_id": j["file_id"], "name": j["name"], "version": j["current_version"],
                           "reason": j["reason"], "incident_id": j["incident_id"], "recipients": recipients})
        shares = []
        mine = conn.execute("SELECT s.file_id, f.name, f.current_version FROM slots s JOIN files f ON f.file_id ="
                            " s.file_id WHERE s.device_id = ? AND s.version = f.current_version AND f.deleted = 0",
                            (ctx.device_id,)).fetchall()
        others = conn.execute("SELECT device_id, name FROM devices WHERE user_id = ? AND status = 'active'"
                              " AND device_id != ?", (ctx.user_id, ctx.device_id)).fetchall()
        for f in mine:
            if f["file_id"] in seen:
                continue
            for o in others:
                if not holds_slot(conn, f["file_id"], f["current_version"], o["device_id"]):
                    shares.append({"file_id": f["file_id"], "name": f["name"], "version": f["current_version"],
                                   "device_id": o["device_id"], "device_name": o["name"]})
    return {"rekeys": rekeys, "shares": shares}
