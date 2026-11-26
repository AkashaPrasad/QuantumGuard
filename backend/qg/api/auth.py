"""Public routes, enrolment (spec/SUITE.md 5.1) and session handshake (5.2)."""

from __future__ import annotations

import json
import os
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, Request, Response
from pydantic import Field

from qg.api.common import client_ip
from qg.clock import fmt, parse
from qg.core import code_hash
from qg.crypto import kdf, xwing
from qg.crypto.encoding import EncodingError, b64u, b64u_decode
from qg.crypto.sign import mldsa_valid_public_key, mldsa_verify
from qg.crypto.suite import (
    CHUNK_BYTES,
    LEASE_SECONDS,
    MAX_FILE_BYTES,
    MAX_RECIPIENTS,
    SESSION_HARD_CAP_SECONDS,
    SESSION_START_SECONDS,
    SESSION_TTL_SECONDS,
    SUITE,
)
from qg.crypto.transcripts import enroll_transcript, request_hash, session_transcript
from qg.errors import QGError
from qg.gateway.http import Ctx, Strict, body_openapi, core_of, gateway, json_body, raw_target
from qg.ids import is_id, new_id
from qg.session.store import Pending

router = APIRouter()

B64 = Annotated[str, Field(min_length=1, max_length=8192, pattern=r"^[A-Za-z0-9_-]+$")]


def _public_rate(request: Request, bucket: str) -> None:
    core = core_of(request)
    rate, burst = core.public_rate
    wait = core.buckets.take(f"{bucket}:{client_ip(request)}", rate, burst, core.clock.monotonic())
    if wait > 0:
        raise QGError("QG_RATE_LIMITED", "rate_limited", retry_after=int(wait) + 1)


def _public_hash(request: Request, body: bytes) -> str:
    return request_hash(request.method, raw_target(request), 0, body)


# ---- public reads ----------------------------------------------------------------------------


@router.get("/healthz", tags=["public"])
def healthz() -> dict:
    return {"status": "ok"}


@router.get("/api/v1/meta", tags=["public"])
def meta(request: Request) -> dict:
    core = core_of(request)
    return {
        "suite": SUITE,
        "version": "1",
        "commit": core.settings.commit,
        "demo": core.settings.demo,
        "server_keys": {
            "ed25519_pk": b64u(core.keys.signer.ed.public_key),
            "mldsa_pk": b64u(core.keys.signer.pq.public_key),
            "kem_pk": b64u(core.keys.kem.public_key),
        },
        "recovery_pk": b64u(core.keys.recovery_pk),
        "policy_bundle_hash": core.policy.hash,
        "limits": {
            "chunk_bytes": CHUNK_BYTES,
            "max_file_bytes": MAX_FILE_BYTES,
            "max_recipients": MAX_RECIPIENTS,
            "lease_seconds": LEASE_SECONDS,
            "session_ttl_seconds": SESSION_TTL_SECONDS,
            "session_hard_cap_seconds": SESSION_HARD_CAP_SECONDS,
        },
        "features": {"messaging": True, "slhdsa": False},
    }


@router.get("/api/v1/directory", tags=["public"])
def directory(request: Request) -> dict:
    core = core_of(request)
    epoch_q = request.query_params.get("epoch")
    epoch = None
    if epoch_q is not None:
        if not epoch_q.isdigit() or len(epoch_q) > 12:
            raise QGError("QG_INVALID_INPUT", "bad_epoch")
        epoch = int(epoch_q)
    with core.db.tx() as conn:
        doc = core.directory.get(conn, epoch)
    if doc is None:
        raise QGError("QG_NOT_FOUND", "not_found")
    return doc


@router.get("/api/v1/log/checkpoint", tags=["public"])
def checkpoint(request: Request) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        cp = core.log.checkpoint(conn, force=True) or core.log.latest_checkpoint()
    if cp is None:
        raise QGError("QG_NOT_FOUND", "not_found")
    return cp


@router.get("/api/v1/keys", tags=["public"])
def keyset(request: Request) -> dict:
    row = core_of(request).db.one("SELECT doc FROM keysets ORDER BY epoch DESC LIMIT 1")
    if row is None:
        raise QGError("QG_NOT_FOUND", "not_found")
    return json.loads(row["doc"])


def _bench_path() -> Path:
    env = os.environ.get("QG_BENCH_FILE")
    return Path(env) if env else Path(__file__).resolve().parents[3] / "bench" / "latest.json"


@router.get("/api/v1/bench/latest", tags=["public"])
def bench_latest() -> dict:
    try:
        return json.loads(_bench_path().read_text())
    except (OSError, ValueError) as exc:
        raise QGError("QG_NOT_FOUND", "not_found") from exc


# ---- enrolment -------------------------------------------------------------------------------


class EnrollStart(Strict):
    suite: Literal["QG-1"]
    code: Annotated[str, Field(min_length=10, max_length=64)]
    device_name: Annotated[str, Field(min_length=1, max_length=64)]
    kem_pk: B64
    sig_pk: B64


class EnrollFinish(Strict):
    enroll_id: Annotated[str, Field(min_length=26, max_length=26)]
    signature: B64
    key_confirm: B64


def _enrolment_held(conn, user_id: str) -> bool:  # noqa: ANN001
    open_inc = conn.execute(
        "SELECT reported_at FROM incidents WHERE user_id = ? AND status IN ('open', 'rekeying') "
        "ORDER BY reported_at DESC LIMIT 1",
        (user_id,),
    ).fetchone()
    active_hold = conn.execute(
        "SELECT 1 FROM responses WHERE action = 'hold_enrolment' AND scope_id = ? AND lifted_at IS NULL LIMIT 1",
        (user_id,),
    ).fetchone()
    if active_hold:
        return True
    if open_inc is None:
        return False
    lifted = conn.execute(
        "SELECT 1 FROM responses WHERE action = 'hold_enrolment' AND scope_id = ? AND lifted_at >= ? LIMIT 1",
        (user_id, open_inc[0]),
    ).fetchone()
    return lifted is None


@router.post("/api/v1/enroll/start", tags=["enrolment"], openapi_extra=body_openapi(EnrollStart))
def enroll_start(request: Request, body: EnrollStart = json_body(EnrollStart)) -> dict:
    core = core_of(request)
    _public_rate(request, "enroll")
    raw = request.state.raw_body if hasattr(request.state, "raw_body") else b""
    rh = _public_hash(request, raw)
    try:
        kem_pk = b64u_decode(body.kem_pk, length=1216)
        sig_pk = b64u_decode(body.sig_pk, length=1952)
        xwing.validate_public_key(kem_pk)
    except (EncodingError, xwing.XWingError) as exc:
        raise QGError("QG_INVALID_INPUT", "bad_public_key") from exc
    if not mldsa_valid_public_key(sig_pk):
        raise QGError("QG_INVALID_INPUT", "bad_public_key")
    now = core.clock.now()
    with core.db.tx() as conn:
        inv = conn.execute("SELECT * FROM invites WHERE code_hash = ?", (code_hash(body.code),)).fetchone()
        valid = inv is not None and inv["status"] == "pending" and parse(inv["expires_at"]) > now
        if not valid:
            rc = core.receipt(conn, action="enroll", decision="deny", reason="invite_invalid",
                              subject={"user_id": None, "device_id": None, "session_id": None}, request_hash=rh)
            invalid_receipt = rc["id"]
        else:
            invalid_receipt = None
            user = conn.execute("SELECT user_id, name, status FROM users WHERE user_id = ?", (inv["user_id"],)).fetchone()
            roles = core.directory.roles(conn, user["user_id"])
            held = _enrolment_held(conn, user["user_id"])
            epoch = core.directory.current_epoch(conn)
    if invalid_receipt:
        request.state.receipt_id = invalid_receipt
        raise QGError("QG_INVALID_INPUT", "invite_invalid", receipt_id=invalid_receipt)
    subject = {"user_id": user["user_id"], "device_id": None, "session_id": None}
    if held:
        with core.db.tx() as conn:
            rc = core.receipt(conn, action="enroll", decision="deny", reason="enrolment_held", subject=subject,
                              request_hash=rh)
            core.emit(conn, "enrol_during_loss", subject, [rc["id"]])
        request.state.receipt_id = rc["id"]
        raise QGError("QG_QUARANTINED", "enrolment_held", receipt_id=rc["id"])
    if user["status"] == "disabled":
        raise QGError("QG_INVALID_INPUT", "invite_invalid")
    ss, ct = xwing.encapsulate(kem_pk)
    challenge = os.urandom(32)
    enroll_id = new_id("enr")
    server_time = fmt(now)
    ttl = min(300.0, (parse(inv["expires_at"]) - now).total_seconds())
    core.secrets.put_pending(
        enroll_id,
        Pending("enroll", core.clock.monotonic() + ttl, {
            "invite_id": inv["invite_id"], "user_id": user["user_id"], "device_name": body.device_name,
            "kem_pk": kem_pk, "sig_pk": sig_pk, "kem_pk_b64u": body.kem_pk, "sig_pk_b64u": body.sig_pk,
            "challenge": challenge, "xwing_ct": ct, "ss": ss, "epoch": epoch, "server_time": server_time,
        }),
        core.clock.monotonic(),
    )
    return {
        "enroll_id": enroll_id,
        "challenge": b64u(challenge),
        "xwing_ct": b64u(ct),
        "user": {"user_id": user["user_id"], "name": user["name"], "roles": roles},
        "directory_epoch": epoch,
        "server_time": server_time,
    }


@router.post("/api/v1/enroll/finish", tags=["enrolment"], openapi_extra=body_openapi(EnrollFinish))
def enroll_finish(request: Request, body: EnrollFinish = json_body(EnrollFinish)) -> dict:
    core = core_of(request)
    _public_rate(request, "enroll")
    rh = _public_hash(request, getattr(request.state, "raw_body", b""))
    p = core.secrets.take_pending(body.enroll_id, "enroll", core.clock.monotonic())
    if p is None:
        raise QGError("QG_INVALID_INPUT", "invite_invalid")
    d = p.data
    t = enroll_transcript(
        enroll_id=body.enroll_id, user_id=d["user_id"], device_name=d["device_name"], kem_pk_b64u=d["kem_pk_b64u"],
        sig_pk_b64u=d["sig_pk_b64u"], challenge_b64u=b64u(d["challenge"]), xwing_ct_b64u=b64u(d["xwing_ct"]),
        directory_epoch=d["epoch"], server_time=d["server_time"],
    )
    try:
        sig = b64u_decode(body.signature)
        confirm = b64u_decode(body.key_confirm, length=48)
    except EncodingError:
        sig, confirm = b"", b""
    ok_sig = bool(sig) and mldsa_verify(d["sig_pk"], sig, t, "enroll")
    ok_kc = bool(confirm) and kdf.verify_hmac384(kdf.enroll_confirm_key(d["ss"], d["challenge"]), t, confirm)
    subject = {"user_id": d["user_id"], "device_id": None, "session_id": None}
    if not (ok_sig and ok_kc):
        with core.db.tx() as conn:
            rc = core.receipt(conn, action="enroll", decision="deny", reason="proof_failed", subject=subject,
                              request_hash=rh)
            core.emit(conn, "signature_failure", subject, [rc["id"]], kind="enroll", source=client_ip(request))
        request.state.receipt_id = rc["id"]
        raise QGError("QG_BAD_SIGNATURE", "proof_failed", receipt_id=rc["id"])
    now = core.clock.now()
    with core.db.tx() as conn:
        inv = conn.execute("SELECT status, expires_at FROM invites WHERE invite_id = ?", (d["invite_id"],)).fetchone()
        if inv is None or inv["status"] != "pending" or parse(inv["expires_at"]) <= now:
            raise QGError("QG_INVALID_INPUT", "invite_invalid")
        if _enrolment_held(conn, d["user_id"]):
            raise QGError("QG_QUARANTINED", "enrolment_held")
        device_id = new_id("dev")
        epoch = core.directory.current_epoch(conn) + 1
        created, expires = core.directory.new_device_times()
        cert = core.directory.certificate(
            device_id=device_id, user_id=d["user_id"], name=d["device_name"], kem_pk=d["kem_pk"], sig_pk=d["sig_pk"],
            created_at=created, expires_at=expires, directory_epoch=epoch,
        )
        conn.execute(
            "INSERT INTO devices (device_id, user_id, name, kem_pk, sig_pk, status, created_at, expires_at,"
            " directory_epoch, certificate) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (device_id, d["user_id"], d["device_name"], d["kem_pk"], d["sig_pk"], "active", created, expires, epoch,
             json.dumps(cert)),
        )
        conn.execute("UPDATE invites SET status = 'used', used_at = ?, used_by_device = ? WHERE invite_id = ?",
                     (fmt(now), device_id, d["invite_id"]))
        doc = core.directory.publish(conn, "enroll")
        rc = core.receipt(conn, action="enroll", decision="allow", reason="enrolled",
                          subject={**subject, "device_id": device_id}, request_hash=rh, resource=device_id)
    request.state.receipt_id = rc["id"]
    return {"certificate": cert, "directory": doc}


# ---- session ---------------------------------------------------------------------------------


class SessionStart(Strict):
    suite: Literal["QG-1"]
    device_id: Annotated[str, Field(min_length=1, max_length=64)]


class SessionFinish(Strict):
    start_id: Annotated[str, Field(min_length=26, max_length=26)]
    signature: B64
    key_confirm: B64


@router.post("/api/v1/session/start", tags=["session"], openapi_extra=body_openapi(SessionStart))
def session_start(request: Request, body: SessionStart = json_body(SessionStart)) -> dict:
    core = core_of(request)
    _public_rate(request, "session")
    if not is_id(body.device_id, "dev"):
        raise QGError("QG_INVALID_INPUT", "bad_device_id")
    with core.db.tx() as conn:
        dev = conn.execute("SELECT kem_pk, status FROM devices WHERE device_id = ?", (body.device_id,)).fetchone()
        epoch = core.directory.current_epoch(conn)
    challenge = os.urandom(32)
    if dev is not None and dev["status"] != "revoked":
        ss, ct = xwing.encapsulate(bytes(dev["kem_pk"]))
    else:
        ss, ct = None, os.urandom(1120)  # same shape for unknown and revoked devices
    start_id = new_id("sst")
    server_time = core.clock.iso()
    core.secrets.put_pending(
        start_id,
        Pending("session", core.clock.monotonic() + SESSION_START_SECONDS, {
            "device_id": body.device_id, "challenge": challenge, "xwing_ct": ct, "ss": ss, "epoch": epoch,
            "server_time": server_time,
        }),
        core.clock.monotonic(),
    )
    return {"start_id": start_id, "challenge": b64u(challenge), "xwing_ct": b64u(ct), "directory_epoch": epoch,
            "server_time": server_time}


@router.post("/api/v1/session/finish", tags=["session"], openapi_extra=body_openapi(SessionFinish))
def session_finish(request: Request, body: SessionFinish = json_body(SessionFinish)) -> dict:
    core = core_of(request)
    _public_rate(request, "session")
    rh = _public_hash(request, getattr(request.state, "raw_body", b""))
    p = core.secrets.take_pending(body.start_id, "session", core.clock.monotonic())
    if p is None:
        raise QGError("QG_BAD_SIGNATURE", "start_unknown")
    d = p.data
    device_id = d["device_id"]
    with core.db.tx() as conn:
        dev = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        if dev is not None:
            user = conn.execute("SELECT * FROM users WHERE user_id = ?", (dev["user_id"],)).fetchone()
    if dev is None:
        raise QGError("QG_BAD_SIGNATURE", "proof_failed")
    subject = {"user_id": dev["user_id"], "device_id": device_id, "session_id": None}
    if dev["status"] == "revoked":
        with core.db.tx() as conn:
            rc = core.receipt(conn, action="session.start", decision="deny", reason="device_revoked",
                              subject=subject, request_hash=rh, resource=device_id)
            core.record_denied_attempt(conn, device_id, rc["id"])
            core.emit(conn, "revoked_device_attempt", subject, [rc["id"]])
        request.state.receipt_id = rc["id"]
        raise QGError("QG_DENY_REVOKED", "device_revoked", receipt_id=rc["id"])
    t = session_transcript(start_id=body.start_id, device_id=device_id, challenge_b64u=b64u(d["challenge"]),
                           xwing_ct_b64u=b64u(d["xwing_ct"]), directory_epoch=d["epoch"],
                           server_time=d["server_time"])
    try:
        sig = b64u_decode(body.signature)
        confirm = b64u_decode(body.key_confirm, length=48)
    except EncodingError:
        sig, confirm = b"", b""
    ok = (
        d["ss"] is not None
        and bool(sig)
        and mldsa_verify(bytes(dev["sig_pk"]), sig, t, "session")
        and kdf.verify_hmac384(kdf.session_confirm_key(d["ss"], d["challenge"]), t, confirm)
    )
    if not ok:
        with core.db.tx() as conn:
            rc = core.receipt(conn, action="session.start", decision="deny", reason="proof_failed", subject=subject,
                              request_hash=rh, resource=device_id)
            core.emit(conn, "signature_failure", subject, [rc["id"]], kind="session")
        request.state.receipt_id = rc["id"]
        raise QGError("QG_BAD_SIGNATURE", "proof_failed", receipt_id=rc["id"])
    now = core.clock.now()
    if parse(dev["expires_at"]) <= now:
        raise QGError("QG_DENY_POLICY", "device_expired")
    if dev["status"] == "quarantined":
        raise QGError("QG_QUARANTINED", "device_quarantined")
    if user["status"] == "disabled":
        raise QGError("QG_DENY_POLICY", "user_disabled")
    k_mac = kdf.session_mac_key(d["ss"], d["challenge"])
    session_id = new_id("ses")
    hard = now + timedelta(seconds=SESSION_HARD_CAP_SECONDS)
    with core.db.tx() as conn:
        dev2 = conn.execute("SELECT status FROM devices WHERE device_id = ?", (device_id,)).fetchone()
        if dev2["status"] != "active":
            raise QGError("QG_DENY_REVOKED", "device_revoked")
        first = conn.execute(
            "SELECT 1 FROM receipts WHERE device_id = ? AND action = 'session.start' AND decision = 'allow' LIMIT 1",
            (device_id,),
        ).fetchone() is None
        conn.execute(
            "INSERT INTO sessions (session_id, device_id, user_id, last_seq, created_at, last_used_at, hard_expires_at)"
            " VALUES (?,?,?,0,?,?,?)",
            (session_id, device_id, dev["user_id"], fmt(now), fmt(now), fmt(hard)),
        )
        conn.execute("UPDATE devices SET last_seen_at = ? WHERE device_id = ?", (fmt(now), device_id))
        core.secrets.set_mac(session_id, k_mac)
        core.db.on_rollback(lambda: core.secrets.drop_mac(session_id))
        rc = core.receipt(conn, action="session.start", decision="allow", reason="session_started",
                          subject={**subject, "session_id": session_id}, request_hash=rh, resource=device_id)
        roles = core.directory.roles(conn, dev["user_id"])
        epoch = core.directory.current_epoch(conn)
    request.state.receipt_id = rc["id"]
    return {
        "session_id": session_id,
        "expires_at": fmt(min(now + timedelta(seconds=SESSION_TTL_SECONDS), hard)),
        "hard_expires_at": fmt(hard),
        "user": {"user_id": dev["user_id"], "name": user["name"], "roles": roles, "status": user["status"]},
        "device": {"device_id": device_id, "name": dev["name"]},
        "directory_epoch": epoch,
        "first_session": first,
    }


@router.post("/api/v1/session/end", tags=["session"], status_code=204, response_class=Response)
def session_end(request: Request, ctx: Ctx = gateway("session.end")) -> Response:
    core = core_of(request)
    with core.db.tx() as conn:
        rc = core.receipt(conn, action="session.end", decision="allow", reason="session_ended", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=ctx.session_id)
        core.end_sessions(conn, where="session_id = ?", params=(ctx.session_id,), reason="ended")
    ctx.set_receipt(rc["id"])
    return Response(status_code=204)
