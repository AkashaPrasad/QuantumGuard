"""Per-device message envelopes (workflow 4, spec/SUITE.md section 11)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Request
from pydantic import Field

from qg.api.common import page_params, paginate
from qg.crypto.encoding import EncodingError, b64u_decode
from qg.crypto.messages import digests_for
from qg.crypto.messages import statement as message_statement
from qg.crypto.sign import mldsa_verify
from qg.crypto.suite import MAX_RECIPIENTS
from qg.errors import QGError
from qg.gateway.http import Ctx, Strict, authorize, body_openapi, core_of, gateway, json_body, live
from qg.ids import is_id, new_id

router = APIRouter(prefix="/api/v1", tags=["messages"])

B64 = Annotated[str, Field(min_length=1, max_length=90000, pattern=r"^[A-Za-z0-9_-]+$")]


class Envelope(Strict):
    device_id: Annotated[str, Field(min_length=26, max_length=26)]
    xwing_ct: B64
    ciphertext: B64


class MessageCreate(Strict):
    to_user_id: Annotated[str, Field(min_length=26, max_length=26)]
    envelopes: Annotated[list[Envelope], Field(min_length=1, max_length=MAX_RECIPIENTS)]
    signature: B64


def statement(to_user_id: str, envelopes: list[dict]) -> bytes:
    return message_statement(to_user_id, digests_for(envelopes))


@router.get("/messages")
def list_messages(request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    limit, before = page_params(request)
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "message.list")
        rows = conn.execute(
            "SELECT m.*, e.xwing_ct, e.ciphertext, u.name AS from_name FROM messages m JOIN message_envelopes e ON"
            " e.message_id = m.id JOIN users u ON u.user_id = m.from_user WHERE e.device_id = ?"
            " ORDER BY m.created_at DESC, m.id", (ctx.device_id,)).fetchall()
        items = []
        for r in rows:
            # every envelope's digest (not its ciphertext) so this device can check the sender's signature
            others = conn.execute("SELECT device_id, xwing_ct, ciphertext FROM message_envelopes WHERE message_id = ?",
                                  (r["id"],)).fetchall()
            items.append({"message_id": r["id"],
                          "from": {"user_id": r["from_user"], "name": r["from_name"], "device_id": r["from_device"]},
                          "to_user_id": r["to_user_id"], "sent_at": r["created_at"],
                          "envelope": {"xwing_ct": r["xwing_ct"], "ciphertext": r["ciphertext"]},
                          "envelope_digests": digests_for([dict(o) for o in others]),
                          "signature": r["signature"]})
    return paginate(items, "message_id", limit, before)


@router.post("/messages", openapi_extra=body_openapi(MessageCreate))
def send_message(request: Request, ctx: Ctx = gateway("message.send"),
                 body: MessageCreate = json_body(MessageCreate)) -> dict:
    core = core_of(request)
    envs = [e.model_dump() for e in body.envelopes]
    ids = [e["device_id"] for e in envs]
    if len(set(ids)) != len(ids):
        raise QGError("QG_INVALID_INPUT", "duplicate_device")
    for e in envs:
        try:
            b64u_decode(e["xwing_ct"], length=1120)
            if len(b64u_decode(e["ciphertext"])) < 28:
                raise QGError("QG_INVALID_INPUT", "bad_envelope")
        except EncodingError as exc:
            raise QGError("QG_INVALID_INPUT", "bad_envelope") from exc
    try:
        sig = b64u_decode(body.signature)
    except EncodingError:
        sig = b""
    with core.db.tx() as conn:
        live(core, conn, ctx)
        d = authorize(core, conn, ctx, "message.send", receipt_action="message.send")
        sig_pk = conn.execute("SELECT sig_pk FROM devices WHERE device_id = ?", (ctx.device_id,)).fetchone()[0]
    if not sig or not mldsa_verify(bytes(sig_pk), sig, statement(body.to_user_id, envs), "message"):
        rid = core.deny_receipt(ctx, "message.send", "bad_signature", body.to_user_id)
        core.emit_now("signature_failure", ctx.subject, [rid], kind="message")
        raise QGError("QG_BAD_SIGNATURE", "bad_signature", receipt_id=rid)
    with core.db.tx() as conn:
        live(core, conn, ctx)
        if not is_id(body.to_user_id, "usr") or conn.execute("SELECT 1 FROM users WHERE user_id = ?",
                                                              (body.to_user_id,)).fetchone() is None:
            raise QGError("QG_NOT_FOUND", "not_found")
        active = {r[0] for r in conn.execute("SELECT device_id FROM devices WHERE user_id = ? AND status = 'active'",
                                             (body.to_user_id,))}
        if not set(ids) <= active:
            rid = core.deny_receipt(ctx, "message.send", "recipient_not_allowed", body.to_user_id)
            raise QGError("QG_DENY_POLICY", "recipient_not_allowed", receipt_id=rid)
        mid = new_id("msg")
        conn.execute("INSERT INTO messages (id, from_device, from_user, to_user_id, created_at, signature) VALUES"
                     " (?,?,?,?,?,?)", (mid, ctx.device_id, ctx.user_id, body.to_user_id, core.clock.iso(),
                                        body.signature))
        for e in envs:
            conn.execute("INSERT INTO message_envelopes (message_id, device_id, xwing_ct, ciphertext) VALUES (?,?,?,?)",
                         (mid, e["device_id"], e["xwing_ct"], e["ciphertext"]))
        rc = core.receipt(conn, action="message.send", decision="allow", reason="sent", subject=ctx.subject,
                          request_hash=ctx.request_hash, resource=mid, matched=d.matched_rules)
    ctx.set_receipt(rc["id"])
    return {"message_id": mid}
