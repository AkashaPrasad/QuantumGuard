"""Receipts, inclusion and consistency proofs (spec/API.md section 9)."""

from __future__ import annotations

import json

from fastapi import APIRouter, Request

from qg.api.common import page_params, paginate
from qg.crypto.encoding import b64u
from qg.errors import QGError
from qg.gateway.http import Ctx, authorize, core_of, gateway
from qg.ids import is_id

router = APIRouter(prefix="/api/v1", tags=["evidence"])

FILTERS = ("user_id", "device_id", "resource", "action", "decision")


def _can_read_all(core, ctx: Ctx) -> bool:  # noqa: ANN001
    return core.policy.decide(ctx.roles, "receipt.read_all", {"user_active": True, "device_active": True}).allow


@router.get("/log/receipts")
def list_receipts(request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    limit, before = page_params(request)
    q = request.query_params
    clauses, params = [], []
    for f in FILTERS:
        v = q.get(f)
        if v is not None:
            if len(v) > 64:
                raise QGError("QG_INVALID_INPUT", "bad_filter")
            clauses.append(f"{f} = ?")
            params.append(v)
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "receipt.list")
        if not _can_read_all(core, ctx):
            clauses.append("user_id = ?")
            params.append(ctx.user_id)
        if before is not None:
            row = conn.execute("SELECT leaf_index FROM receipts WHERE id = ?", (before,)).fetchone()
            if row is None:
                return {"items": [], "next_before": None}
            clauses.append("leaf_index < ?")
            params.append(row[0])
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = conn.execute(f"SELECT leaf FROM receipts{where} ORDER BY leaf_index DESC LIMIT ?",  # noqa: S608
                            (*params, limit + 1)).fetchall()
    items = [json.loads(r[0]) for r in rows]
    return paginate(items, "id", limit, None)


@router.get("/log/receipts/{receipt_id}")
def get_receipt(receipt_id: str, request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "receipt.read")
        row = conn.execute("SELECT leaf, user_id FROM receipts WHERE id = ?", (receipt_id,)).fetchone() if is_id(
            receipt_id, "rcp") else None
        if row is None or (row["user_id"] != ctx.user_id and not _can_read_all(core, ctx)):
            raise QGError("QG_NOT_FOUND", "not_found")
    return json.loads(row["leaf"])


def _int(request: Request, name: str, default: int | None = None) -> int | None:
    v = request.query_params.get(name)
    if v is None:
        return default
    if not v.isdigit() or len(v) > 15:
        raise QGError("QG_INVALID_INPUT", f"bad_{name}")
    return int(v)


@router.get("/log/proof/{index}")
def get_proof(index: int, request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    tree_size = _int(request, "tree_size")
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "proof.read")
        if tree_size is None:
            core.log.checkpoint(conn, force=True)
    cp = core.log.latest_checkpoint() if tree_size is None else core.log.checkpoint_at(tree_size)
    if cp is None or not 0 <= index < cp["tree_size"]:
        raise QGError("QG_NOT_FOUND", "not_found")
    return {**core.log.proof(index, cp["tree_size"]), "checkpoint": cp}


@router.get("/log/consistency")
def get_consistency(request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    first, second = _int(request, "from"), _int(request, "to")
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "proof.read")
    if first is None or second is None or not 0 < first <= second <= core.log.size:
        raise QGError("QG_INVALID_INPUT", "bad_sizes")
    return {"from": first, "to": second, "proof": [b64u(h) for h in core.log.tree.consistency(first, second)]}
