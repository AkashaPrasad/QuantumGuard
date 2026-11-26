"""Signed policy bundle (read-only)."""

from __future__ import annotations

from fastapi import APIRouter, Request

from qg.gateway.http import Ctx, authorize, core_of, gateway

router = APIRouter(prefix="/api/v1", tags=["policy"])


@router.get("/policy")
def get_policy(request: Request, ctx: Ctx = gateway()) -> dict:
    core = core_of(request)
    with core.db.tx() as conn:
        authorize(core, conn, ctx, "policy.read")
    return core.policy.public_view()
