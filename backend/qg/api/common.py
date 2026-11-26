"""Small helpers shared by routers."""

from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import Request

from qg.errors import QGError
from qg.ids import is_id


def page_params(request: Request) -> tuple[int, str | None]:
    q = request.query_params
    try:
        limit = int(q.get("limit", "50"))
    except ValueError as exc:
        raise QGError("QG_INVALID_INPUT", "bad_limit") from exc
    if not 1 <= limit <= 200:
        raise QGError("QG_INVALID_INPUT", "bad_limit")
    before = q.get("before")
    if before is not None and not is_id(before):
        raise QGError("QG_INVALID_INPUT", "bad_before")
    return limit, before


def paginate(items: list[dict[str, Any]], key: str, limit: int, before: str | None) -> dict[str, Any]:
    """Items must already be in display order (newest first). `before` is the id of the last item seen."""
    if before is not None:
        ids = [i[key] for i in items]
        items = items[ids.index(before) + 1 :] if before in ids else []
    page = items[:limit]
    nxt = page[-1][key] if len(items) > limit and page else None
    return {"items": page, "next_before": nxt}


def user_name(conn: sqlite3.Connection, user_id: str | None) -> str | None:
    if user_id is None:
        return None
    row = conn.execute("SELECT name FROM users WHERE user_id = ?", (user_id,)).fetchone()
    return row[0] if row else None


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"
