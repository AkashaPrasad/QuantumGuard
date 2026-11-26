"""Privilege graph (no ML): people -> roles -> capabilities -> crown-jewel resources (restricted files and the
recovery key). Used by QG-R007 to draw the new path that an unapproved privilege opens."""

from __future__ import annotations

import sqlite3
from typing import Any

CAPABILITIES = {
    "admin": [("approve", "recovery_release"), ("request", "role_grant")],
    "operator": [("approve", "recovery_release"), ("revoke", "devices")],
}


def crown_jewels(conn: sqlite3.Connection) -> list[dict[str, str]]:
    rows = conn.execute("SELECT file_id, name FROM files WHERE classification = 'restricted' AND deleted = 0"
                        " AND is_decoy = 0 AND current_version > 0 ORDER BY file_id").fetchall()
    return [{"id": r[0], "name": r[1]} for r in rows]


def path_for_role(conn: sqlite3.Connection, user_id: str, role: str, *, signed: bool) -> list[dict[str, Any]]:
    """Edges from a person through a role to crown-jewel resources."""
    if role not in CAPABILITIES:
        return []
    jewels = crown_jewels(conn)
    edges: list[dict[str, Any]] = [{"from": user_id, "to": f"role:{role}",
                                    "relation": "holds_role" if signed else "holds_role_unsigned"}]
    for verb, obj in CAPABILITIES[role]:
        edges.append({"from": f"role:{role}", "to": f"capability:{verb}:{obj}", "relation": "grants"})
        if obj == "recovery_release":
            edges.append({"from": f"capability:{verb}:{obj}", "to": "key:recovery", "relation": "unlocks"})
            for j in jewels:
                edges.append({"from": "key:recovery", "to": f"file:{j['id']}", "relation": "opens"})
    return edges
