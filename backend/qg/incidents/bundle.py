"""Proof bundle export (spec/SUITE.md section 9.5)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from qg.crypto.encoding import b64u
from qg.crypto.suite import SUITE

from . import service

if TYPE_CHECKING:
    from qg.core import Core

FORMAT = "qg-proof-bundle/1"


def incident_leaf_indices(conn, inc) -> list[int]:  # noqa: ANN001
    idx = set()
    rc = conn.execute("SELECT leaf_index FROM receipts WHERE id = ?", (inc["revoke_receipt_id"],)).fetchone()
    if rc:
        idx.add(rc[0])
    for r in conn.execute("SELECT leaf_index FROM receipts WHERE device_id = ? AND (action = 'slot.release'"
                          " OR decision = 'deny' OR action IN ('device.report_lost', 'device.revoke'))",
                          (inc["device_id"],)):
        idx.add(r[0])
    for r in conn.execute("SELECT leaf_index FROM receipts WHERE resource IN (?, ?) AND action IN"
                          " ('device.revoke', 'device.report_lost', 'bundle.export', 'incident.close')",
                          (inc["device_id"], inc["id"])):
        idx.add(r[0])
    for r in conn.execute("SELECT r.leaf_index FROM receipts r JOIN incident_files f ON f.file_id = r.resource"
                          " WHERE f.incident_id = ? AND r.action = 'rekey.commit' AND r.ts >= ?",
                          (inc["id"], inc["reported_at"])):
        idx.add(r[0])
    return sorted(idx)


def build_bundle(core: Core, incident_id: str) -> dict[str, Any]:
    with core.db.tx() as conn:
        inc = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        cp = core.log.checkpoint(conn, force=True)
    with core.db.tx() as conn:
        rev_cp = core.log.checkpoint_at(inc["checkpoint_tree_size"])
        size = cp["tree_size"]
        entries = []
        for i in incident_leaf_indices(conn, inc):
            if i >= size:
                continue
            leaf = conn.execute("SELECT leaf FROM receipts WHERE leaf_index = ?", (i,)).fetchone()[0]
            entries.append({
                "leaf_index": i,
                "leaf_hash": b64u(core.log.tree.leaves[i]),
                "receipt": json.loads(leaf),
                "audit_path": [b64u(h) for h in core.log.tree.inclusion(i, size)],
            })
        consistency = [b64u(h) for h in core.log.tree.consistency(rev_cp["tree_size"], size)] if rev_cp and rev_cp[
            "tree_size"] else []
        body = {
            "format": FORMAT,
            "suite": SUITE,
            "incident_id": incident_id,
            "generated_at": core.clock.iso(),
            "server_keys": core.keys.signer.public_keys,
            "checkpoint": cp,
            "revocation_checkpoint": rev_cp,
            "consistency": consistency,
            "directory": core.directory.get(conn, inc["directory_epoch"]),
            "exposure": service.exposure(conn, inc),
            "entries": entries,
        }
    return core.keys.signer.sign_object(body, "report")
