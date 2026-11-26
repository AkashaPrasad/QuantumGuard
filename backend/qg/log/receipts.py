"""Append-only receipt log with RFC 6962 hashing and batched dual-signed checkpoints."""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Any

from qg.clock import Clock
from qg.crypto.encoding import b64u, canon
from qg.crypto.sign import DualSigner
from qg.crypto.suite import SUITE
from qg.ids import new_id
from qg.storage.db import Database

from . import merkle

CHECKPOINT_EVERY_RECEIPTS = 256
CHECKPOINT_EVERY_SECONDS = 1.0


class MerkleCache:
    """Leaf hashes plus memoised roots of complete, aligned power-of-two subtrees (immutable)."""

    def __init__(self) -> None:
        self.leaves: list[bytes] = []
        self._cache: dict[tuple[int, int], bytes] = {}

    def _root(self, start: int, size: int) -> bytes:
        if size == 1:
            return self.leaves[start]
        if size & (size - 1) == 0:
            hit = self._cache.get((start, size))
            if hit is not None:
                return hit
        k = 1
        while k * 2 < size:
            k *= 2
        h = merkle.node_hash(self._root(start, k), self._root(start + k, size - k))
        if size & (size - 1) == 0:
            self._cache[(start, size)] = h
        return h

    def root(self, n: int) -> bytes:
        if n == 0:
            return merkle.EMPTY_ROOT
        return self._root(0, n)

    def inclusion(self, index: int, n: int) -> list[bytes]:
        if not 0 <= index < n <= len(self.leaves):
            raise ValueError("bad index")
        path: list[bytes] = []

        def walk(i: int, start: int, size: int) -> None:
            if size == 1:
                return
            k = 1
            while k * 2 < size:
                k *= 2
            if i < k:
                walk(i, start, k)
                path.append(self._root(start + k, size - k))
            else:
                walk(i - k, start + k, size - k)
                path.append(self._root(start, k))

        walk(index, 0, n)
        return path

    def consistency(self, m: int, n: int) -> list[bytes]:
        if not 0 < m <= n <= len(self.leaves):
            raise ValueError("bad sizes")
        if m == n:
            return []
        out: list[bytes] = []

        def sub(mm: int, start: int, size: int, complete: bool) -> None:
            if mm == size:
                if not complete:
                    out.append(self._root(start, size))
                return
            k = 1
            while k * 2 < size:
                k *= 2
            if mm <= k:
                sub(mm, start, k, complete)
                out.append(self._root(start + k, size - k))
            else:
                sub(mm - k, start + k, size - k, False)
                out.append(self._root(start, k))

        sub(m, 0, n, True)
        return out


class EvidenceLog:
    def __init__(self, db: Database, signer: DualSigner, clock: Clock) -> None:
        self.db = db
        self.signer = signer
        self.clock = clock
        self.tree = MerkleCache()
        self._pending: list[bytes] = []
        self._lock = threading.Lock()
        self._last_checkpoint_mono = clock.monotonic()
        for row in db.all("SELECT leaf_hash FROM receipts ORDER BY leaf_index"):
            self.tree.leaves.append(bytes(row["leaf_hash"]))

    @property
    def size(self) -> int:
        return len(self.tree.leaves)

    def append(
        self,
        conn: sqlite3.Connection,
        *,
        action: str,
        decision: str,
        reason_code: str,
        request_hash: str,
        subject: dict[str, str | None],
        resource: str | None,
        policy_bundle_hash: str,
        matched_rules: list[str],
        key_epoch: int,
        directory_epoch: int,
        receipt_id: str | None = None,
    ) -> dict[str, Any]:
        """Append a receipt inside the caller's transaction. Visible in the tree after commit."""
        leaf_index = len(self.tree.leaves) + len(self._pending)
        receipt: dict[str, Any] = {
            "suite": SUITE,
            "id": receipt_id or new_id("rcp"),
            "ts": self.clock.iso(),
            "request_hash": request_hash,
            "subject": {
                "user_id": subject.get("user_id"),
                "device_id": subject.get("device_id"),
                "session_id": subject.get("session_id"),
            },
            "action": action,
            "resource": resource,
            "policy_bundle_hash": policy_bundle_hash,
            "matched_rules": list(matched_rules),
            "decision": decision,
            "reason_code": reason_code,
            "key_epoch": key_epoch,
            "directory_epoch": directory_epoch,
            "leaf_index": leaf_index,
        }
        leaf = canon(receipt)
        lh = merkle.leaf_hash(leaf)
        conn.execute(
            "INSERT INTO receipts (leaf_index, id, ts, action, decision, reason_code, user_id, device_id, session_id,"
            " resource, leaf, leaf_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                leaf_index,
                receipt["id"],
                receipt["ts"],
                action,
                decision,
                reason_code,
                receipt["subject"]["user_id"],
                receipt["subject"]["device_id"],
                receipt["subject"]["session_id"],
                resource,
                leaf,
                lh,
            ),
        )
        if not self._pending:
            self.db.on_commit(self._commit_pending)
            self.db.on_rollback(self._pending.clear)
        self._pending.append(lh)
        return receipt

    def _commit_pending(self) -> None:
        self.tree.leaves.extend(self._pending)
        self._pending.clear()

    # ---- checkpoints -------------------------------------------------------------------------

    def latest_checkpoint(self) -> dict[str, Any] | None:
        row = self.db.one("SELECT doc FROM checkpoints ORDER BY tree_size DESC LIMIT 1")
        return json.loads(row["doc"]) if row else None

    def checkpoint_at(self, tree_size: int) -> dict[str, Any] | None:
        row = self.db.one("SELECT doc FROM checkpoints WHERE tree_size = ?", (tree_size,))
        return json.loads(row["doc"]) if row else None

    def checkpoint(self, conn: sqlite3.Connection, *, force: bool = False) -> dict[str, Any] | None:
        """Sign a checkpoint over the committed tree plus this transaction's pending receipts."""
        size = len(self.tree.leaves) + len(self._pending)
        last_row = conn.execute("SELECT MAX(tree_size) FROM checkpoints").fetchone()[0]
        last = last_row or 0
        if last_row is not None and size == last:
            return self.checkpoint_at(size) if force and size else None
        if not force and last_row is not None:
            due = size - last >= CHECKPOINT_EVERY_RECEIPTS or (
                self.clock.monotonic() - self._last_checkpoint_mono >= CHECKPOINT_EVERY_SECONDS
            )
            if not due:
                return None
        root = self._root_with_pending(self.tree.leaves + self._pending) if self._pending else self.tree.root(size)
        cp = self.signer.sign_object(
            {"root_hash": b64u(root), "suite": SUITE, "tree_size": size, "ts": self.clock.iso()}, "checkpoint"
        )
        conn.execute(
            "INSERT INTO checkpoints (tree_size, root_hash, ts, doc) VALUES (?,?,?,?)",
            (size, root, cp["ts"], json.dumps(cp)),
        )
        self._last_checkpoint_mono = self.clock.monotonic()
        return cp

    def _root_with_pending(self, hashes: list[bytes]) -> bytes:
        tmp = MerkleCache()
        tmp.leaves = hashes
        tmp._cache = dict(self.tree._cache)  # complete subtrees of committed leaves are still valid
        return tmp.root(len(hashes))

    def tick(self) -> dict[str, Any] | None:
        """Called periodically: checkpoint when receipts are waiting and the interval passed."""
        with self.db.tx() as conn:
            return self.checkpoint(conn)

    # ---- self-audit (feeds QG-R013) ---------------------------------------------------------

    def audit(self) -> dict[str, Any] | None:
        """Recompute every stored leaf hash and the newest checkpoint root. Returns the first mismatch."""
        with self.db.tx() as conn:
            rows = conn.execute("SELECT leaf_index, leaf, leaf_hash FROM receipts ORDER BY leaf_index").fetchall()
            cp_row = conn.execute("SELECT tree_size, root_hash FROM checkpoints ORDER BY tree_size DESC LIMIT 1").fetchone()
        for i, row in enumerate(rows):
            stored = bytes(row["leaf_hash"])
            if row["leaf_index"] != i:
                return {"first_bad_index": i, "check": "leaf_index_gap"}
            if merkle.leaf_hash(bytes(row["leaf"])) != stored:
                return {"first_bad_index": i, "check": "leaf_hash"}
            if i < len(self.tree.leaves) and self.tree.leaves[i] != stored:
                return {"first_bad_index": i, "check": "tree"}
        if cp_row is not None and cp_row[0] <= len(self.tree.leaves):
            if self.tree.root(cp_row[0]) != bytes(cp_row[1]):
                return {"first_bad_index": None, "check": "checkpoint_root"}
        return None

    # ---- proofs ------------------------------------------------------------------------------

    def proof(self, index: int, tree_size: int) -> dict[str, Any]:
        return {
            "leaf_index": index,
            "tree_size": tree_size,
            "leaf_hash": b64u(self.tree.leaves[index]),
            "audit_path": [b64u(h) for h in self.tree.inclusion(index, tree_size)],
        }

    def receipt(self, receipt_id: str) -> dict[str, Any] | None:
        row = self.db.one("SELECT leaf FROM receipts WHERE id = ?", (receipt_id,))
        return json.loads(row["leaf"]) if row else None
