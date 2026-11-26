"""Directory: users, roles, device certificates and revocations, published as dual-signed epochs."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from qg.clock import Clock, fmt, parse
from qg.crypto.encoding import b64u, canon
from qg.crypto.kdf import sha256
from qg.crypto.sign import DualSigner
from qg.crypto.suite import EPOCH_GRACE_SECONDS, SUITE

ROLES = ("admin", "auditor", "employee", "operator")


class Directory:
    def __init__(self, signer: DualSigner, recovery_pk: Callable[[], bytes | None], clock: Clock) -> None:
        self.signer = signer
        self.recovery_pk = recovery_pk  # None until `qg.admin recovery-kit init` has run
        self.clock = clock

    # ---- reads -------------------------------------------------------------------------------

    @staticmethod
    def current_epoch(conn: sqlite3.Connection) -> int:
        return conn.execute("SELECT COALESCE(MAX(epoch), 0) FROM directory").fetchone()[0]

    @staticmethod
    def get(conn: sqlite3.Connection, epoch: int | None = None) -> dict[str, Any] | None:
        if epoch is None:
            row = conn.execute("SELECT doc FROM directory ORDER BY epoch DESC LIMIT 1").fetchone()
        else:
            row = conn.execute("SELECT doc FROM directory WHERE epoch = ?", (epoch,)).fetchone()
        return json.loads(row[0]) if row else None

    @staticmethod
    def roles(conn: sqlite3.Connection, user_id: str) -> list[str]:
        return sorted(r[0] for r in conn.execute("SELECT role FROM user_roles WHERE user_id = ?", (user_id,)))

    # ---- certificates ------------------------------------------------------------------------

    def certificate(self, *, device_id: str, user_id: str, name: str, kem_pk: bytes, sig_pk: bytes,
                    created_at: str, expires_at: str, directory_epoch: int) -> dict[str, Any]:
        body = {
            "created_at": created_at,
            "device_id": device_id,
            "directory_epoch": directory_epoch,
            "expires_at": expires_at,
            "kem_pk": b64u(kem_pk),
            "name": name,
            "sig_pk": b64u(sig_pk),
            "suite": SUITE,
            "user_id": user_id,
        }
        return self.signer.sign_object(body, "certificate")

    def new_device_times(self) -> tuple[str, str]:
        now = self.clock.now()
        return fmt(now), fmt(now + timedelta(days=365))

    # ---- publishing --------------------------------------------------------------------------

    def publish(self, conn: sqlite3.Connection, reason: str, *, revocation: bool = False) -> dict[str, Any]:
        prev = conn.execute("SELECT epoch, doc_hash FROM directory ORDER BY epoch DESC LIMIT 1").fetchone()
        epoch = (prev[0] + 1) if prev else 1
        prev_hash = bytes(prev[1]) if prev else bytes(32)
        now = self.clock.iso()
        users = []
        for u in conn.execute("SELECT user_id, name, status FROM users ORDER BY user_id"):
            users.append({"user_id": u[0], "name": u[1], "roles": self.roles(conn, u[0]), "status": u[2]})
        devices = []
        for d in conn.execute(
            "SELECT certificate FROM devices WHERE status != 'revoked' ORDER BY device_id"
        ):
            cert = json.loads(d[0])
            devices.append({k: v for k, v in cert.items() if k != "signatures"})
        revoked = [
            {"device_id": r[0], "revoked_at": r[1], "epoch": r[2]}
            for r in conn.execute(
                "SELECT device_id, revoked_at, revoked_epoch FROM devices WHERE status = 'revoked' ORDER BY device_id"
            )
        ]
        doc = self.signer.sign_object(
            {
                "suite": SUITE,
                "epoch": epoch,
                "prev_hash": b64u(prev_hash),
                "issued_at": now,
                "users": users,
                "devices": devices,
                "revoked": revoked,
                "recovery_pk": (lambda pk: b64u(pk) if pk else None)(self.recovery_pk()),
            },
            "directory",
        )
        conn.execute("UPDATE directory SET superseded_at = ? WHERE epoch = ?", (now, epoch - 1))
        conn.execute(
            "INSERT INTO directory (epoch, doc, doc_hash, issued_at, revocation, reason) VALUES (?,?,?,?,?,?)",
            (epoch, json.dumps(doc), sha256(canon(doc)), now, int(revocation), reason),
        )
        return doc

    def epoch_acceptable(self, conn: sqlite3.Connection, epoch: int) -> bool:
        """spec/SUITE.md 8.4: current epoch, or a recently superseded one with no revocation since."""
        current = self.current_epoch(conn)
        if epoch == current:
            return True
        if not isinstance(epoch, int) or epoch < 1 or epoch > current:
            return False
        row = conn.execute("SELECT superseded_at FROM directory WHERE epoch = ?", (epoch,)).fetchone()
        if row is None or row[0] is None:
            return False
        if (self.clock.now() - parse(row[0])).total_seconds() > EPOCH_GRACE_SECONDS:
            return False
        revoked_since = conn.execute(
            "SELECT 1 FROM directory WHERE epoch > ? AND revocation = 1 LIMIT 1", (epoch,)
        ).fetchone()
        return revoked_since is None
