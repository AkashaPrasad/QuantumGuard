"""Server runtime: wires storage, keys, directory, evidence log, policy, detection and responses."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import threading
import time
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from qg import keys as keymod
from qg import seed
from qg.clock import Clock, fmt, parse
from qg.config import Settings
from qg.crypto.encoding import b64u
from qg.crypto.kdf import sha256
from qg.crypto.sign import MLDSAKey
from qg.crypto.suite import BOOTSTRAP_INVITE_SECONDS, INVITE_SECONDS, SUITE
from qg.detect.engine import Detector
from qg.detect.model import Event, Response
from qg.directory.service import Directory
from qg.ids import new_id
from qg.log.receipts import EvidenceLog
from qg.policy.engine import PolicyEngine, bundle_hash, load_document
from qg.session.store import SecretStore
from qg.storage.blobs import BlobStore
from qg.storage.db import Database, get_meta, set_meta


class TokenBuckets:
    def __init__(self) -> None:
        self._b: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def take(self, key: str, rate: float, burst: float, now: float) -> float:
        """Take one token. Returns 0 when allowed, else seconds until a token is available."""
        with self._lock:
            tokens, last = self._b.get(key, [burst, now])
            tokens = min(burst, tokens + (now - last) * rate)
            if tokens >= 1:
                self._b[key] = [tokens - 1, now]
                if len(self._b) > 50_000:
                    self._b.clear()
                return 0.0
            self._b[key] = [tokens, now]
            return (1 - tokens) / rate


CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_NORMALISE = str.maketrans({"O": "0", "I": "1", "L": "1"})


def new_code() -> str:
    """16 Crockford base32 characters (80 bits) in four groups: K7QM-2XVD-9RTA-HB4N."""
    n = int.from_bytes(os.urandom(10), "big")
    chars = "".join(CROCKFORD[(n >> (5 * i)) & 31] for i in range(16))
    return "-".join(chars[i : i + 4] for i in range(0, 16, 4))


def normalise_code(code: str) -> str:
    """spec/API.md 4.1: trim, upper-case, drop hyphens and spaces, read O as 0 and I or L as 1."""
    return code.strip().upper().replace("-", "").replace(" ", "").translate(_NORMALISE)


def code_hash(code: str) -> bytes:
    return sha256(normalise_code(code).encode("utf-8"))


class Core:
    def __init__(self, settings: Settings, clock: Clock | None = None,
                 log_sink: Callable[[str], None] | None = None) -> None:
        self.settings = settings
        self.clock = clock or Clock()
        self._log_sink = log_sink
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.keys, _ = keymod.load_or_create(settings.keys_dir)
        self.db = Database(settings.data_dir / "quantumguard.sqlite")
        self.blobs = BlobStore(settings.data_dir / "blobs")
        self.directory = Directory(self.keys.signer, self.keys.recovery_pk, self.clock)
        self.log = EvidenceLog(self.db, self.keys.signer, self.clock)
        self.secrets = SecretStore()
        self.buckets = TokenBuckets()
        self.policy = self._load_policy()
        self.detector = Detector(self)
        self.started_mono = time.monotonic()
        self.bootstrap_invites = self._first_start()
        self._stop = threading.Event()
        self._ticker: threading.Thread | None = None

    # ---- logging -----------------------------------------------------------------------------

    def log_line(self, line: str) -> None:
        if self._log_sink is not None:
            self._log_sink(line)
        elif self.settings.log_stdout:
            sys.stdout.write(line + "\n")
            sys.stdout.flush()

    def log_event(self, event: str, **fields: Any) -> None:
        self.log_line(json.dumps({"event": event, "ts": self.clock.iso(), **fields}, sort_keys=True,
                                 separators=(",", ":")))

    # ---- startup -----------------------------------------------------------------------------

    def _load_policy(self) -> PolicyEngine:
        doc = load_document()
        with self.db.tx() as conn:
            stored = get_meta(conn, "policy_signed")
            if stored is None:
                signed = PolicyEngine.sign_bundle(doc, self.keys.signer, self.clock.iso())
                set_meta(conn, "policy_signed", json.dumps(signed))
            else:
                signed = json.loads(stored)
        engine = PolicyEngine(doc, signed, self.keys.signer.ed.public_key, self.keys.signer.pq.public_key,
                              down_flag=self.settings.data_dir / "policy.down")
        if not engine._intact:  # noqa: SLF001
            self.log_event("policy_bundle_mismatch", expected=bundle_hash(doc))
        return engine

    def resign_policy(self) -> str:
        doc = load_document()
        signed = PolicyEngine.sign_bundle(doc, self.keys.signer, self.clock.iso())
        with self.db.tx() as conn:
            set_meta(conn, "policy_signed", json.dumps(signed))
        self.policy = PolicyEngine(doc, signed, self.keys.signer.ed.public_key, self.keys.signer.pq.public_key,
                                   down_flag=self.settings.data_dir / "policy.down")
        return self.policy.hash

    def _first_start(self) -> list[dict[str, Any]] | None:
        with self.db.tx() as conn:
            if get_meta(conn, "initialized"):
                return None
            now = self.clock.now()
            invites = []
            for name, roles in seed.PEOPLE:
                uid = new_id("usr")
                conn.execute("INSERT INTO users (user_id, name, status, created_at, seeded) VALUES (?,?,?,?,1)",
                             (uid, name, "active", fmt(now)))
                for role in roles:
                    conn.execute(
                        "INSERT INTO user_roles (user_id, role, granted_at, change_id, source) VALUES (?,?,?,?,?)",
                        (uid, role, fmt(now), None, "seed"),
                    )
                invites.append({"user_id": uid, "name": name, "roles": roles})
            owner = invites[0]["user_id"]
            for fname, classification in seed.DECOY_FILES:
                conn.execute(
                    "INSERT INTO files (file_id, owner_user_id, name, classification, current_version, created_at,"
                    " updated_at, is_decoy) VALUES (?,?,?,?,0,?,?,1)",
                    (new_id("fil"), owner, fname, classification, fmt(now), fmt(now)),
                )
            for sname in seed.DECOY_SERVICES:
                sid = new_id("svc")
                conn.execute("INSERT INTO services (service_id, name, status, created_at, is_decoy) VALUES (?,?,?,?,1)",
                             (sid, sname, "active", fmt(now)))
                conn.execute(
                    "INSERT INTO service_keys (key_id, service_id, alg, public_key, status, created_at)"
                    " VALUES (?,?,?,?,?,?)",
                    (new_id("key"), sid, "ML-DSA-65", MLDSAKey.generate().public_key, "active", fmt(now)),
                )
            self.directory.publish(conn, "bootstrap")
            self.publish_keyset(conn)
            set_meta(conn, "initialized", fmt(now))
            set_meta(conn, "org_name", seed.ORG_NAME)
            return invites

    def issue_bootstrap_invites(self, user_ids: list[str] | None = None) -> list[dict[str, Any]]:
        """Local-only (python -m qg.admin invite): one fresh 24-hour single-use code per seeded person, or per
        named person. Earlier pending codes for those people are cancelled. Never logged."""
        now = self.clock.now()
        out = []
        with self.db.tx() as conn:
            if user_ids is None:
                rows = conn.execute("SELECT user_id, name FROM users WHERE seeded = 1 ORDER BY created_at, rowid").fetchall()
            else:
                rows = []
                for uid in user_ids:
                    r = conn.execute("SELECT user_id, name FROM users WHERE user_id = ? AND status != 'disabled'",
                                     (uid,)).fetchone()
                    if r is None:
                        raise KeyError(uid)
                    rows.append(r)
            for r in rows:
                conn.execute("UPDATE invites SET status = 'cancelled' WHERE user_id = ? AND status = 'pending'"
                             " AND bootstrap = 1", (r[0],))
                code = new_code()
                expires = fmt(now + timedelta(seconds=BOOTSTRAP_INVITE_SECONDS))
                conn.execute(
                    "INSERT INTO invites (invite_id, code_hash, user_id, created_by, created_at, expires_at, status,"
                    " bootstrap) VALUES (?,?,?,?,?,?,?,1)",
                    (new_id("inv"), code_hash(code), r[0], None, fmt(now), expires, "pending"),
                )
                out.append({"user_id": r[0], "name": r[1], "roles": self.directory.roles(conn, r[0]), "code": code,
                            "expires_at": expires})
        return out

    # ---- background checkpoints --------------------------------------------------------------

    def start_background(self) -> None:
        if self._ticker is not None:
            return

        def run() -> None:
            while not self._stop.wait(0.25):
                try:
                    self.log.tick()
                    self.expire_leases()
                except Exception as exc:  # noqa: BLE001 - background loop must survive
                    self.log_event("background_error", error=type(exc).__name__)

        self._ticker = threading.Thread(target=run, name="qg-checkpoints", daemon=True)
        self._ticker.start()

    def stop(self) -> None:
        self._stop.set()
        if self._ticker is not None:
            self._ticker.join(timeout=2)
            self._ticker = None
        try:
            self.log.tick()
        except Exception as exc:  # noqa: BLE001 - shutdown must not fail on a final checkpoint
            self.log_event("shutdown_checkpoint_failed", error=type(exc).__name__)

    def expire_leases(self) -> None:
        with self.db.tx() as conn:
            conn.execute("DELETE FROM leases WHERE expires_at < ?", (fmt(self.clock.now() - timedelta(minutes=5)),))

    # ---- invites -----------------------------------------------------------------------------

    def create_invite(self, conn: sqlite3.Connection, user_id: str, created_by: str | None) -> dict[str, Any]:
        now = self.clock.now()
        code = new_code()
        invite_id = new_id("inv")
        expires = fmt(now + timedelta(seconds=INVITE_SECONDS))
        conn.execute(
            "INSERT INTO invites (invite_id, code_hash, user_id, created_by, created_at, expires_at, status, bootstrap)"
            " VALUES (?,?,?,?,?,?,?,0)",
            (invite_id, code_hash(code), user_id, created_by, fmt(now), expires, "pending"),
        )
        return {"invite_id": invite_id, "code": code, "user_id": user_id, "expires_at": expires}

    # ---- receipts ----------------------------------------------------------------------------

    def receipt(self, conn: sqlite3.Connection, *, action: str, decision: str, reason: str,
                subject: dict[str, str | None], request_hash: str, resource: str | None = None,
                matched: list[str] | None = None, key_epoch: int = 0) -> dict[str, Any]:
        return self.log.append(
            conn,
            action=action,
            decision=decision,
            reason_code=reason,
            request_hash=request_hash,
            subject=subject,
            resource=resource,
            policy_bundle_hash=self.policy.hash,
            matched_rules=matched or [],
            key_epoch=key_epoch,
            directory_epoch=self.directory.current_epoch(conn),
        )

    def deny_receipt(self, ctx: Any, action: str, reason: str, resource: str | None,
                     matched: list[str] | None = None, key_epoch: int = 0) -> str:
        """Write a deny receipt in its own transaction so it survives the failing request."""
        with self.db.tx() as conn:
            rc = self.receipt(conn, action=action, decision="deny", reason=reason, subject=ctx.subject,
                              request_hash=ctx.request_hash, resource=resource, matched=matched, key_epoch=key_epoch)
        ctx.set_receipt(rc["id"])
        return rc["id"]

    def record_denied_attempt(self, conn: sqlite3.Connection, device_id: str, receipt_id: str | None) -> None:
        inc = conn.execute("SELECT id FROM incidents WHERE device_id = ?", (device_id,)).fetchone()
        if inc is not None:
            conn.execute(
                "INSERT INTO incident_timeline (incident_id, step, ts, receipt_id, detail) VALUES (?,?,?,?,?)",
                (inc[0], "denied_attempt", self.clock.iso(), receipt_id, "Request from the revoked device was denied."),
            )

    # ---- incidents and re-key ------------------------------------------------------------------

    def timeline(self, conn: sqlite3.Connection, incident_id: str, step: str, receipt_id: str | None,
                 detail: str) -> None:
        from qg.incidents.service import timeline

        timeline(self, conn, incident_id, step, receipt_id, detail)

    def queue_rekey(self, conn: sqlite3.Connection, file_id: str, from_version: int, reason: str,
                    incident_id: str | None) -> None:
        from qg.incidents.service import queue_rekey

        queue_rekey(self, conn, file_id, from_version, reason, incident_id)

    def finish_rekey(self, conn: sqlite3.Connection, file_id: str, new_version: int, receipt_id: str) -> None:
        from qg.incidents.service import finish_rekey

        finish_rekey(self, conn, file_id, new_version, receipt_id)

    # ---- detection ---------------------------------------------------------------------------

    def emit(self, conn: sqlite3.Connection, event_kind: str, subject: dict[str, str | None],
             receipt_ids: list[str] | None = None, **data: Any) -> list[dict[str, Any]]:
        return self.detector.emit(conn, Event(event_kind, dict(subject), list(receipt_ids or []), data))

    def emit_now(self, event_kind: str, subject: dict[str, str | None], receipt_ids: list[str] | None = None,
                 **data: Any) -> list[dict[str, Any]]:
        return self.detector.emit_now(Event(event_kind, dict(subject), list(receipt_ids or []), data))

    def end_sessions(self, conn: sqlite3.Connection, *, where: str, params: tuple[Any, ...], reason: str) -> int:
        # `where` is always one of a few fixed clauses written in this file; values are bound parameters
        sql = f"SELECT session_id, device_id, user_id FROM sessions WHERE {where}"  # noqa: S608 # nosec B608
        rows = conn.execute(sql, params).fetchall()
        now = self.clock.iso()
        for r in rows:
            conn.execute(
                "INSERT OR REPLACE INTO ended_sessions (session_id, device_id, user_id, ended_at, reason)"
                " VALUES (?,?,?,?,?)",
                (r[0], r[1], r[2], now, reason),
            )
            conn.execute("DELETE FROM sessions WHERE session_id = ?", (r[0],))
            conn.execute("UPDATE leases SET cancelled = 1 WHERE session_id = ?", (r[0],))
            sid = r[0]
            self.db.on_commit(lambda sid=sid: self.secrets.drop_mac(sid))
        return len(rows)

    def apply_response(self, conn: sqlite3.Connection, r: Response, alert_id: str) -> None:
        """Apply the immediate effect of an automatic response. Every effect is scoped and liftable."""
        if r.action == "end_session" and r.scope_id:
            self.end_sessions(conn, where="session_id = ?", params=(r.scope_id,), reason="auto_response")
        elif r.action == "quarantine_device" and r.scope_id:
            self.end_sessions(conn, where="device_id = ?", params=(r.scope_id,), reason="auto_response")
            conn.execute("UPDATE leases SET cancelled = 1 WHERE device_id = ?", (r.scope_id,))
            cur = conn.execute("UPDATE devices SET status = 'quarantined' WHERE device_id = ? AND status = 'active'",
                               (r.scope_id,))
            if cur.rowcount:
                self.directory.publish(conn, "quarantine_device")
        elif r.action == "quarantine_identity" and r.scope_id:
            conn.execute(
                "UPDATE leases SET cancelled = 1 WHERE device_id IN (SELECT device_id FROM devices WHERE user_id = ?)",
                (r.scope_id,),
            )
            cur = conn.execute("UPDATE users SET status = 'quarantined' WHERE user_id = ? AND status = 'active'",
                               (r.scope_id,))
            if cur.rowcount:
                self.directory.publish(conn, "quarantine_identity")
        elif r.action == "require_fresh_session" and r.scope_id:
            col = {"session": "session_id", "device": "device_id", "identity": "user_id"}.get(r.scope_kind)
            if col:
                # col comes from the fixed mapping above
                conn.execute(f"UPDATE sessions SET fresh_required = 1 WHERE {col} = ?", (r.scope_id,))  # noqa: S608 # nosec B608
        elif r.action == "freeze_key_release":
            conn.execute("UPDATE leases SET cancelled = 1")
        elif r.action == "hold_enrolment" and r.scope_id:
            conn.execute(
                "INSERT INTO enrol_holds (hold_id, user_id, incident_id, created_at) VALUES (?,?,?,?)",
                (alert_id, r.scope_id, None, self.clock.iso()),
            )

    def lift_response(self, conn: sqlite3.Connection, response_id: str, by_user: str, reason: str) -> None:
        row = conn.execute("SELECT action, scope_kind, scope_id FROM responses WHERE id = ?", (response_id,)).fetchone()
        conn.execute("UPDATE responses SET lifted_at = ?, lifted_by = ?, lift_reason = ? WHERE id = ?",
                     (self.clock.iso(), by_user, reason, response_id))
        action, _, scope_id = row
        if action == "quarantine_device" and scope_id and not self._other_active(conn, "quarantine_device", scope_id):
            cur = conn.execute("UPDATE devices SET status = 'active' WHERE device_id = ? AND status = 'quarantined'",
                               (scope_id,))
            if cur.rowcount:
                self.directory.publish(conn, "lift_quarantine_device")
        elif action == "quarantine_identity" and scope_id and not self._other_active(conn, "quarantine_identity", scope_id):
            cur = conn.execute("UPDATE users SET status = 'active' WHERE user_id = ? AND status = 'quarantined'",
                               (scope_id,))
            if cur.rowcount:
                self.directory.publish(conn, "lift_quarantine_identity")
        elif action == "hold_enrolment":
            conn.execute("UPDATE enrol_holds SET lifted_at = ? WHERE user_id = ? AND lifted_at IS NULL",
                         (self.clock.iso(), scope_id))

    def _other_active(self, conn: sqlite3.Connection, action: str, scope_id: str) -> bool:
        return conn.execute(
            "SELECT 1 FROM responses WHERE action = ? AND scope_id = ? AND lifted_at IS NULL"
            " AND (expires_at IS NULL OR expires_at > ?) LIMIT 1",
            (action, scope_id, self.clock.iso()),
        ).fetchone() is not None

    def active_responses(self, conn: sqlite3.Connection, *, session_id: str | None, device_id: str | None,
                         user_id: str | None) -> list[sqlite3.Row]:
        return conn.execute(
            "SELECT id, action, scope_kind, scope_id, expires_at FROM responses WHERE lifted_at IS NULL"
            " AND (expires_at IS NULL OR expires_at > ?) AND ((scope_kind = 'session' AND scope_id = ?)"
            " OR (scope_kind = 'device' AND scope_id = ?) OR (scope_kind = 'identity' AND scope_id = ?)"
            " OR scope_kind = 'global')",
            (self.clock.iso(), session_id, device_id, user_id),
        ).fetchall()

    def alert_view(self, conn: sqlite3.Connection, alert_id: str) -> dict[str, Any] | None:
        a = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if a is None:
            return None
        response = None
        if a["response_id"]:
            r = conn.execute("SELECT * FROM responses WHERE id = ?", (a["response_id"],)).fetchone()
            response = {
                "id": r["id"],
                "action": r["action"],
                "scope": {"kind": r["scope_kind"], "id": r["scope_id"]},
                "expires_at": r["expires_at"],
                "lifted_at": r["lifted_at"],
                "lifted_by": r["lifted_by"],
            }
        return {
            "id": a["id"],
            "ts": a["ts"],
            "rule_id": a["rule_id"],
            "severity": a["severity"],
            "status": a["status"],
            "subject": {"user_id": a["user_id"], "device_id": a["device_id"], "session_id": a["session_id"]},
            "summary": a["summary"],
            "explanation": {"condition": a["condition"], "receipt_ids": json.loads(a["receipt_ids"])},
            "response": response,
            "incident_id": a["incident_id"],
            "acknowledged_by": a["acknowledged_by"],
        }

    # ---- service key set ---------------------------------------------------------------------

    def publish_keyset(self, conn: sqlite3.Connection) -> dict[str, Any]:
        epoch = (conn.execute("SELECT COALESCE(MAX(epoch), 0) FROM keysets").fetchone()[0]) + 1
        keys = [
            {"alg": r[0], "key_id": r[1], "public_key": b64u(bytes(r[2])), "service_id": r[3], "status": r[4]}
            for r in conn.execute(
                "SELECT alg, key_id, public_key, service_id, status FROM service_keys ORDER BY key_id"
            )
        ]
        doc = self.keys.signer.sign_object({"epoch": epoch, "keys": keys, "suite": SUITE}, "keyset")
        conn.execute("INSERT INTO keysets (epoch, doc, issued_at) VALUES (?,?,?)",
                     (epoch, json.dumps(doc), self.clock.iso()))
        return doc

    # ---- misc helpers ------------------------------------------------------------------------

    def is_expired(self, ts: str) -> bool:
        return parse(ts) <= self.clock.now()
