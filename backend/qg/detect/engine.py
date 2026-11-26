"""Runs detection rules on security events, records alerts and applies scoped, time-boxed responses."""

from __future__ import annotations

import importlib
import json
import pkgutil
import sqlite3
import threading
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from qg.clock import fmt
from qg.ids import new_id

from .model import Event, Finding, Rule, RuleContext
from .windows import EwmaBaseline, SlidingCounter

if TYPE_CHECKING:
    from qg.core import Core


def load_rules() -> list[Rule]:
    from . import rules as pkg

    out = []
    for info in sorted(pkgutil.iter_modules(pkg.__path__), key=lambda i: i.name):
        if info.name.startswith("qg_r"):
            mod = importlib.import_module(f"{pkg.__name__}.{info.name}")
            out.append(mod.RULE)
    return out


# The QuantumGuard service each security event was observed on, so every alert names it.
_SERVICE_BY_EVENT = {
    "access": "key-release",
    "bad_suite": "gateway",
    "checkpoint_mismatch": "evidence-log",
    "denied": "gateway",
    "enrol_during_loss": "enrolment",
    "grant_applied": "changes",
    "mac_failure": "gateway",
    "privilege_observed": "identity-signals",
    "replay": "gateway",
    "retired_key_used": "service-keys",
    "revoked_device_attempt": "gateway",
    "stale_epoch": "directory",
}
_SERVICE_BY_OBJECT = {
    "approval": "changes",
    "change": "changes",
    "file": "files",
    "manifest": "files",
    "message": "messages",
    "service key": "service-keys",
    "share": "files",
}
_DETAIL_KEYS = ("action", "code", "kind", "resource", "key_id", "classification", "epoch", "seq", "last_seq",
                "route", "source", "claim")


def describe_event(event: Event) -> tuple[str, dict[str, Any]]:
    """Return the service an event concerns and the event fields safe to show in an alert (no secrets)."""
    kind = event.data.get("kind")
    service = _SERVICE_BY_OBJECT.get(kind) if isinstance(kind, str) else None
    action = event.data.get("action")
    if service is None and isinstance(action, str) and action.startswith(("file.", "slot.")):
        service = "files"
    service = service or _SERVICE_BY_EVENT.get(event.kind, "gateway")
    detail = {k: event.data[k] for k in _DETAIL_KEYS if isinstance(event.data.get(k), (str, int))}
    return service, detail


class Detector:
    def __init__(self, core: Core) -> None:
        self.core = core
        self.rules = load_rules()
        self.counters = SlidingCounter()
        self.baseline = EwmaBaseline()
        self._lock = threading.Lock()
        self.events_path: Path = core.settings.data_dir / "SECURITY_EVENTS.jsonl"

    def emit(self, conn: sqlite3.Connection, event: Event) -> list[dict[str, Any]]:
        """Evaluate every rule interested in this event inside the caller's transaction."""
        ctx = RuleContext(self.core, conn)
        alerts = []
        for rule in self.rules:
            if event.kind not in rule.EVENTS:
                continue
            finding = rule.evaluate(ctx, event)
            if finding is not None:
                alert = self._record(conn, rule, finding, event)
                if alert is not None:
                    alerts.append(alert)
        return alerts

    def emit_now(self, event: Event) -> list[dict[str, Any]]:
        """Emit in its own transaction (used after the request's own transaction was rolled back)."""
        with self.core.db.tx() as conn:
            return self.emit(conn, event)

    # ---- alerts and responses ----------------------------------------------------------------

    def _active_duplicate(self, conn: sqlite3.Connection, rule_id: str, finding: Finding) -> sqlite3.Row | None:
        r = finding.response
        if r is None or r.scope_id is None:
            return None
        return conn.execute(
            "SELECT a.id FROM alerts a JOIN responses p ON p.id = a.response_id WHERE a.rule_id = ? AND p.scope_kind = ?"
            " AND p.scope_id = ? AND p.lifted_at IS NULL AND (p.expires_at IS NULL OR p.expires_at > ?) LIMIT 1",
            (rule_id, r.scope_kind, r.scope_id, self.core.clock.iso()),
        ).fetchone()

    def _record(self, conn: sqlite3.Connection, rule: Rule, finding: Finding, event: Event) -> dict[str, Any] | None:
        now = self.core.clock.now()
        dup = self._active_duplicate(conn, rule.RULE_ID, finding)
        if dup is not None:
            row = conn.execute("SELECT receipt_ids FROM alerts WHERE id = ?", (dup[0],)).fetchone()
            ids = json.loads(row[0])
            merged = ids + [r for r in finding.receipt_ids if r not in ids]
            conn.execute("UPDATE alerts SET receipt_ids = ? WHERE id = ?", (json.dumps(merged[-200:]), dup[0]))
            return None
        alert_id = new_id("alr")
        subject = {**event.subject, **finding.subject}
        response_id = None
        if finding.response is not None:
            r = finding.response
            response_id = new_id("rsp")
            expires = fmt(now + timedelta(seconds=r.ttl_seconds)) if r.ttl_seconds else None
            conn.execute(
                "INSERT INTO responses (id, alert_id, action, scope_kind, scope_id, created_at, expires_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (response_id, alert_id, r.action, r.scope_kind, r.scope_id, fmt(now), expires),
            )
            self.core.apply_response(conn, r, alert_id)
        explanation = rule.explain(finding)
        service, detail = describe_event(event)
        conn.execute(
            "INSERT INTO alerts (id, ts, rule_id, severity, status, user_id, device_id, session_id, summary, condition,"
            " receipt_ids, response_id, incident_id, extra, event_kind, service, event_detail)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                alert_id,
                fmt(now),
                rule.RULE_ID,
                rule.SEVERITY,
                "open",
                subject.get("user_id"),
                subject.get("device_id"),
                subject.get("session_id"),
                finding.summary,
                explanation.get("condition", finding.condition),
                json.dumps(finding.receipt_ids),
                response_id,
                finding.incident_id,
                json.dumps(finding.extra) if finding.extra else None,
                event.kind,
                service,
                json.dumps(detail, sort_keys=True) if detail else None,
            ),
        )
        alert = self.core.alert_view(conn, alert_id)
        self.core.db.on_commit(lambda: self._publish(alert))
        return alert

    def _publish(self, alert: dict[str, Any]) -> None:
        # Log lines keep "event":"alert" as their type; the observed security event goes under "security_event".
        line = json.dumps({**alert, "event": "alert", "security_event": alert.get("event")}, separators=(",", ":"),
                          sort_keys=True)
        self.core.log_line(line)
        try:
            with open(self.events_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass
