"""Shared types for detection rules. Rules are explicit conditions over events and receipts: no ML."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from qg.core import Core


@dataclass
class Event:
    kind: str
    subject: dict[str, str | None] = field(default_factory=dict)
    receipt_ids: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def user_id(self) -> str | None:
        return self.subject.get("user_id")

    @property
    def device_id(self) -> str | None:
        return self.subject.get("device_id")

    @property
    def session_id(self) -> str | None:
        return self.subject.get("session_id")


@dataclass
class Response:
    action: str  # deny | end_session | quarantine_device | quarantine_identity | throttle | require_fresh_session
    #              | hold_enrolment | freeze_key_release | none
    scope_kind: str  # session | device | identity | credential | global
    scope_id: str | None
    ttl_seconds: int | None  # None: until an operator lifts it


@dataclass
class Finding:
    summary: str
    condition: str
    receipt_ids: list[str]
    response: Response | None
    subject: dict[str, str | None] = field(default_factory=dict)
    incident_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class RuleContext:
    core: Core
    conn: sqlite3.Connection

    def now(self):  # noqa: ANN201
        return self.core.clock.now()


class Rule(Protocol):
    RULE_ID: str
    SEVERITY: str  # critical | high | medium
    EVENTS: frozenset[str]

    def evaluate(self, ctx: RuleContext, event: Event) -> Finding | None: ...

    def explain(self, finding: Finding) -> dict[str, Any]: ...
