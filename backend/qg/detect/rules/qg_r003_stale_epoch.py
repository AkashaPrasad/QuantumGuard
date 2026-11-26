"""QG-R003: object built on an older directory epoch after the grace period. High. Deny; require a fresh session."""

from __future__ import annotations

from qg.detect.model import Event, Finding, Response, RuleContext

from ._base import BaseRule


class Rule(BaseRule):
    RULE_ID = "QG-R003"
    SEVERITY = "high"
    EVENTS = frozenset({"stale_epoch"})
    CONDITION = "An object named a directory epoch older than allowed (past the 60 s grace or before a revocation)."

    def evaluate(self, ctx: RuleContext, event: Event) -> Finding | None:
        if not event.session_id:
            return None
        return Finding(
            summary=f"Request built on stale directory epoch {event.data.get('epoch')} was denied.",
            condition=self.CONDITION,
            receipt_ids=event.receipt_ids,
            response=Response("require_fresh_session", "session", event.session_id, 600),
        )


RULE = Rule()
