"""QG-R011: enrolment attempt while a loss report is open for the same person. High. Hold enrolment."""

from __future__ import annotations

from qg.detect.model import Event, Finding, Response, RuleContext

from ._base import BaseRule


class Rule(BaseRule):
    RULE_ID = "QG-R011"
    SEVERITY = "high"
    EVENTS = frozenset({"enrol_during_loss"})
    CONDITION = "Someone tried to enrol a new device for a person whose device loss report is still open."

    def evaluate(self, ctx: RuleContext, event: Event) -> Finding | None:
        if not event.user_id:
            return None
        inc = ctx.conn.execute("SELECT id FROM incidents WHERE user_id = ? AND closed_at IS NULL ORDER BY reported_at"
                               " DESC LIMIT 1", (event.user_id,)).fetchone()
        return Finding(
            summary="Enrolment held: a loss report is open for this person. An operator can lift the hold.",
            condition=self.CONDITION,
            receipt_ids=event.receipt_ids,
            response=Response("hold_enrolment", "identity", event.user_id, None),
            incident_id=inc[0] if inc else None,
        )


RULE = Rule()
