"""QG-R002: non-increasing sequence number (replay). High. End that session."""

from __future__ import annotations

from qg.detect.model import Event, Finding, Response, RuleContext

from ._base import BaseRule


class Rule(BaseRule):
    RULE_ID = "QG-R002"
    SEVERITY = "high"
    EVENTS = frozenset({"replay"})
    CONDITION = "A request reused a sequence number that was not greater than the last accepted one."

    def evaluate(self, ctx: RuleContext, event: Event) -> Finding | None:
        if not event.session_id:
            return None
        return Finding(
            summary=f"Replayed request on a session (sequence {event.data.get('seq')} after "
                    f"{event.data.get('last_seq')}); the session was ended.",
            condition=self.CONDITION,
            receipt_ids=event.receipt_ids,
            response=Response("end_session", "session", event.session_id, 3600),
        )


RULE = Rule()
