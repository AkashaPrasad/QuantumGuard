"""QG-R009: 20 or more QG_NOT_FOUND / QG_DENY_POLICY answers in 60 s on one session (enumeration). Medium.
Throttle that session for 5 minutes."""

from __future__ import annotations

from qg.detect.model import Event, Finding, Response, RuleContext

from ._base import BaseRule

THRESHOLD = 20
WINDOW = 60.0


class Rule(BaseRule):
    RULE_ID = "QG-R009"
    SEVERITY = "medium"
    EVENTS = frozenset({"denied"})
    CONDITION = f"{THRESHOLD} or more not-found or policy-denied answers within {int(WINDOW)} s on one session."

    def evaluate(self, ctx: RuleContext, event: Event) -> Finding | None:
        if not event.session_id or event.data.get("code") not in ("QG_NOT_FOUND", "QG_DENY_POLICY"):
            return None
        refs = ctx.core.detector.counters.add(f"r009:{event.session_id}", ctx.core.clock.monotonic(), WINDOW,
                                              (event.receipt_ids or [None])[0])
        if len(refs) < THRESHOLD:
            return None
        return Finding(
            summary=f"{len(refs)} not-found or denied answers in {int(WINDOW)} s look like enumeration; the session is "
                    "throttled for 5 minutes.",
            condition=self.CONDITION,
            receipt_ids=[r for r in refs if r],
            response=Response("throttle", "session", event.session_id, 300),
        )


RULE = Rule()
