"""QG-R012: five or more MAC or signature failures in 60 s. Medium. Throttle the source session or device."""

from __future__ import annotations

from qg.detect.model import Event, Finding, Response, RuleContext

from ._base import BaseRule

THRESHOLD = 5
WINDOW = 60.0


class Rule(BaseRule):
    RULE_ID = "QG-R012"
    SEVERITY = "medium"
    EVENTS = frozenset({"mac_failure", "signature_failure"})
    CONDITION = f"{THRESHOLD} or more request MAC or signature failures within {int(WINDOW)} seconds."

    def evaluate(self, ctx: RuleContext, event: Event) -> Finding | None:
        if event.session_id:
            kind, scope = "session", event.session_id
        elif event.device_id:
            kind, scope = "device", event.device_id
        else:
            return None
        refs = ctx.core.detector.counters.add(f"r012:{kind}:{scope}", ctx.core.clock.monotonic(), WINDOW,
                                              (event.receipt_ids or [None])[0])
        if len(refs) < THRESHOLD:
            return None
        return Finding(
            summary=f"{len(refs)} authentication failures in {int(WINDOW)} s; the {kind} is throttled for 5 minutes.",
            condition=self.CONDITION,
            receipt_ids=[r for r in refs if r],
            response=Response("throttle", kind, scope, 300),
        )


RULE = Rule()
