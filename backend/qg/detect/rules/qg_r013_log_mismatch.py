"""QG-R013: checkpoint or consistency check mismatch. Critical. Alert and freeze key release until an operator
acknowledges the alert."""

from __future__ import annotations

from qg.detect.model import Event, Finding, Response, RuleContext

from ._base import BaseRule


class Rule(BaseRule):
    RULE_ID = "QG-R013"
    SEVERITY = "critical"
    EVENTS = frozenset({"checkpoint_mismatch"})
    CONDITION = "A stored receipt, leaf hash or signed checkpoint no longer matches the evidence log."

    def evaluate(self, ctx: RuleContext, event: Event) -> Finding | None:
        return Finding(
            summary=f"Evidence log integrity check failed at leaf {event.data.get('first_bad_index')}; key release is "
                    "frozen until an operator acknowledges this alert.",
            condition=self.CONDITION,
            receipt_ids=event.receipt_ids,
            response=Response("freeze_key_release", "global", None, None),
            extra={"first_bad_index": event.data.get("first_bad_index"), "check": event.data.get("check")},
        )


RULE = Rule()
