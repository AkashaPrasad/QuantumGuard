"""QG-R014: unknown or weaker suite requested. Medium. Deny."""

from __future__ import annotations

from qg.detect.model import Event, Finding, RuleContext

from ._base import BaseRule


class Rule(BaseRule):
    RULE_ID = "QG-R014"
    SEVERITY = "medium"
    EVENTS = frozenset({"bad_suite"})
    CONDITION = "A request named a suite other than QG-1 (no negotiation or downgrade exists)."

    def evaluate(self, ctx: RuleContext, event: Event) -> Finding | None:
        return Finding(
            summary=f"Request with an unsupported suite on {event.data.get('route')} was denied.",
            condition=self.CONDITION,
            receipt_ids=event.receipt_ids,
            response=None,
        )


RULE = Rule()
