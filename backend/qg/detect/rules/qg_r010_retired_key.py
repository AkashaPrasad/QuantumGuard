"""QG-R010: a retired service key was used. High. Deny."""

from __future__ import annotations

from qg.detect.model import Event, Finding, Response, RuleContext

from ._base import BaseRule


class Rule(BaseRule):
    RULE_ID = "QG-R010"
    SEVERITY = "high"
    EVENTS = frozenset({"retired_key_used"})
    CONDITION = "A request presented a service key that rotation has retired."

    def evaluate(self, ctx: RuleContext, event: Event) -> Finding | None:
        key_id = event.data.get("key_id")
        if not key_id:
            return None
        return Finding(
            summary=f"Retired service key {key_id} was presented and denied.",
            condition=self.CONDITION,
            receipt_ids=event.receipt_ids,
            response=Response("deny", "credential", key_id, None),
        )


RULE = Rule()
