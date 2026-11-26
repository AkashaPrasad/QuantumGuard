"""QG-R004: decoy file or decoy service key touched. Critical. End session, quarantine device pending operator."""

from __future__ import annotations

from qg.detect.model import Event, Finding, Response, RuleContext

from ._base import BaseRule


class Rule(BaseRule):
    RULE_ID = "QG-R004"
    SEVERITY = "critical"
    EVENTS = frozenset({"decoy_touched"})
    CONDITION = "A planted decoy object that no legitimate workflow references was accessed."

    def evaluate(self, ctx: RuleContext, event: Event) -> Finding | None:
        if event.device_id:
            response = Response("quarantine_device", "device", event.device_id, None)
        elif event.data.get("key_id"):
            response = Response("deny", "credential", event.data["key_id"], None)
        else:
            return None
        return Finding(
            summary=f"Decoy {event.data.get('kind', 'object')} {event.data.get('resource') or event.data.get('key_id')}"
                    " was touched; the device is quarantined until an operator lifts it.",
            condition=self.CONDITION,
            receipt_ids=event.receipt_ids,
            response=response,
        )


RULE = Rule()
