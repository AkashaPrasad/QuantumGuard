"""QG-R001: request or session attempt from a revoked device. Critical. Deny; attach to the incident."""

from __future__ import annotations

from qg.detect.model import Event, Finding, Response, RuleContext

from ._base import BaseRule


class Rule(BaseRule):
    RULE_ID = "QG-R001"
    SEVERITY = "critical"
    EVENTS = frozenset({"revoked_device_attempt"})
    CONDITION = "A request or session attempt came from a device that is revoked."

    def evaluate(self, ctx: RuleContext, event: Event) -> Finding | None:
        if not event.device_id:
            return None
        inc = ctx.conn.execute("SELECT id FROM incidents WHERE device_id = ?", (event.device_id,)).fetchone()
        return Finding(
            summary="A revoked device tried to use QuantumGuard and was denied.",
            condition=self.CONDITION,
            receipt_ids=event.receipt_ids,
            response=Response("deny", "device", event.device_id, None),
            incident_id=inc[0] if inc else None,
        )


RULE = Rule()
