"""QG-R005: privilege present in the identity source with no signed change record. Critical.
Quarantine the identity for sensitive resources and cancel its leases."""

from __future__ import annotations

from qg.detect.model import Event, Finding, Response, RuleContext

from ._base import BaseRule


class Rule(BaseRule):
    RULE_ID = "QG-R005"
    SEVERITY = "critical"
    EVENTS = frozenset({"privilege_observed"})
    CONDITION = "The identity source reports a role for a person that no applied, signed change (or seed) grants."

    def evaluate(self, ctx: RuleContext, event: Event) -> Finding | None:
        role = event.data.get("role")
        if not event.user_id or not role:
            return None
        granted = ctx.conn.execute("SELECT 1 FROM user_roles WHERE user_id = ? AND role = ?",
                                   (event.user_id, role)).fetchone()
        if granted:
            return None
        return Finding(
            summary=f"Role {role} appeared in the identity source with no signed change; the person is quarantined "
                    "for confidential and restricted files until an operator lifts it.",
            condition=self.CONDITION,
            receipt_ids=event.receipt_ids,
            response=Response("quarantine_identity", "identity", event.user_id, None),
            extra={"role": role, "source": event.data.get("source")},
        )


RULE = Rule()
