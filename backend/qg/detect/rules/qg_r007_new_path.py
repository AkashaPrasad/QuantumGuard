"""QG-R007: a new path to a crown-jewel resource appears in the privilege graph without an approved change.
High. Alert with the path drawn (no automatic response)."""

from __future__ import annotations

from qg.detect.graph import path_for_role
from qg.detect.model import Event, Finding, RuleContext

from ._base import BaseRule


class Rule(BaseRule):
    RULE_ID = "QG-R007"
    SEVERITY = "high"
    EVENTS = frozenset({"privilege_observed"})
    CONDITION = "A privilege with no approved change opens a path from a person to restricted files or the recovery key."

    def evaluate(self, ctx: RuleContext, event: Event) -> Finding | None:
        role = event.data.get("role")
        if not event.user_id or not role:
            return None
        if ctx.conn.execute("SELECT 1 FROM user_roles WHERE user_id = ? AND role = ?", (event.user_id, role)).fetchone():
            return None
        path = path_for_role(ctx.conn, event.user_id, role, signed=False)
        if not any(e["relation"] == "unlocks" for e in path):
            return None
        return Finding(
            summary=f"Unapproved role {role} opens a path to the recovery key and "
                    f"{sum(1 for e in path if e['relation'] == 'opens')} restricted files.",
            condition=self.CONDITION,
            receipt_ids=event.receipt_ids,
            response=None,
            extra={"path": path},
        )


RULE = Rule()
