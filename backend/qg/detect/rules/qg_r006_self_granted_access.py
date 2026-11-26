"""QG-R006: a grant followed by sensitive access within 10 minutes where the approver (or requester) is the
grantee. High. Quarantine the identity for sensitive resources."""

from __future__ import annotations

from datetime import timedelta

from qg.clock import fmt
from qg.detect.model import Event, Finding, Response, RuleContext

from ._base import BaseRule

WINDOW = timedelta(minutes=10)
SENSITIVE = ("confidential", "restricted")


class Rule(BaseRule):
    RULE_ID = "QG-R006"
    SEVERITY = "high"
    EVENTS = frozenset({"access"})
    CONDITION = ("A role granted to this person in the last 10 minutes was requested or approved by that same person, "
                 "and they then opened a confidential or restricted file.")

    def evaluate(self, ctx: RuleContext, event: Event) -> Finding | None:
        if not event.user_id or event.data.get("classification") not in SENSITIVE:
            return None
        since = fmt(ctx.now() - WINDOW)
        row = ctx.conn.execute(
            "SELECT c.id, c.role FROM changes c WHERE c.target_user_id = ? AND c.status = 'applied' AND c.applied_at >= ?"
            " AND c.type = 'role_grant' AND (c.requested_by = c.target_user_id OR EXISTS (SELECT 1 FROM change_approvals"
            " a WHERE a.change_id = c.id AND a.user_id = c.target_user_id)) ORDER BY c.applied_at DESC LIMIT 1",
            (event.user_id, since)).fetchone()
        if row is None:
            return None
        return Finding(
            summary=f"Self-granted role {row[1]} was followed within 10 minutes by access to a sensitive file; the "
                    "person is quarantined for sensitive files.",
            condition=self.CONDITION,
            receipt_ids=event.receipt_ids,
            response=Response("quarantine_identity", "identity", event.user_id, None),
            extra={"change_id": row[0], "resource": event.data.get("resource")},
        )


RULE = Rule()
