"""Helper base class for rules: explain() returns the rule id, the condition in words and the receipts."""

from __future__ import annotations

from typing import Any

from qg.detect.model import Finding


class BaseRule:
    RULE_ID = ""
    SEVERITY = "medium"
    EVENTS: frozenset[str] = frozenset()
    CONDITION = ""

    def explain(self, finding: Finding) -> dict[str, Any]:
        return {"rule_id": self.RULE_ID, "condition": finding.condition or self.CONDITION,
                "receipt_ids": list(finding.receipt_ids)}
