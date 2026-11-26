"""QG-R008: access rate above the identity's own mean + 3 standard deviations (EWMA baseline per minute).
Medium. Require a fresh session proof."""

from __future__ import annotations

from qg.detect.model import Event, Finding, Response, RuleContext

from ._base import BaseRule

MIN_COUNT = 10  # never fire on tiny absolute rates


class Rule(BaseRule):
    RULE_ID = "QG-R008"
    SEVERITY = "medium"
    EVENTS = frozenset({"access"})
    CONDITION = "Key releases per minute exceeded this person's own EWMA mean plus three standard deviations."

    def evaluate(self, ctx: RuleContext, event: Event) -> Finding | None:
        if not event.user_id or not event.session_id:
            return None
        b = ctx.core.detector.baseline
        count, mean, std, n = b.observe(event.user_id, ctx.core.clock.monotonic())
        if n < b.warmup or count < MIN_COUNT or count <= mean + 3 * max(std, 1.0):
            return None
        return Finding(
            summary=f"{int(count)} key releases this minute against a baseline of {mean:.1f} ± {std:.1f}; "
                    "the session must be proved again.",
            condition=self.CONDITION,
            receipt_ids=event.receipt_ids,
            response=Response("require_fresh_session", "session", event.session_id, 600),
            extra={"count": int(count), "mean_milli": int(mean * 1000), "std_milli": int(std * 1000)},
        )


RULE = Rule()
