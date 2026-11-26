"""QG-R012: five or more MAC or signature failures in 60 s. Medium. Throttle the source.

The source is whoever produced the failures. A failure that proves no key (a bad request MAC, a failed
handshake proof) only shows the caller's network address and the device or person it claimed. Those are
counted per (address, claim) and the response, scope `source` with id `<address>|<claim>`, makes further
*failed* proofs and bad MACs from that address for that claim answer `QG_RATE_LIMITED` without being recorded
again, for five minutes, liftable by an operator. A correct proof is always verified first and accepted, so
nobody is locked out by someone else's failures, and other people behind the same address are unaffected.
Repeat findings merge into the open alert while its response is active. A signature failure on an
authenticated session (bad manifest, share, change or message signature) comes from that session, which is
throttled. No address range is ever blocked.
"""

from __future__ import annotations

from qg.detect.model import Event, Finding, Response, RuleContext

from ._base import BaseRule

THRESHOLD = 5
WINDOW = 60.0
BLOCK_SECONDS = 300
UNPROVEN = frozenset({"request_mac", "enroll", "session"})


class Rule(BaseRule):
    RULE_ID = "QG-R012"
    SEVERITY = "medium"
    EVENTS = frozenset({"mac_failure", "signature_failure"})
    CONDITION = f"{THRESHOLD} or more request MAC or signature failures within {int(WINDOW)} seconds from one source."

    def evaluate(self, ctx: RuleContext, event: Event) -> Finding | None:
        unproven = event.data.get("kind") in UNPROVEN
        if unproven:
            source, claim = event.data.get("source"), event.data.get("claim")
            if not source or not claim:
                return None
            key = f"r012:src:{source}|{claim}"
        elif event.session_id:
            key = f"r012:session:{event.session_id}"
        else:
            return None
        refs = ctx.core.detector.counters.add(key, ctx.core.clock.monotonic(), WINDOW, (event.receipt_ids or [None])[0])
        if len(refs) < THRESHOLD:
            return None
        if unproven:
            ctx.core.detector.counters.clear(key)
            return Finding(
                summary=f"{len(refs)} failed key proofs in {int(WINDOW)} s from one network address claiming {claim}; "
                        "further failed proofs from that address for that claim are refused for 5 minutes. Correct "
                        "proofs, the claimed device and other people are not affected.",
                condition=self.CONDITION,
                receipt_ids=[r for r in refs if r],
                response=Response("throttle", "source", f"{source}|{claim}", BLOCK_SECONDS),
                subject={"user_id": None, "device_id": None, "session_id": None},
                extra={"source": source, "claim": claim},
            )
        return Finding(
            summary=f"{len(refs)} signature failures in {int(WINDOW)} s on one session; the session is throttled "
                    "for 5 minutes.",
            condition=self.CONDITION,
            receipt_ids=[r for r in refs if r],
            response=Response("throttle", "session", event.session_id, BLOCK_SECONDS),
        )


RULE = Rule()
