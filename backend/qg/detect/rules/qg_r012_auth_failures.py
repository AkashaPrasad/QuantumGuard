"""QG-R012: five or more MAC or signature failures in 60 s. Medium. Throttle the source.

The source is whoever produced the failures. A failure that proves no key (a bad request MAC, a failed
handshake proof) only shows the caller's network address: those are counted per address and the response
blocks new handshakes from that address for five minutes. The device or session the failures *claim* is never
throttled, so nobody can lock another person out by failing on their behalf. A signature failure on an
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
            source = event.data.get("source")
            if not source:
                return None
            key = f"r012:addr:{source}"
        elif event.session_id:
            key = f"r012:session:{event.session_id}"
        else:
            return None
        refs = ctx.core.detector.counters.add(key, ctx.core.clock.monotonic(), WINDOW, (event.receipt_ids or [None])[0])
        if len(refs) < THRESHOLD:
            return None
        if unproven:
            ctx.core.block_handshakes(source, BLOCK_SECONDS)
            ctx.core.detector.counters.clear(key)
            return Finding(
                summary=f"{len(refs)} failed key proofs in {int(WINDOW)} s from one network address; new handshakes from "
                        "that address are refused for 5 minutes. The devices and sessions they named are not affected.",
                condition=self.CONDITION,
                receipt_ids=[r for r in refs if r],
                response=None,
                subject={"user_id": None, "device_id": None, "session_id": None},
                extra={"source": source, "blocked_seconds": BLOCK_SECONDS},
            )
        return Finding(
            summary=f"{len(refs)} signature failures in {int(WINDOW)} s on one session; the session is throttled "
                    "for 5 minutes.",
            condition=self.CONDITION,
            receipt_ids=[r for r in refs if r],
            response=Response("throttle", "session", event.session_id, BLOCK_SECONDS),
        )


RULE = Rule()
