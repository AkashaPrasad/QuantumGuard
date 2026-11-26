"""Message statement (spec/SUITE.md section 11): the sender signs one digest per recipient envelope, so any
single recipient device can verify the signature from its own envelope plus the list of digests."""

from __future__ import annotations

import hashlib
from typing import Any

from .encoding import b64u, canon
from .suite import SUITE


def envelope_digest(device_id: str, xwing_ct: str, ciphertext: str) -> str:
    """b64u(SHA-256(canon({ciphertext, device_id, xwing_ct}))) with the b64u strings exactly as sent."""
    return b64u(hashlib.sha256(canon({"ciphertext": ciphertext, "device_id": device_id, "xwing_ct": xwing_ct})).digest())


def digests_for(envelopes: list[dict[str, Any]]) -> list[dict[str, str]]:
    return sorted(({"device_id": e["device_id"], "digest": envelope_digest(e["device_id"], e["xwing_ct"],
                                                                             e["ciphertext"])} for e in envelopes),
                  key=lambda d: d["device_id"])


def statement(to_user_id: str, envelope_digests: list[dict[str, str]]) -> bytes:
    """canon({envelope_digests: [{device_id, digest}] sorted by device_id, suite, to_user_id})."""
    return canon({"envelope_digests": sorted(({"device_id": d["device_id"], "digest": d["digest"]}
                                              for d in envelope_digests), key=lambda d: d["device_id"]),
                  "suite": SUITE, "to_user_id": to_user_id})
