"""Enrolment and session transcripts and the request MAC (spec/SUITE.md sections 5 and 6)."""

from __future__ import annotations

import hashlib

from . import kdf
from .encoding import b64u, canon
from .suite import SUITE

EMPTY_SHA256_HEX = hashlib.sha256(b"").hexdigest()


def enroll_transcript(
    *,
    enroll_id: str,
    user_id: str,
    device_name: str,
    kem_pk_b64u: str,
    sig_pk_b64u: str,
    challenge_b64u: str,
    xwing_ct_b64u: str,
    directory_epoch: int,
    server_time: str,
) -> bytes:
    return canon(
        {
            "challenge": challenge_b64u,
            "device_name": device_name,
            "directory_epoch": directory_epoch,
            "enroll_id": enroll_id,
            "kem_pk": kem_pk_b64u,
            "purpose": "enroll",
            "server_time": server_time,
            "sig_pk": sig_pk_b64u,
            "suite": SUITE,
            "user_id": user_id,
            "xwing_ct": xwing_ct_b64u,
        }
    )


def session_transcript(
    *,
    start_id: str,
    device_id: str,
    challenge_b64u: str,
    xwing_ct_b64u: str,
    directory_epoch: int,
    server_time: str,
) -> bytes:
    return canon(
        {
            "challenge": challenge_b64u,
            "device_id": device_id,
            "directory_epoch": directory_epoch,
            "purpose": "session",
            "server_time": server_time,
            "start_id": start_id,
            "suite": SUITE,
            "xwing_ct": xwing_ct_b64u,
        }
    )


def mac_input(method: str, path: str, seq: int, body: bytes) -> bytes:
    return "\n".join([method.upper(), path, str(seq), hashlib.sha256(body).hexdigest()]).encode("utf-8")


def request_mac(k_mac: bytes, method: str, path: str, seq: int, body: bytes) -> str:
    return b64u(kdf.hmac384(k_mac, mac_input(method, path, seq, body)))


def request_hash(method: str, path: str, seq: int, body: bytes) -> str:
    return b64u(hashlib.sha256(mac_input(method, path, seq, body)).digest())
