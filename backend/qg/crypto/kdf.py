"""HKDF-SHA-384, HMAC-SHA-384 and SHA-256 helpers (spec/SUITE.md section 3)."""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def hkdf(ikm: bytes, *, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA384(), length=length, salt=salt or None, info=info).derive(ikm)


def hmac384(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha384).digest()


def verify_hmac384(key: bytes, data: bytes, tag: bytes) -> bool:
    return hmac.compare_digest(hmac384(key, data), tag)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def enroll_confirm_key(ss: bytes, challenge: bytes) -> bytes:
    return hkdf(ss, salt=challenge, info=b"QG/v1/enroll/confirm", length=48)


def session_confirm_key(ss: bytes, challenge: bytes) -> bytes:
    return hkdf(ss, salt=challenge, info=b"QG/v1/session/confirm", length=48)


def session_mac_key(ss: bytes, challenge: bytes) -> bytes:
    return hkdf(ss, salt=challenge, info=b"QG/v1/session/mac", length=48)


def wrap_key(ss: bytes) -> bytes:
    return hkdf(ss, salt=b"", info=b"QG/v1/wrap", length=32)


def seal_key(master: bytes, epoch: int) -> bytes:
    return hkdf(master, salt=b"", info=f"QG/v1/seal/{epoch}".encode("ascii"), length=32)


def message_key(ss: bytes) -> bytes:
    return hkdf(ss, salt=b"", info=b"QG/v1/message", length=32)
