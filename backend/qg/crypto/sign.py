"""ML-DSA-65 and Ed25519 signing with QG-1 contexts, and the dual-signature rule."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

from .encoding import EncodingError, b64u, b64u_decode, canon
from .suite import ED25519_PK_LEN, MLDSA_PK_LEN, MLDSA_SEED_LEN, context


class SignatureError(ValueError):
    pass


@dataclass(frozen=True)
class MLDSAKey:
    seed: bytes
    _sk: mldsa.MLDSA65PrivateKey
    public_key: bytes

    @classmethod
    def from_seed(cls, seed: bytes) -> MLDSAKey:
        if len(seed) != MLDSA_SEED_LEN:
            raise SignatureError("seed must be 32 bytes")
        sk = mldsa.MLDSA65PrivateKey.from_seed_bytes(seed)
        return cls(seed, sk, sk.public_key().public_bytes_raw())

    @classmethod
    def generate(cls) -> MLDSAKey:
        return cls.from_seed(os.urandom(MLDSA_SEED_LEN))

    def sign(self, message: bytes, purpose: str) -> bytes:
        return self._sk.sign(message, context(purpose))

    def __repr__(self) -> str:
        return "MLDSAKey(<redacted>)"


def mldsa_verify(pk: bytes, sig: bytes, message: bytes, purpose: str) -> bool:
    if len(pk) != MLDSA_PK_LEN:
        return False
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(pk).verify(sig, message, context(purpose))
        return True
    except (InvalidSignature, ValueError):
        return False


def mldsa_valid_public_key(pk: bytes) -> bool:
    if len(pk) != MLDSA_PK_LEN:
        return False
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(pk)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class Ed25519Key:
    seed: bytes
    _sk: ed25519.Ed25519PrivateKey
    public_key: bytes

    @classmethod
    def from_seed(cls, seed: bytes) -> Ed25519Key:
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        return cls(seed, sk, sk.public_key().public_bytes_raw())

    @classmethod
    def generate(cls) -> Ed25519Key:
        return cls.from_seed(os.urandom(32))

    def sign(self, message: bytes, purpose: str) -> bytes:
        return self._sk.sign(context(purpose) + b"\x00" + message)

    def __repr__(self) -> str:
        return "Ed25519Key(<redacted>)"


def ed25519_verify(pk: bytes, sig: bytes, message: bytes, purpose: str) -> bool:
    if len(pk) != ED25519_PK_LEN:
        return False
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pk).verify(sig, context(purpose) + b"\x00" + message)
        return True
    except (InvalidSignature, ValueError):
        return False


@dataclass(frozen=True)
class DualSigner:
    ed: Ed25519Key
    pq: MLDSAKey

    def sign_object(self, obj: dict[str, Any], purpose: str) -> dict[str, Any]:
        """Return a copy of obj with a `signatures` member over canon(obj without signatures)."""
        body = {k: v for k, v in obj.items() if k != "signatures"}
        m = canon(body)
        return {
            **body,
            "signatures": {
                "ed25519": b64u(self.ed.sign(m, purpose)),
                "mldsa": b64u(self.pq.sign(m, purpose)),
            },
        }

    @property
    def public_keys(self) -> dict[str, str]:
        return {"ed25519_pk": b64u(self.ed.public_key), "mldsa_pk": b64u(self.pq.public_key)}


def verify_dual(obj: Any, purpose: str, ed25519_pk: bytes, mldsa_pk: bytes) -> bool:
    """Dual-signature rule: both signatures present, well formed and valid, nothing else."""
    if not isinstance(obj, dict):
        return False
    sigs = obj.get("signatures")
    if not isinstance(sigs, dict) or set(sigs) != {"ed25519", "mldsa"}:
        return False
    try:
        ed_sig = b64u_decode(sigs["ed25519"])
        pq_sig = b64u_decode(sigs["mldsa"])
        m = canon({k: v for k, v in obj.items() if k != "signatures"})
    except EncodingError:
        return False
    return ed25519_verify(ed25519_pk, ed_sig, m, purpose) and mldsa_verify(mldsa_pk, pq_sig, m, purpose)
