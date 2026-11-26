"""X-Wing hybrid KEM composed per draft-connolly-cfrg-xwing-kem-11 from ML-KEM-768 and X25519.

Protocol code: it only composes primitives from `cryptography`.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import mlkem, x25519

from .suite import XWING_CT_LEN, XWING_PK_LEN, XWING_SEED_LEN

XWING_LABEL = bytes.fromhex("5c2e2f2f5e5c")  # "\.//^\"
_MLKEM_PK_LEN = 1184
_MLKEM_CT_LEN = 1088


class XWingError(ValueError):
    pass


def _combiner(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()


@dataclass(frozen=True)
class XWingPrivateKey:
    """Expanded decapsulation key; never serialised except as its 32-byte seed."""

    seed: bytes
    _mlkem: mlkem.MLKEM768PrivateKey
    _x25519: x25519.X25519PrivateKey
    public_key: bytes

    @classmethod
    def from_seed(cls, seed: bytes) -> XWingPrivateKey:
        if len(seed) != XWING_SEED_LEN:
            raise XWingError("seed must be 32 bytes")
        expanded = hashlib.shake_256(seed).digest(96)
        sk_m = mlkem.MLKEM768PrivateKey.from_seed_bytes(expanded[0:64])
        sk_x = x25519.X25519PrivateKey.from_private_bytes(expanded[64:96])
        pk = sk_m.public_key().public_bytes_raw() + sk_x.public_key().public_bytes_raw()
        return cls(seed, sk_m, sk_x, pk)

    @classmethod
    def generate(cls) -> XWingPrivateKey:
        return cls.from_seed(os.urandom(XWING_SEED_LEN))

    def decapsulate(self, ct: bytes) -> bytes:
        if len(ct) != XWING_CT_LEN:
            raise XWingError("ciphertext must be 1120 bytes")
        ct_m, ct_x = ct[:_MLKEM_CT_LEN], ct[_MLKEM_CT_LEN:]
        ss_m = self._mlkem.decapsulate(ct_m)
        try:
            ss_x = self._x25519.exchange(x25519.X25519PublicKey.from_public_bytes(ct_x))
        except ValueError as exc:  # all-zero shared secret
            raise XWingError("invalid X25519 share") from exc
        return _combiner(ss_m, ss_x, ct_x, self.public_key[_MLKEM_PK_LEN:])

    def __repr__(self) -> str:  # never print key material
        return "XWingPrivateKey(<redacted>)"


def encapsulate(pk: bytes) -> tuple[bytes, bytes]:
    """Return (shared_secret, ciphertext)."""
    if len(pk) != XWING_PK_LEN:
        raise XWingError("public key must be 1216 bytes")
    pk_m, pk_x = pk[:_MLKEM_PK_LEN], pk[_MLKEM_PK_LEN:]
    try:
        mpk = mlkem.MLKEM768PublicKey.from_public_bytes(pk_m)
        xpk = x25519.X25519PublicKey.from_public_bytes(pk_x)
    except ValueError as exc:
        raise XWingError("invalid public key") from exc
    ek_x = x25519.X25519PrivateKey.generate()
    ct_x = ek_x.public_key().public_bytes_raw()
    try:
        ss_x = ek_x.exchange(xpk)
    except ValueError as exc:
        raise XWingError("invalid X25519 public key") from exc
    ss_m, ct_m = mpk.encapsulate()
    return _combiner(ss_m, ss_x, ct_x, pk_x), ct_m + ct_x


def validate_public_key(pk: bytes) -> None:
    if len(pk) != XWING_PK_LEN:
        raise XWingError("public key must be 1216 bytes")
    try:
        mlkem.MLKEM768PublicKey.from_public_bytes(pk[:_MLKEM_PK_LEN])
        x25519.X25519PublicKey.from_public_bytes(pk[_MLKEM_PK_LEN:])
    except ValueError as exc:
        raise XWingError("invalid public key") from exc
