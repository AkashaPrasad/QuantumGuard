"""AES-256-GCM framing: file chunks, DEK wraps and server seals (spec/SUITE.md section 7)."""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import kdf, xwing
from .encoding import EncodingError, b64u, b64u_decode, canon
from .suite import CHUNK_BYTES, SUITE

NONCE_LEN = 12
TAG_LEN = 16


class AeadError(ValueError):
    """Authentication or framing failure. Never says which byte was wrong."""


def gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise AeadError("authentication failed") from exc


# ---- chunks ---------------------------------------------------------------------------------


def chunk_aad(file_id: str, version: int, index: int, is_last: bool) -> bytes:
    return canon(
        {"chunk_index": index, "file_id": file_id, "is_last": is_last, "suite": SUITE, "version": version}
    )


def split_plaintext(data: bytes, chunk_bytes: int = CHUNK_BYTES) -> list[bytes]:
    if not data:
        return [b""]
    return [data[i : i + chunk_bytes] for i in range(0, len(data), chunk_bytes)]


def encrypt_chunk(
    dek: bytes, prefix: bytes, file_id: str, version: int, index: int, is_last: bool, chunk: bytes
) -> bytes:
    if len(prefix) != 8:
        raise ValueError("nonce prefix must be 8 bytes")
    nonce = prefix + index.to_bytes(4, "big")
    return nonce + gcm_encrypt(dek, nonce, chunk, chunk_aad(file_id, version, index, is_last))


def encrypt_file(
    dek: bytes, file_id: str, version: int, data: bytes, prefix: bytes | None = None
) -> list[bytes]:
    prefix = prefix if prefix is not None else os.urandom(8)
    parts = split_plaintext(data)
    n = len(parts)
    return [encrypt_chunk(dek, prefix, file_id, version, i, i == n - 1, p) for i, p in enumerate(parts)]


def decrypt_chunks(dek: bytes, file_id: str, version: int, blobs: Iterable[bytes], chunk_count: int) -> Iterator[bytes]:
    prefix: bytes | None = None
    i = -1
    for i, blob in enumerate(blobs):
        if i >= chunk_count or len(blob) < NONCE_LEN + TAG_LEN:
            raise AeadError("bad chunk framing")
        nonce = blob[:NONCE_LEN]
        if nonce[8:12] != i.to_bytes(4, "big"):
            raise AeadError("chunk out of order")
        if prefix is None:
            prefix = nonce[:8]
        elif nonce[:8] != prefix:
            raise AeadError("chunk from another file")
        yield gcm_decrypt(dek, nonce, blob[NONCE_LEN:], chunk_aad(file_id, version, i, i == chunk_count - 1))
    if i != chunk_count - 1:
        raise AeadError("file truncated")


def ciphertext_sha256(blobs: Iterable[bytes]) -> bytes:
    import hashlib

    h = hashlib.sha256()
    for b in blobs:
        h.update(b)
    return h.digest()


# ---- DEK wraps -------------------------------------------------------------------------------


def wrap_binding(file_id: str, version: int, device_id: str, directory_epoch: int) -> dict[str, Any]:
    return {
        "device_id": device_id,
        "directory_epoch": directory_epoch,
        "file_id": file_id,
        "suite": SUITE,
        "version": version,
    }


def wrap_dek_with_secret(ss: bytes, dek: bytes, binding: dict[str, Any], nonce: bytes | None = None) -> bytes:
    nonce = nonce if nonce is not None else os.urandom(NONCE_LEN)
    return nonce + gcm_encrypt(kdf.wrap_key(ss), nonce, dek, canon(binding))


def wrap_dek(kem_pk: bytes, dek: bytes, binding: dict[str, Any]) -> dict[str, str]:
    ss, ct = xwing.encapsulate(kem_pk)
    return {"xwing_ct": b64u(ct), "wrapped_dek": b64u(wrap_dek_with_secret(ss, dek, binding))}


def unwrap_dek(kem_sk: xwing.XWingPrivateKey, inner_wrap: dict[str, Any], binding: dict[str, Any]) -> bytes:
    try:
        ct = b64u_decode(inner_wrap["xwing_ct"], length=1120)
        wrapped = b64u_decode(inner_wrap["wrapped_dek"], length=NONCE_LEN + 32 + TAG_LEN)
    except (KeyError, TypeError, EncodingError) as exc:
        raise AeadError("bad wrap") from exc
    try:
        ss = kem_sk.decapsulate(ct)
    except xwing.XWingError as exc:
        raise AeadError("bad wrap") from exc
    return gcm_decrypt(kdf.wrap_key(ss), wrapped[:NONCE_LEN], wrapped[NONCE_LEN:], canon(binding))


# ---- server seal -----------------------------------------------------------------------------


def seal_aad(slot_id: str, file_id: str, version: int, device_id: str, seal_epoch: int) -> bytes:
    return canon(
        {
            "device_id": device_id,
            "file_id": file_id,
            "seal_epoch": seal_epoch,
            "slot_id": slot_id,
            "suite": SUITE,
            "version": version,
        }
    )


def seal(master: bytes, seal_epoch: int, aad: bytes, inner_wrap: dict[str, Any]) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    return nonce + gcm_encrypt(kdf.seal_key(master, seal_epoch), nonce, canon(inner_wrap), aad)


def unseal(master: bytes, seal_epoch: int, aad: bytes, sealed: bytes) -> bytes:
    if len(sealed) < NONCE_LEN + TAG_LEN:
        raise AeadError("bad seal")
    return gcm_decrypt(kdf.seal_key(master, seal_epoch), sealed[:NONCE_LEN], sealed[NONCE_LEN:], aad)
