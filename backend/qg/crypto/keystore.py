"""Passphrase-protected device keystore shared by the CLI and the browser (spec/SUITE.md section 15)."""

from __future__ import annotations

import json
import os
import unicodedata
from dataclasses import dataclass
from typing import Any

from argon2.low_level import Type, hash_secret_raw

from .aead import AeadError, gcm_decrypt, gcm_encrypt
from .encoding import EncodingError, b64u, b64u_decode, canon, parse_strict
from .suite import SUITE

FORMAT = "qg-keystore/1"
DEFAULT_KDF = {"alg": "argon2id", "version": 19, "m_kib": 19456, "t": 2, "p": 1}
BOUNDS = {"m_kib": (19456, 1_048_576), "t": (2, 10), "p": (1, 4)}


class KeystoreError(ValueError):
    pass


@dataclass(frozen=True)
class DeviceSeeds:
    sig_seed: bytes
    kem_seed: bytes

    def __repr__(self) -> str:
        return "DeviceSeeds(<redacted>)"


def derive_key(passphrase: str, kdf_params: dict[str, Any]) -> bytes:
    salt = b64u_decode(kdf_params["salt"], length=16)
    return hash_secret_raw(
        secret=unicodedata.normalize("NFC", passphrase).encode("utf-8"),
        salt=salt,
        time_cost=kdf_params["t"],
        memory_cost=kdf_params["m_kib"],
        parallelism=kdf_params["p"],
        hash_len=32,
        type=Type.ID,
        version=19,
    )


def seal_keystore(
    seeds: DeviceSeeds,
    passphrase: str,
    label: dict[str, Any],
    *,
    kdf_params: dict[str, int] | None = None,
    salt: bytes | None = None,
    nonce: bytes | None = None,
) -> dict[str, Any]:
    params: dict[str, Any] = dict(kdf_params or DEFAULT_KDF)
    params["alg"], params["version"] = "argon2id", 19
    params["salt"] = b64u(salt if salt is not None else os.urandom(16))
    nonce = nonce if nonce is not None else os.urandom(12)
    header = {
        "aead": {"alg": "AES-256-GCM", "nonce": b64u(nonce)},
        "format": FORMAT,
        "kdf": params,
        "label": label,
        "suite": SUITE,
    }
    _check_header(header)
    key = derive_key(passphrase, params)
    plaintext = canon({"kem_seed": b64u(seeds.kem_seed), "sig_seed": b64u(seeds.sig_seed)})
    return {**header, "ciphertext": b64u(gcm_encrypt(key, nonce, plaintext, canon(header)))}


def _check_header(header: dict[str, Any]) -> None:
    if header.get("format") != FORMAT or header.get("suite") != SUITE:
        raise KeystoreError("not a QG-1 keystore")
    kdf_params = header.get("kdf")
    if not isinstance(kdf_params, dict) or set(kdf_params) != {"alg", "version", "m_kib", "t", "p", "salt"}:
        raise KeystoreError("bad kdf header")
    if kdf_params["alg"] != "argon2id" or kdf_params["version"] != 19:
        raise KeystoreError("bad kdf header")
    for name, (lo, hi) in BOUNDS.items():
        v = kdf_params[name]
        if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
            raise KeystoreError("kdf parameters out of bounds")
    aead = header.get("aead")
    if not isinstance(aead, dict) or set(aead) != {"alg", "nonce"} or aead["alg"] != "AES-256-GCM":
        raise KeystoreError("bad aead header")
    if not isinstance(header.get("label"), dict):
        raise KeystoreError("bad label")


def open_keystore(doc: dict[str, Any], passphrase: str) -> DeviceSeeds:
    if not isinstance(doc, dict) or set(doc) != {"aead", "ciphertext", "format", "kdf", "label", "suite"}:
        raise KeystoreError("not a QG-1 keystore")
    header = {k: v for k, v in doc.items() if k != "ciphertext"}
    _check_header(header)
    try:
        nonce = b64u_decode(header["aead"]["nonce"], length=12)
        ct = b64u_decode(doc["ciphertext"])
        key = derive_key(passphrase, header["kdf"])
        pt = gcm_decrypt(key, nonce, ct, canon(header))
        inner = parse_strict(pt)
        return DeviceSeeds(
            sig_seed=b64u_decode(inner["sig_seed"], length=32),
            kem_seed=b64u_decode(inner["kem_seed"], length=32),
        )
    except (AeadError, EncodingError, KeyError, TypeError) as exc:
        raise KeystoreError("wrong passphrase or damaged keystore") from exc


def load_file(path: str) -> dict[str, Any]:
    with open(path, "rb") as fh:
        return parse_strict(fh.read())


def save_file(path: str, doc: dict[str, Any]) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
