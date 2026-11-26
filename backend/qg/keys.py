"""Server key material, generated at first start into QG_KEYS_DIR (never the database volume).

The recovery kit is different: the server only ever holds its public key. `python -m qg.admin recovery-kit
init` generates the kit, hands the private half to the operator (that command's stdout, or a file the operator
chooses outside both volumes) and stores only `recovery-public.json` here. Until a kit is issued the server
runs without recovery wraps.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from qg.crypto.encoding import b64u, b64u_decode
from qg.crypto.sign import DualSigner, Ed25519Key, MLDSAKey
from qg.crypto.xwing import XWingPrivateKey

SERVER_FILE = "server-keys.json"
RECOVERY_PUBLIC_FILE = "recovery-public.json"
LEGACY_RECOVERY_FILE = "recovery-kit.json"  # written by builds before 2026-11-26 evening; must not stay here
KIT_FORMAT = "qg-recovery-kit/1"


class RecoveryKitError(RuntimeError):
    pass


@dataclass(frozen=True)
class ServerKeys:
    signer: DualSigner
    kem: XWingPrivateKey
    seal_master: bytes
    seal_epoch: int

    def __repr__(self) -> str:
        return "ServerKeys(<redacted>)"


def _write_exclusive(path: Path, doc: dict[str, Any]) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")


def load_or_create(keys_dir: Path) -> tuple[ServerKeys, bool]:
    """Return the server keys and whether they were created now."""
    keys_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    server_path = keys_dir / SERVER_FILE
    created = False
    if not server_path.exists():
        _write_exclusive(
            server_path,
            {
                "format": "qg-server-keys/1",
                "suite": "QG-1",
                "ed25519_seed": b64u(os.urandom(32)),
                "mldsa_seed": b64u(os.urandom(32)),
                "kem_seed": b64u(os.urandom(32)),
                "seal_master": b64u(os.urandom(32)),
                "seal_epoch": 1,
            },
        )
        created = True
    doc = json.loads(server_path.read_text())
    keys = ServerKeys(
        signer=DualSigner(
            Ed25519Key.from_seed(b64u_decode(doc["ed25519_seed"], length=32)),
            MLDSAKey.from_seed(b64u_decode(doc["mldsa_seed"], length=32)),
        ),
        kem=XWingPrivateKey.from_seed(b64u_decode(doc["kem_seed"], length=32)),
        seal_master=b64u_decode(doc["seal_master"], length=32),
        seal_epoch=int(doc["seal_epoch"]),
    )
    return keys, created


# ---- recovery kit -----------------------------------------------------------------------------------


class RecoveryPublicKey:
    """Reads the recovery public key from the keys volume, re-reading when the file appears or changes, so a
    running server picks up a kit issued by the admin command."""

    def __init__(self, keys_dir: Path) -> None:
        self.keys_dir = keys_dir
        self._cache: tuple[float, bytes | None] | None = None

    def get(self) -> bytes | None:
        path = self.keys_dir / RECOVERY_PUBLIC_FILE
        try:
            mtime = path.stat().st_mtime
        except FileNotFoundError:
            return self._legacy()
        if self._cache is None or self._cache[0] != mtime:
            doc = json.loads(path.read_text())
            self._cache = (mtime, b64u_decode(doc["recovery_pk"], length=1216))
        return self._cache[1]

    def _legacy(self) -> bytes | None:
        """Older installs kept the public key inside server-keys.json."""
        try:
            doc = json.loads((self.keys_dir / SERVER_FILE).read_text())
        except FileNotFoundError:
            return None
        pk = doc.get("recovery_pk")
        return b64u_decode(pk, length=1216) if pk else None


def legacy_kit_present(keys_dir: Path) -> bool:
    return (keys_dir / LEGACY_RECOVERY_FILE).exists()


def new_recovery_kit(created_at: str) -> tuple[dict[str, Any], bytes]:
    kit = XWingPrivateKey.generate()
    doc = {
        "format": KIT_FORMAT,
        "suite": "QG-1",
        "created_at": created_at,
        "kem_seed": b64u(kit.seed),
        "recovery_pk": b64u(kit.public_key),
        "note": "QuantumGuard recovery kit. Keep it offline; the server does not have it. Opening a file with it "
                "also needs an applied recovery_release change approved by two other people.",
    }
    return doc, kit.public_key


def activate_recovery_public_key(keys_dir: Path, public_key: bytes, created_at: str) -> None:
    """Publish the kit's public half. Fails if any recovery key was already issued (single run)."""
    if RecoveryPublicKey(keys_dir).get() is not None:
        raise RecoveryKitError("a recovery kit was already issued")
    try:
        _write_exclusive(keys_dir / RECOVERY_PUBLIC_FILE, {
            "format": "qg-recovery-public/1", "suite": "QG-1", "created_at": created_at,
            "recovery_pk": b64u(public_key)})
    except FileExistsError as exc:
        raise RecoveryKitError("a recovery kit was already issued") from exc


def load_recovery_kit(path: Path) -> XWingPrivateKey:
    doc = json.loads(Path(path).read_text())
    if doc.get("format") != KIT_FORMAT:
        raise ValueError("not a recovery kit")
    key = XWingPrivateKey.from_seed(b64u_decode(doc["kem_seed"], length=32))
    if b64u(key.public_key) != doc.get("recovery_pk"):
        raise ValueError("recovery kit is inconsistent")
    return key
