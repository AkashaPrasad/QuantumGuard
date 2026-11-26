"""Server key material, generated at first start into QG_KEYS_DIR (never the database volume)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from qg.crypto.encoding import b64u, b64u_decode
from qg.crypto.sign import DualSigner, Ed25519Key, MLDSAKey
from qg.crypto.xwing import XWingPrivateKey

SERVER_FILE = "server-keys.json"
RECOVERY_FILE = "recovery-kit.json"


@dataclass(frozen=True)
class ServerKeys:
    signer: DualSigner
    kem: XWingPrivateKey
    seal_master: bytes
    seal_epoch: int
    recovery_pk: bytes

    def __repr__(self) -> str:
        return "ServerKeys(<redacted>)"


def _write_secret(path: Path, doc: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")


def load_or_create(keys_dir: Path) -> tuple[ServerKeys, bool]:
    """Return the server keys and whether they were created now."""
    keys_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    server_path, kit_path = keys_dir / SERVER_FILE, keys_dir / RECOVERY_FILE
    created = False
    if not server_path.exists():
        recovery = XWingPrivateKey.generate()
        if not kit_path.exists():
            _write_secret(
                kit_path,
                {
                    "format": "qg-recovery-kit/1",
                    "suite": "QG-1",
                    "kem_seed": b64u(recovery.seed),
                    "recovery_pk": b64u(recovery.public_key),
                    "note": "Recovery kit: move this file offline. Opening a recovery wrap also needs an applied "
                    "recovery_release change approved by two other people.",
                },
            )
        kit = json.loads(kit_path.read_text())
        _write_secret(
            server_path,
            {
                "format": "qg-server-keys/1",
                "suite": "QG-1",
                "ed25519_seed": b64u(os.urandom(32)),
                "mldsa_seed": b64u(os.urandom(32)),
                "kem_seed": b64u(os.urandom(32)),
                "seal_master": b64u(os.urandom(32)),
                "seal_epoch": 1,
                "recovery_pk": kit["recovery_pk"],
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
        recovery_pk=b64u_decode(doc["recovery_pk"], length=1216),
    )
    return keys, created


def load_recovery_kit(path: Path) -> XWingPrivateKey:
    doc = json.loads(Path(path).read_text())
    if doc.get("format") != "qg-recovery-kit/1":
        raise ValueError("not a recovery kit")
    return XWingPrivateKey.from_seed(b64u_decode(doc["kem_seed"], length=32))
