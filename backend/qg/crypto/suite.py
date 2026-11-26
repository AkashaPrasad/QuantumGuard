"""Suite QG-1 constants (spec/SUITE.md)."""

from __future__ import annotations

SUITE = "QG-1"
XWING_DRAFT = "draft-connolly-cfrg-xwing-kem-11"

XWING_PK_LEN = 1216
XWING_CT_LEN = 1120
XWING_SEED_LEN = 32
MLDSA_PK_LEN = 1952
MLDSA_SIG_LEN = 3309
MLDSA_SEED_LEN = 32
ED25519_PK_LEN = 32
ED25519_SIG_LEN = 64

CHUNK_BYTES = 1_048_576
MAX_FILE_BYTES = 104_857_600
MAX_RECIPIENTS = 32
LEASE_SECONDS = 60
SESSION_TTL_SECONDS = 600
SESSION_HARD_CAP_SECONDS = 3600
INVITE_SECONDS = 900
BOOTSTRAP_INVITE_SECONDS = 86_400
EPOCH_GRACE_SECONDS = 60
SESSION_START_SECONDS = 60

PURPOSES = frozenset(
    {
        "enroll",
        "session",
        "manifest",
        "share",
        "change",
        "message",
        "certificate",
        "directory",
        "checkpoint",
        "keyset",
        "policy",
        "report",
    }
)

RECOVERY_DEVICE_ID = "recovery"


def context(purpose: str) -> bytes:
    if purpose not in PURPOSES:
        raise ValueError(f"unknown purpose {purpose!r}")
    return f"QG/v1/{purpose}".encode("ascii")
