"""Shared helpers for the security and attack suites.

Everything here drives the production app through its public HTTP API with the real `qg` client library.
The only direct database or file access is test-owned: reading public keys, observing state for assertions,
and fault injection or artifact corruption that a test names explicitly. Nothing here changes a policy
decision, a cryptographic check or an access check.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from qg.crypto import aead
from qg.crypto.encoding import b64u, canon
from qg.crypto.suite import RECOVERY_DEVICE_ID, SUITE
from qg.ids import new_id

CHUNK = 1_048_576


def deny(resp: Any, status: int, code: str, reason: str | None = None) -> dict[str, Any]:
    """Assert a refusal in the exact shape of spec/API.md 1.2 and return the error object."""
    assert resp.status_code == status, (resp.status_code, resp.text[:300])
    err = resp.json()["error"]
    assert err["code"] == code, err
    if reason is not None:
        assert err["reason"] == reason, err
    assert resp.headers.get("QG-Request-Id")
    assert "inner_wrap" not in resp.text and "wrapped_dek" not in resp.text
    return err


def refill(env: Any) -> None:
    """Refill the per-address and per-session rate-limit buckets. Tests enrol more devices from one address
    than a person would; rate limiting is not what these tests measure."""
    env.core.buckets._b.clear()  # noqa: SLF001


def q(env: Any, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    """Read-only observation of server state for assertions."""
    return env.core.db.all(sql, params)


def count(env: Any, sql: str, params: tuple = ()) -> int:
    return env.core.db.one(sql, params)[0]


def kem_pk(env: Any, device_id: str) -> bytes:
    """A device's public KEM key (public data; read from storage so a revoked device can be named too)."""
    return bytes(env.core.db.one("SELECT kem_pk FROM devices WHERE device_id = ?", (device_id,))[0])


def new_file(dev: Any, name: str, data: bytes, classification: str = "confidential") -> str:
    created = dev.post("/api/v1/files", {"name": name, "classification": classification, "size_bytes": len(data),
                                          "chunk_count": max(1, -(-len(data) // CHUNK))})
    return created["file_id"]


def upload_chunks(dev: Any, file_id: str, version: int, data: bytes) -> tuple[bytes, list[bytes]]:
    dek = os.urandom(32)
    blobs = aead.encrypt_file(dek, file_id, version, data)
    for i, blob in enumerate(blobs):
        r = dev.raw_request("PUT", f"/api/v1/files/{file_id}/versions/{version}/chunks/{i}", body=blob,
                            content_type="application/octet-stream")
        assert r.status_code == 204, r.text
    return dek, blobs


def commit_body(env: Any, dev: Any, file_id: str, version: int, dek: bytes, blobs: list[bytes],
                classification: str, recipients: list[str], *, epoch: int | None = None,
                suite: str = SUITE) -> dict[str, Any]:
    """The commit request exactly as the client builds it, with a chosen epoch or recipient list."""
    directory = dev.refresh_directory()
    epoch = directory["epoch"] if epoch is None else epoch
    recips = sorted(set(recipients))
    manifest = {
        "chunk_count": len(blobs),
        "ciphertext_sha256": b64u(aead.ciphertext_sha256(blobs)),
        "classification": classification,
        "directory_epoch": epoch,
        "file_id": file_id,
        "recipients": recips,
        "suite": suite,
        "version": version,
    }
    wraps = [{"device_id": d, **aead.wrap_dek(kem_pk(env, d), dek, aead.wrap_binding(file_id, version, d, epoch))}
             for d in recips]
    body = {
        "manifest": manifest,
        "manifest_sig": b64u(dev.state.keys.sig.sign(canon(manifest), "manifest")),
        "wraps": wraps,
    }
    recovery_pk = env.core.recovery.get()  # present once a recovery kit has been issued
    if recovery_pk is not None:
        body["recovery_wrap"] = aead.wrap_dek(recovery_pk, dek,
                                              aead.wrap_binding(file_id, version, RECOVERY_DEVICE_ID, epoch))
    return body


def send_commit(dev: Any, file_id: str, version: int, body: dict[str, Any]) -> Any:
    return dev.raw_request("POST", f"/api/v1/files/{file_id}/versions/{version}/commit",
                           body=json.dumps(body, separators=(",", ":")).encode())


def protect_raw(env: Any, dev: Any, name: str, data: bytes, classification: str, recipients: list[str], *,
                epoch: int | None = None) -> tuple[str, Any]:
    """Create, upload and commit with a chosen recipient list or epoch. Returns (file_id, raw response)."""
    fid = new_file(dev, name, data, classification)
    dek, blobs = upload_chunks(dev, fid, 1, data)
    body = commit_body(env, dev, fid, 1, dek, blobs, classification, recipients, epoch=epoch)
    return fid, send_commit(dev, fid, 1, body)


def blob_dir(env: Any, file_id: str, version: int) -> Path:
    return env.core.blobs.root / file_id / str(version)


def chunks_with_lease(dev: Any, slot: dict[str, Any]) -> list[bytes]:
    return [dev.chunk(slot["file_id"], i, slot["lease"]["lease_id"]) for i in range(slot["manifest"]["chunk_count"])]


def absent_id(prefix: str) -> str:
    return new_id(prefix)


def encodings(secret: bytes) -> list[str]:
    """Text forms a secret could take in a log line."""
    out = [secret.hex(), secret.hex().upper(), b64u(secret), base64.b64encode(secret).decode()]
    try:
        text = secret.decode("utf-8")
        if text.isprintable() and len(text) >= 8:
            out.append(text)
    except UnicodeDecodeError:
        pass
    return out
