"""HTTP client for the QuantumGuard API with QG-1 request signing."""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import httpx

from qg.crypto import aead, kdf
from qg.crypto.encoding import b64u, b64u_decode, canon
from qg.crypto.sign import mldsa_verify, verify_dual
from qg.crypto.suite import RECOVERY_DEVICE_ID, SUITE
from qg.crypto.transcripts import enroll_transcript, request_mac, session_transcript

from .device import DeviceKeys, DeviceState


class ApiError(Exception):
    def __init__(self, status: int, body: dict[str, Any]) -> None:
        err = body.get("error", {}) if isinstance(body, dict) else {}
        self.status = status
        self.code = err.get("code", "QG_UNKNOWN")
        self.reason = err.get("reason")
        self.receipt_id = err.get("receipt_id")
        self.body = body
        super().__init__(f"{status} {self.code} {self.reason}")


class ClientRefused(Exception):
    """The client itself refused data (bad signature, stale directory, failed authentication)."""


def _check(resp: httpx.Response) -> httpx.Response:
    if resp.status_code >= 400:
        try:
            body = resp.json()
        except ValueError:
            body = {}
        raise ApiError(resp.status_code, body)
    return resp


@dataclass
class Session:
    session_id: str
    k_mac: bytes
    seq: int = 0
    info: dict[str, Any] | None = None

    def __repr__(self) -> str:
        return f"Session({self.session_id}, <redacted>)"


class Device:
    """One enrolled device talking to one server."""

    def __init__(self, http: httpx.Client, state: DeviceState) -> None:
        self.http = http
        self.state = state
        self.session: Session | None = None
        self._lock = threading.Lock()
        self.directory: dict[str, Any] | None = None

    @property
    def device_id(self) -> str:
        assert self.state.device_id
        return self.state.device_id

    @property
    def user_id(self) -> str:
        assert self.state.user_id
        return self.state.user_id

    # ---- trust -------------------------------------------------------------------------------

    def _server_pks(self) -> tuple[bytes, bytes]:
        sk = self.state.server_keys
        return b64u_decode(sk["ed25519_pk"]), b64u_decode(sk["mldsa_pk"])

    def accept_directory(self, doc: dict[str, Any]) -> dict[str, Any]:
        """Verify the dual signature and refuse any epoch lower than the highest seen."""
        ed, pq = self._server_pks()
        if not verify_dual(doc, "directory", ed, pq):
            raise ClientRefused("directory signature")
        if doc.get("suite") != SUITE:
            raise ClientRefused("directory suite")
        if doc["epoch"] < self.state.highest_epoch:
            raise ClientRefused("directory epoch rollback")
        self.state.highest_epoch = doc["epoch"]
        self.directory = doc
        return doc

    def refresh_directory(self) -> dict[str, Any]:
        return self.accept_directory(_check(self.http.get("/api/v1/directory")).json())

    def device_entry(self, device_id: str) -> dict[str, Any] | None:
        if self.directory is None:
            self.refresh_directory()
        assert self.directory is not None
        for d in self.directory["devices"]:
            if d["device_id"] == device_id:
                return d
        return None

    def signer_key(self, device_id: str, manifest_epoch: int) -> bytes | None:
        """The signing key a manifest signer had at the manifest's epoch. A signer revoked later is accepted
        only through the dual-signed historical directory, and only if its revocation came after that epoch."""
        entry = self.device_entry(device_id)
        if entry is None:
            self.refresh_directory()
            entry = self.device_entry(device_id)
        if entry is not None:
            return b64u_decode(entry["sig_pk"])
        assert self.directory is not None
        revoked = {r["device_id"]: r for r in self.directory.get("revoked", [])}
        r = revoked.get(device_id)
        if r is None or r["epoch"] <= manifest_epoch:
            return None
        old = _check(self.http.get(f"/api/v1/directory?epoch={manifest_epoch}")).json()
        ed, pq = self._server_pks()
        if not verify_dual(old, "directory", ed, pq) or old.get("epoch") != manifest_epoch:
            raise ClientRefused("historical directory signature")
        for d in old["devices"]:
            if d["device_id"] == device_id:
                return b64u_decode(d["sig_pk"])
        return None

    # ---- session -----------------------------------------------------------------------------

    def login(self) -> dict[str, Any]:
        start = _check(self.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": self.device_id}))
        s = start.json()
        ct = b64u_decode(s["xwing_ct"])
        challenge = b64u_decode(s["challenge"])
        ss = self.state.keys.kem.decapsulate(ct)
        t = session_transcript(start_id=s["start_id"], device_id=self.device_id, challenge_b64u=s["challenge"],
                               xwing_ct_b64u=s["xwing_ct"], directory_epoch=s["directory_epoch"],
                               server_time=s["server_time"])
        body = {
            "start_id": s["start_id"],
            "signature": b64u(self.state.keys.sig.sign(t, "session")),
            "key_confirm": b64u(kdf.hmac384(kdf.session_confirm_key(ss, challenge), t)),
        }
        fin = _check(self.http.post("/api/v1/session/finish", json=body)).json()
        self.session = Session(fin["session_id"], kdf.session_mac_key(ss, challenge), 0, fin)
        return fin

    def raw_request(self, method: str, path: str, *, body: bytes = b"", headers: dict[str, str] | None = None,
                    seq: int | None = None, content_type: str | None = "application/json") -> httpx.Response:
        """Signed request. Returns the raw response (no status check)."""
        if self.session is None:
            raise RuntimeError("not signed in")
        with self._lock:
            if seq is None:
                self.session.seq += 1
                seq = self.session.seq
            else:
                self.session.seq = max(self.session.seq, seq)
            h = {
                "QG-Session": self.session.session_id,
                "QG-Seq": str(seq),
                "QG-MAC": request_mac(self.session.k_mac, method, path, seq, body),
            }
            if content_type and body:
                h["Content-Type"] = content_type
            h.update(headers or {})
            return self.http.request(method, path, content=body, headers=h)

    def call(self, method: str, path: str, payload: Any = None, **kw: Any) -> Any:
        body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        resp = _check(self.raw_request(method, path, body=body, **kw))
        if resp.status_code == 204 or not resp.content:
            return None
        if resp.headers.get("content-type", "").startswith("application/json"):
            return resp.json()
        return resp.content

    def get(self, path: str, **kw: Any) -> Any:
        return self.call("GET", path, **kw)

    def post(self, path: str, payload: Any = None, **kw: Any) -> Any:
        return self.call("POST", path, {} if payload is None else payload, **kw)

    # ---- files -------------------------------------------------------------------------------

    def _wraps_for(self, device_ids: list[str], dek: bytes, file_id: str, version: int, epoch: int) -> list[dict]:
        out = []
        for did in device_ids:
            entry = self.device_entry(did)
            if entry is None:
                self.refresh_directory()
                entry = self.device_entry(did)
            if entry is None:
                raise ClientRefused(f"device {did} not in directory")
            binding = aead.wrap_binding(file_id, version, did, epoch)
            out.append({"device_id": did, **aead.wrap_dek(b64u_decode(entry["kem_pk"]), dek, binding)})
        return out

    def _upload_version(self, file_id: str, version: int, data: bytes, classification: str,
                        recipients: list[str]) -> dict[str, Any]:
        directory = self.refresh_directory()
        epoch = directory["epoch"]
        dek = os.urandom(32)
        blobs = aead.encrypt_file(dek, file_id, version, data)
        for i, blob in enumerate(blobs):
            _check(self.raw_request("PUT", f"/api/v1/files/{file_id}/versions/{version}/chunks/{i}", body=blob,
                                    content_type="application/octet-stream"))
        recips = sorted(set(recipients))
        manifest = {
            "chunk_count": len(blobs),
            "ciphertext_sha256": b64u(aead.ciphertext_sha256(blobs)),
            "classification": classification,
            "directory_epoch": epoch,
            "file_id": file_id,
            "recipients": recips,
            "suite": SUITE,
            "version": version,
        }
        recovery_pk = b64u_decode(directory["recovery_pk"])
        commit = {
            "manifest": manifest,
            "manifest_sig": b64u(self.state.keys.sig.sign(canon(manifest), "manifest")),
            "wraps": self._wraps_for(recips, dek, file_id, version, epoch),
            "recovery_wrap": aead.wrap_dek(recovery_pk, dek,
                                           aead.wrap_binding(file_id, version, RECOVERY_DEVICE_ID, epoch)),
        }
        return self.post(f"/api/v1/files/{file_id}/versions/{version}/commit", commit)

    def protect(self, name: str, data: bytes, classification: str = "confidential",
                recipients: list[str] | None = None) -> dict[str, Any]:
        """Encrypt locally and upload. Recipients are device ids; this device is always included."""
        chunk_count = max(1, -(-len(data) // 1_048_576))
        created = self.post("/api/v1/files", {"name": name, "classification": classification,
                                              "size_bytes": len(data), "chunk_count": chunk_count})
        recips = sorted(set((recipients or []) + [self.device_id]))
        return self._upload_version(created["file_id"], created["version"], data, classification, recips)

    def slot(self, file_id: str) -> dict[str, Any]:
        return self.get(f"/api/v1/files/{file_id}/slot")

    def open_slot(self, slot: dict[str, Any]) -> bytes:
        """Verify the manifest, unwrap the DEK and download every chunk under the lease."""
        manifest = slot["manifest"]
        signer_pk = self.signer_key(slot["signer_device_id"], manifest["directory_epoch"])
        if signer_pk is None or not mldsa_verify(signer_pk, b64u_decode(slot["manifest_sig"]), canon(manifest),
                                                 "manifest"):
            raise ClientRefused("manifest signature")
        if manifest["file_id"] != slot["file_id"] or manifest["version"] != slot["version"]:
            raise ClientRefused("manifest does not match the slot")
        binding = aead.wrap_binding(slot["file_id"], slot["version"], self.device_id, slot["wrap_epoch"])
        try:
            dek = aead.unwrap_dek(self.state.keys.kem, slot["inner_wrap"], binding)
        except aead.AeadError as exc:
            raise ClientRefused("wrap") from exc
        blobs = [self.chunk(slot["file_id"], i, slot["lease"]["lease_id"]) for i in range(manifest["chunk_count"])]
        return self.decrypt(slot, dek, blobs)

    def decrypt(self, slot: dict[str, Any], dek: bytes, blobs: list[bytes]) -> bytes:
        manifest = slot["manifest"]
        if b64u(aead.ciphertext_sha256(blobs)) != manifest["ciphertext_sha256"]:
            raise ClientRefused("ciphertext hash")
        try:
            return b"".join(aead.decrypt_chunks(dek, slot["file_id"], slot["version"], blobs, manifest["chunk_count"]))
        except aead.AeadError as exc:
            raise ClientRefused("chunk authentication") from exc

    def chunk(self, file_id: str, index: int, lease_id: str) -> bytes:
        resp = _check(self.raw_request("GET", f"/api/v1/files/{file_id}/chunks/{index}", headers={"QG-Lease": lease_id}))
        return resp.content

    def open(self, file_id: str) -> bytes:
        return self.open_slot(self.slot(file_id))

    def unwrap(self, slot: dict[str, Any]) -> bytes:
        binding = aead.wrap_binding(slot["file_id"], slot["version"], self.device_id, slot["wrap_epoch"])
        return aead.unwrap_dek(self.state.keys.kem, slot["inner_wrap"], binding)

    def share(self, file_id: str, device_ids: list[str]) -> dict[str, Any]:
        slot = self.slot(file_id)
        dek = self.unwrap(slot)
        directory = self.refresh_directory()
        epoch = directory["epoch"]
        recips = sorted(set(device_ids))
        statement = {"directory_epoch": epoch, "file_id": file_id, "recipients": recips, "suite": SUITE,
                     "version": slot["version"]}
        return self.post(f"/api/v1/files/{file_id}/share", {
            "share": statement,
            "share_sig": b64u(self.state.keys.sig.sign(canon(statement), "share")),
            "wraps": self._wraps_for(recips, dek, file_id, slot["version"], epoch),
        })

    def rekey_pending(self) -> dict[str, Any]:
        return self.get("/api/v1/rekey/pending")

    def rekey_one(self, item: dict[str, Any]) -> dict[str, Any]:
        """Re-encrypt one file under a new key for exactly the listed recipients."""
        file_id = item["file_id"]
        data = self.open(file_id)
        info = self.get(f"/api/v1/files/{file_id}")
        nv = self.post(f"/api/v1/files/{file_id}/versions", {
            "reason": "rekey", "size_bytes": len(data), "chunk_count": max(1, -(-len(data) // 1_048_576))})
        return self._upload_version(file_id, nv["version"], data, info["classification"], item["recipients"])

    def rekey_all(self) -> list[dict[str, Any]]:
        done = []
        for item in self.rekey_pending()["rekeys"]:
            done.append(self.rekey_one(item))
        return done

    def catch_up_shares(self) -> int:
        n = 0
        for s in self.rekey_pending()["shares"]:
            self.share(s["file_id"], [s["device_id"]])
            n += 1
        return n


class QGClient:
    """Entry point: enrol devices and restore them from keystores."""

    def __init__(self, http: httpx.Client | str) -> None:
        self.http = httpx.Client(base_url=http, timeout=30) if isinstance(http, str) else http

    def meta(self) -> dict[str, Any]:
        return _check(self.http.get("/api/v1/meta")).json()

    def enroll(self, code: str, device_name: str, keys: DeviceKeys | None = None) -> Device:
        keys = keys or DeviceKeys.generate()
        meta = self.meta()
        start = _check(self.http.post("/api/v1/enroll/start", json={
            "suite": SUITE, "code": code, "device_name": device_name,
            "kem_pk": keys.kem_pk_b64u, "sig_pk": keys.sig_pk_b64u})).json()
        return self.finish_enroll(start, keys, device_name, meta)

    def finish_enroll(self, start: dict[str, Any], keys: DeviceKeys, device_name: str, meta: dict[str, Any],
                      *, break_signature: bool = False, break_confirm: bool = False) -> Device:
        ss = keys.kem.decapsulate(b64u_decode(start["xwing_ct"]))
        challenge = b64u_decode(start["challenge"])
        t = enroll_transcript(enroll_id=start["enroll_id"], user_id=start["user"]["user_id"], device_name=device_name,
                              kem_pk_b64u=keys.kem_pk_b64u, sig_pk_b64u=keys.sig_pk_b64u,
                              challenge_b64u=start["challenge"], xwing_ct_b64u=start["xwing_ct"],
                              directory_epoch=start["directory_epoch"], server_time=start["server_time"])
        sig = keys.sig.sign(t, "enroll")
        confirm = kdf.hmac384(kdf.enroll_confirm_key(ss, challenge), t)
        if break_signature:
            sig = keys.sig.sign(t + b"x", "enroll")
        if break_confirm:
            confirm = kdf.hmac384(os.urandom(48), t)
        fin = _check(self.http.post("/api/v1/enroll/finish", json={
            "enroll_id": start["enroll_id"], "signature": b64u(sig), "key_confirm": b64u(confirm)})).json()
        cert = fin["certificate"]
        state = DeviceState(keys, device_name, cert["device_id"], cert["user_id"], str(self.http.base_url),
                            cert["created_at"], dict(meta["server_keys"]), 0)
        dev = Device(self.http, state)
        ed, pq = dev._server_pks()  # noqa: SLF001
        if not verify_dual(cert, "certificate", ed, pq):
            raise ClientRefused("certificate signature")
        dev.accept_directory(fin["directory"])
        return dev

    def device(self, state: DeviceState) -> Device:
        return Device(self.http, state)


def iter_chunks(data: bytes, size: int = 1_048_576) -> Iterator[bytes]:
    for i in range(0, max(len(data), 1), size):
        yield data[i : i + size]
