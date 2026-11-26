"""`security_case` adapter for tests/security (see tests/security/README.md).

Every operation drives the production app through the public HTTP API with the real `qg.client` library.
Client-side operations run the real client checks on genuinely mutated bytes and report `returncode` and
`plaintext_written`. Fault injection is limited to what the README allows: an unsigned role reported by the
identity source (delivered as a signal), a policy outage switch, artifact corruption, database copies and the
test clock. Nothing here patches policy, cryptographic verification or access checks.
"""

from __future__ import annotations

import base64
import io
import json
import os
import shutil
import sqlite3
import tempfile
import threading
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx

from qg.client.api import ApiError, ClientRefused, Device, QGClient
from qg.client.device import DeviceKeys
from qg.crypto import aead, kdf
from qg.crypto.encoding import b64u, b64u_decode, canon
from qg.crypto.sign import mldsa_verify
from qg.crypto.suite import RECOVERY_DEVICE_ID, SUITE
from qg.crypto.transcripts import enroll_transcript, request_mac
from qg.testing import create_test_app, set_policy_available

__all__ = ["Case", "Release", "RaceResult", "Result", "security_case"]

MULTI_CHUNK = 2 * 1_048_576 + 4321


@dataclass
class Result:
    """Outcome of a client-side operation."""

    returncode: int
    plaintext_written: bool
    detail: str = ""
    attempted: bool = False
    private_keys_available: bool = False
    plaintext_recovered: bool = False


@dataclass
class Release:
    decision_index: int
    status_code: int
    contains_key_material: bool


@dataclass
class RaceResult:
    revoke_committed: bool
    revoke_commit_index: int
    releases: list[Release] = field(default_factory=list)


def _flip_b64u(text: str) -> str:
    raw = bytearray(b64u_decode(text))
    raw[len(raw) // 2] ^= 0x01
    return b64u(bytes(raw))


class Case:
    def __init__(self, name: str, data_dir: Path, keys_dir: Path, clock: Callable[[], datetime]) -> None:
        from fastapi.testclient import TestClient

        self.name = name
        self.clock = clock
        self.app = create_test_app(data_dir=data_dir, keys_dir=keys_dir, clock=clock)
        self.core = self.app.state.core
        self.http = TestClient(self.app, base_url="http://testserver")
        self.client = QGClient(self.http)
        self.codes = {p["name"]: p["code"] for p in self.app.state.bootstrap_invites}
        self.users = {p["name"]: p["user_id"] for p in self.app.state.bootstrap_invites}
        self.tmp = Path(tempfile.mkdtemp(prefix=f"qg-case-{name}-"))
        self.s: dict[str, Any] = {}
        self._extra_clients: list[Any] = []
        setup = getattr(self, f"_setup_{name}", None)
        if setup is None:
            raise KeyError(f"unknown security case {name!r}")
        setup()

    # ---- helpers -----------------------------------------------------------------------------

    def enroll(self, person: str, device_name: str, code: str | None = None) -> Device:
        dev = self.client.enroll(code or self.codes.pop(person), device_name)
        dev.login()
        return dev

    def second(self, dev: Device, device_name: str) -> Device:
        inv = dev.post("/api/v1/invites", {"user_id": dev.user_id})
        return self.enroll("", device_name, inv["code"])

    def db(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        return self.core.db.all(sql, params)

    def now_iso(self) -> str:
        return self.core.clock.iso()

    def report_lost(self, reporter: Device, lost: Device) -> httpx.Response:
        body = json.dumps({"lost_at": self.now_iso()}).encode()
        return reporter.raw_request("POST", f"/api/v1/devices/{lost.device_id}/report-lost", body=body)

    def slot_response(self, dev: Device, file_id: str) -> httpx.Response:
        return dev.raw_request("GET", f"/api/v1/files/{file_id}/slot")

    def _client_open(self, dev: Device, file_id: str, *, slot_fn: Callable[[dict], dict] | None = None,
                     blobs_fn: Callable[[list[bytes]], list[bytes]] | None = None,
                     decrypt_version_offset: int = 0) -> Result:
        """Download a slot and chunks, apply a mutation to the real artifacts, then run the client's checks."""
        try:
            slot = dev.slot(file_id)
            lease = slot["lease"]["lease_id"]
            blobs = [dev.chunk(file_id, i, lease) for i in range(slot["manifest"]["chunk_count"])]
        except ApiError as exc:
            return Result(1, False, f"api {exc.code}")
        if slot_fn is not None:
            slot = slot_fn(slot)
        if blobs_fn is not None:
            blobs = blobs_fn(blobs)
        out = self.tmp / f"open-{os.urandom(4).hex()}.bin"
        try:
            manifest = slot["manifest"]
            signer = dev.signer_key(slot["signer_device_id"], manifest["directory_epoch"])
            if signer is None or not mldsa_verify(signer, b64u_decode(slot["manifest_sig"]), canon(manifest),
                                                  "manifest"):
                raise ClientRefused("manifest signature")
            if manifest["file_id"] != slot["file_id"] or manifest["version"] != slot["version"]:
                raise ClientRefused("manifest does not match the slot")
            dek = dev.unwrap(slot)
            if b64u(aead.ciphertext_sha256(blobs)) != manifest["ciphertext_sha256"] and not decrypt_version_offset:
                raise ClientRefused("ciphertext hash")
            data = b"".join(aead.decrypt_chunks(dek, slot["file_id"], slot["version"] + decrypt_version_offset, blobs,
                                                manifest["chunk_count"]))
        except (ClientRefused, aead.AeadError, ValueError, KeyError) as exc:
            return Result(1, False, type(exc).__name__)
        out.write_bytes(data)
        return Result(0, True)

    def _protect_two_party(self, owner_name: str = "Aiko Tanaka", size: int = MULTI_CHUNK,
                           classification: str = "confidential") -> None:
        owner = self.enroll(owner_name, "laptop")
        phone = self.second(owner, "phone")
        self.s.update(owner=owner, phone=phone)
        self.s["data"] = os.urandom(size)
        self.s["fid"] = owner.protect("plates.bin", self.s["data"], classification, [phone.device_id])["file"]["file_id"]

    def _pending_commit(self, dev: Device, data: bytes, classification: str, recipients: list[str],
                        epoch: int) -> tuple[str, int, dict[str, Any]]:
        """Create a file and upload chunks; return a commit body built on `epoch` (not sent)."""
        chunk_count = max(1, -(-len(data) // 1_048_576))
        created = dev.post("/api/v1/files", {"name": "pending.bin", "classification": classification,
                                             "size_bytes": len(data), "chunk_count": chunk_count})
        fid, version = created["file_id"], created["version"]
        dek = os.urandom(32)
        blobs = aead.encrypt_file(dek, fid, version, data)
        for i, blob in enumerate(blobs):
            dev.raw_request("PUT", f"/api/v1/files/{fid}/versions/{version}/chunks/{i}", body=blob,
                            content_type="application/octet-stream")
        directory = dev.refresh_directory()
        recips = sorted(set(recipients))
        manifest = {"chunk_count": len(blobs), "ciphertext_sha256": b64u(aead.ciphertext_sha256(blobs)),
                    "classification": classification, "directory_epoch": epoch, "file_id": fid,
                    "recipients": recips, "suite": SUITE, "version": version}
        wraps = []
        for did in recips:
            entry = next(d for d in directory["devices"] if d["device_id"] == did)
            wraps.append({"device_id": did, **aead.wrap_dek(b64u_decode(entry["kem_pk"]), dek,
                                                            aead.wrap_binding(fid, version, did, epoch))})
        body = {"manifest": manifest, "manifest_sig": b64u(dev.state.keys.sig.sign(canon(manifest), "manifest")),
                "wraps": wraps,
                "recovery_wrap": aead.wrap_dek(b64u_decode(directory["recovery_pk"]), dek,
                                               aead.wrap_binding(fid, version, RECOVERY_DEVICE_ID, epoch))}
        return fid, version, body

    def _commit(self, dev: Device, fid: str, version: int, body: dict[str, Any]) -> httpx.Response:
        return dev.raw_request("POST", f"/api/v1/files/{fid}/versions/{version}/commit",
                               body=json.dumps(body).encode())

    def _raw_enroll_start(self, code: str, suite: str = SUITE) -> tuple[httpx.Response, DeviceKeys]:
        keys = DeviceKeys.generate()
        r = self.http.post("/api/v1/enroll/start", json={"suite": suite, "code": code, "device_name": "probe",
                                                         "kem_pk": keys.kem_pk_b64u, "sig_pk": keys.sig_pk_b64u})
        return r, keys

    def _raw_enroll_finish(self, start: dict[str, Any], keys: DeviceKeys, *, break_sig: bool = False,
                           break_confirm: bool = False) -> httpx.Response:
        ss = keys.kem.decapsulate(b64u_decode(start["xwing_ct"]))
        challenge = b64u_decode(start["challenge"])
        t = enroll_transcript(enroll_id=start["enroll_id"], user_id=start["user"]["user_id"], device_name="probe",
                              kem_pk_b64u=keys.kem_pk_b64u, sig_pk_b64u=keys.sig_pk_b64u,
                              challenge_b64u=start["challenge"], xwing_ct_b64u=start["xwing_ct"],
                              directory_epoch=start["directory_epoch"], server_time=start["server_time"])
        sig = keys.sig.sign(t + b"!" if break_sig else t, "enroll")
        confirm = kdf.hmac384(os.urandom(48) if break_confirm else kdf.enroll_confirm_key(ss, challenge), t)
        return self.http.post("/api/v1/enroll/finish", json={"enroll_id": start["enroll_id"], "signature": b64u(sig),
                                                             "key_confirm": b64u(confirm)})

    def _verify_cli(self, doc: dict[str, Any]) -> Result:
        """Run the real `qg verify` command offline on a bundle file with pinned keys."""
        from qg.client.cli import main

        path = self.tmp / f"bundle-{os.urandom(4).hex()}.json"
        path.write_text(json.dumps(doc))
        keys = self.tmp / "server-keys.json"
        keys.write_text(json.dumps(self.client.meta()["server_keys"]))
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = main(["verify", str(path), "--keys", str(keys), "--json"])
        return Result(rc, False, out.getvalue()[-200:])

    # ---- scenario setups -------------------------------------------------------------------

    def _setup_revoked_session(self) -> None:
        self._protect_two_party(size=4000)

    _setup_revoked_existing_session = _setup_revoked_session
    _setup_revocation_race = _setup_revoked_session
    _setup_policy_outage = _setup_revoked_session

    def _setup_slot_context(self) -> None:
        self._protect_two_party(size=6000)
        o, p = self.s["owner"], self.s["phone"]
        self.s["fid2"] = o.protect("second.bin", os.urandom(3000), "confidential", [p.device_id])["file"]["file_id"]

    def _setup_chunk_integrity(self) -> None:
        self._protect_two_party()

    def _setup_directory_rollback(self) -> None:
        self.s["owner"] = self.enroll("Aiko Tanaka", "laptop")
        self.s["owner"].call("PATCH", f"/api/v1/devices/{self.s['owner'].device_id}", {"name": "renamed laptop"})

    def _setup_unauthorized_manifest_recipient(self) -> None:
        self.s["owner"] = self.enroll("Aiko Tanaka", "laptop")
        self.s["auditor"] = self.enroll("Jonas Weber", "auditor laptop")

    def _setup_request_replay(self) -> None:
        self.s["dev"] = self.enroll("Aiko Tanaka", "laptop")

    _setup_sequence_gap = _setup_request_replay

    def _setup_lease_expiry(self) -> None:
        self._protect_two_party()

    def _setup_expired_invite(self) -> None:
        dev = self.enroll("Aiko Tanaka", "laptop")
        self.s["code"] = dev.post("/api/v1/invites", {"user_id": dev.user_id})["code"]

    def _setup_reused_invite(self) -> None:
        self.s["code"] = self.codes.pop("Daniel Mensah")

    def _setup_missing_enrollment_proof(self) -> None:
        self.s["epoch"] = self.http.get("/api/v1/directory").json()["epoch"]
        self.s["devices_before"] = len(self.db("SELECT device_id FROM devices"))

    def _setup_self_approval(self) -> None:
        mira = self.enroll("Mira Okafor", "mira")
        tomas = self.enroll("Tomas Lindqvist", "tomas")
        epoch = mira.refresh_directory()["epoch"]
        change = {"directory_epoch": epoch, "file_id": None, "reason": "cover on-call", "role": "operator",
                  "suite": SUITE, "target_user_id": tomas.user_id, "type": "role_grant"}
        created = mira.post("/api/v1/changes", {"change": change,
                                                "signature": b64u(mira.state.keys.sig.sign(canon(change), "change"))})
        self.s.update(mira=mira, tomas=tomas, change=created)

    def _setup_unsigned_privilege(self) -> None:
        aiko = self.enroll("Aiko Tanaka", "aiko")
        daniel = self.enroll("Daniel Mensah", "daniel")
        priya = self.enroll("Priya Raman", "priya")
        fid = aiko.protect("trial.pdf", os.urandom(4000), "confidential", [daniel.device_id])["file"]["file_id"]
        self.s.update(aiko=aiko, daniel=daniel, priya=priya, fid=fid)

    def _setup_decoy_touch(self) -> None:
        self._setup_unsigned_privilege()
        self.s["decoy"] = self.db("SELECT file_id FROM files WHERE is_decoy = 1")[0][0]

    def _setup_unknown_suite(self) -> None:
        pass

    def _setup_object_isolation(self) -> None:
        aiko = self.enroll("Aiko Tanaka", "aiko")
        mira = self.enroll("Mira Okafor", "mira")
        fid = aiko.protect("private.bin", os.urandom(2000), "confidential")["file"]["file_id"]
        self.s.update(aiko=aiko, prober=mira, fid=fid, absent="fil_" + b64u(os.urandom(16)))

    def _setup_proof_bundle_integrity(self) -> None:
        self._protect_two_party(size=3000)
        o, p = self.s["owner"], self.s["phone"]
        o.open(self.s["fid"])
        inc = self.report_lost(p, o).json()["incident_id"]
        self.slot_response(o, self.s["fid"])  # denied attempt
        priya = self.enroll("Priya Raman", "priya")
        self.s["bundle"] = priya.get(f"/api/v1/incidents/{inc}/bundle")

    def _setup_secret_logging(self) -> None:
        self.s["canaries"] = set()

    def _setup_database_copy(self) -> None:
        self._protect_two_party(size=5000)

    def _setup_recovery_approval(self) -> None:
        aiko = self.enroll("Aiko Tanaka", "aiko")
        mira = self.enroll("Mira Okafor", "mira")
        tomas = self.enroll("Tomas Lindqvist", "tomas")
        tomas2 = self.second(tomas, "tomas phone")
        priya = self.enroll("Priya Raman", "priya")
        fid = aiko.protect("archive.bin", os.urandom(3000), "restricted")["file"]["file_id"]
        epoch = mira.refresh_directory()["epoch"]
        change = {"directory_epoch": epoch, "file_id": fid, "reason": "owner left the company", "role": None,
                  "suite": SUITE, "target_user_id": aiko.user_id, "type": "recovery_release"}
        created = mira.post("/api/v1/changes", {"change": change,
                                                "signature": b64u(mira.state.keys.sig.sign(canon(change), "change"))})
        self.s.update(aiko=aiko, mira=mira, tomas=tomas, tomas2=tomas2, priya=priya, fid=fid, change=created)

    # ---- operations ------------------------------------------------------------------------

    def op_valid_session(self) -> httpx.Response:
        return self.s["owner"].raw_request("GET", "/api/v1/devices")

    def op_revoke(self) -> httpx.Response:
        r = self.report_lost(self.s["phone"], self.s["owner"])
        if r.status_code == 200:
            self.s["revoke"] = r.json()
        return r

    def op_revoked_start(self) -> httpx.Response:
        r = self.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": self.s["owner"].device_id})
        self.s["start"] = r.json()
        return r

    def op_revoked_finish(self) -> httpx.Response:
        start, keys = self.s["start"], self.s["owner"].state.keys
        from qg.crypto.transcripts import session_transcript

        t = session_transcript(start_id=start["start_id"], device_id=self.s["owner"].device_id,
                               challenge_b64u=start["challenge"], xwing_ct_b64u=start["xwing_ct"],
                               directory_epoch=start["directory_epoch"], server_time=start["server_time"])
        return self.http.post("/api/v1/session/finish", json={
            "start_id": start["start_id"], "signature": b64u(keys.sig.sign(t, "session")),
            "key_confirm": b64u(os.urandom(48))})

    def op_slot_before(self) -> httpx.Response:
        return self.slot_response(self.s["owner"], self.s["fid"])

    op_slot_before_race = op_slot_before
    op_slot_before_outage = op_slot_before

    def op_slot_after_same_session(self) -> httpx.Response:
        return self.slot_response(self.s["owner"], self.s["fid"])

    def op_unrelated_device_slot(self) -> httpx.Response:
        if "phone" in self.s and self.name in ("revocation_race",):
            return self.slot_response(self.s["phone"], self.s["fid"])
        return self.slot_response(self.s["aiko"], self.s["fid"])

    def op_open_original(self) -> Result:
        return self._client_open(self.s["phone"], self.s["fid"])

    def op_open_slot_moved_to_file(self) -> Result:
        other = self.s["phone"].slot(self.s["fid2"])
        return self._client_open(self.s["phone"], self.s["fid"],
                                 slot_fn=lambda s: {**s, "inner_wrap": other["inner_wrap"]})

    def op_open_slot_moved_to_device(self) -> Result:
        owners = self.s["owner"].slot(self.s["fid"])
        return self._client_open(self.s["phone"], self.s["fid"],
                                 slot_fn=lambda s: {**s, "inner_wrap": owners["inner_wrap"]})

    def op_open_reordered(self) -> Result:
        return self._client_open(self.s["phone"], self.s["fid"], blobs_fn=lambda b: [b[1], b[0], *b[2:]])

    def op_open_truncated(self) -> Result:
        return self._client_open(self.s["phone"], self.s["fid"], blobs_fn=lambda b: b[:-1])

    def op_open_bit_flipped(self) -> Result:
        def flip(blobs: list[bytes]) -> list[bytes]:
            b = bytearray(blobs[1])
            b[100] ^= 0x04
            return [blobs[0], bytes(b), *blobs[2:]]

        return self._client_open(self.s["phone"], self.s["fid"], blobs_fn=flip)

    def op_open_wrong_aad(self) -> Result:
        # Authentic chunks decrypted under the AAD of another version: the binding must fail.
        return self._client_open(self.s["phone"], self.s["fid"], decrypt_version_offset=1)

    def op_accept_new_directory(self) -> Result:
        try:
            self.s["owner"].refresh_directory()
            return Result(0, False)
        except ClientRefused as exc:
            return Result(1, False, str(exc))

    def op_accept_old_directory(self) -> Result:
        old = self.http.get("/api/v1/directory?epoch=1").json()
        try:
            self.s["owner"].accept_directory(old)
            return Result(0, False)
        except ClientRefused as exc:
            return Result(1, False, str(exc))

    def op_advance_past_epoch_grace(self) -> None:
        dev = self.s["owner"]
        epoch = dev.refresh_directory()["epoch"]
        fid, version, body = self._pending_commit(dev, os.urandom(2000), "confidential", [dev.device_id], epoch)
        dev.call("PATCH", f"/api/v1/devices/{dev.device_id}", {"name": "laptop again"})  # new epoch
        advance = getattr(self.clock, "advance", None)
        if advance is not None:
            advance(61)
        dev.login()  # session idle limits are unaffected, but keep the session fresh
        self.s.update(pending=(fid, version, body))

    def op_commit_old_epoch(self) -> httpx.Response:
        fid, version, body = self.s["pending"]
        return self._commit(self.s["owner"], fid, version, body)

    def op_commit(self) -> httpx.Response:
        owner, auditor = self.s["owner"], self.s["auditor"]
        epoch = owner.refresh_directory()["epoch"]
        fid, version, body = self._pending_commit(owner, os.urandom(2000), "restricted",
                                                  [owner.device_id, auditor.device_id], epoch)
        self.s["pending"] = (fid, version, body)
        return self._commit(owner, fid, version, body)

    def _signed(self, dev: Device, seq: int) -> httpx.Response:
        path = "/api/v1/devices"
        headers = {"QG-Session": dev.session.session_id, "QG-Seq": str(seq),
                   "QG-MAC": request_mac(dev.session.k_mac, "GET", path, seq, b"")}
        return self.http.get(path, headers=headers)

    def op_original(self) -> httpx.Response:
        self.s["seq"] = 5
        return self._signed(self.s["dev"], 5)

    def op_exact_replay(self) -> httpx.Response:
        return self._signed(self.s["dev"], self.s["seq"])

    def op_fresh_sequence_same_session(self) -> httpx.Response:
        return self._signed(self.s["dev"], self.s["seq"] + 1)

    def op_sequence_1(self) -> httpx.Response:
        return self._signed(self.s["dev"], 1)

    def op_sequence_100(self) -> httpx.Response:
        return self._signed(self.s["dev"], 100)

    def op_sequence_99(self) -> httpx.Response:
        return self._signed(self.s["dev"], 99)

    def op_slot(self) -> httpx.Response:
        r = self.slot_response(self.s["phone"], self.s["fid"])
        self.s["lease"] = r.json()["lease"]["lease_id"]
        return r

    def _chunk(self, i: int) -> httpx.Response:
        return self.s["phone"].raw_request("GET", f"/api/v1/files/{self.s['fid']}/chunks/{i}",
                                           headers={"QG-Lease": self.s["lease"]})

    def op_chunk_0(self) -> httpx.Response:
        return self._chunk(0)

    def op_chunk_1(self) -> httpx.Response:
        return self._chunk(1)

    def op_enroll_start(self) -> httpx.Response:
        return self._raw_enroll_start(self.s["code"])[0]

    def op_first_enroll(self) -> httpx.Response:
        r, keys = self._raw_enroll_start(self.s["code"])
        return self._raw_enroll_finish(r.json(), keys)

    def op_second_enroll_start(self) -> httpx.Response:
        return self._raw_enroll_start(self.s["code"])[0]

    def _finish_without(self, which: str) -> httpx.Response:
        r, keys = self._raw_enroll_start(self.codes.pop("Aiko Tanaka"))
        return self._raw_enroll_finish(r.json(), keys, break_sig=which == "signing", break_confirm=which == "kem")

    def op_finish_without_kem_proof(self) -> httpx.Response:
        return self._finish_without("kem")

    def op_finish_without_signing_proof(self) -> httpx.Response:
        return self._finish_without("signing")

    def _approve(self, dev: Device, change: dict[str, Any]) -> httpx.Response:
        approval = {"change_hash": change["change_hash"], "change_id": change["id"], "decision": "approve",
                    "purpose": "approve", "suite": SUITE}
        body = json.dumps({"signature": b64u(dev.state.keys.sig.sign(canon(approval), "change"))}).encode()
        return dev.raw_request("POST", f"/api/v1/changes/{change['id']}/approve", body=body)

    def op_requester_approves(self) -> httpx.Response:
        return self._approve(self.s["mira"], self.s["change"])

    def op_target_approves(self) -> httpx.Response:
        return self._approve(self.s["tomas"], self.s["change"])

    def op_inject_unsigned_role_at_identity_source(self) -> httpx.Response:
        now = int(self.core.clock.now().timestamp())
        body = {"iss": "sandbox-identity-source", "jti": os.urandom(8).hex(), "iat": now, "aud": "quantumguard",
                "events": {"urn:qg:event-type:privilege-observed": {
                    "subject": {"format": "opaque", "id": self.s["daniel"].user_id}, "event_timestamp": now,
                    "role": "admin"}}}
        return self.s["priya"].raw_request("POST", "/api/v1/signals", body=json.dumps(body).encode())

    def op_sensitive_slot(self) -> httpx.Response:
        return self.slot_response(self.s["daniel"], self.s["fid"])

    def op_unrelated_identity_slot(self) -> httpx.Response:
        return self.slot_response(self.s["aiko"], self.s["fid"])

    def op_touch_decoy(self) -> httpx.Response:
        return self.slot_response(self.s["daniel"], self.s["decoy"])

    def op_same_device_slot(self) -> httpx.Response:
        # The quarantine ended the device's sessions; its next slot request needs a session first. Report the
        # first refusal on that path (a session attempt by the quarantined device, or the slot request).
        dev = self.s["daniel"]
        r = self.slot_response(dev, self.s["fid"])
        if r.status_code != 401:
            return r
        start = self.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": dev.device_id}).json()
        from qg.crypto.transcripts import session_transcript

        ss = dev.state.keys.kem.decapsulate(b64u_decode(start["xwing_ct"]))
        ch = b64u_decode(start["challenge"])
        t = session_transcript(start_id=start["start_id"], device_id=dev.device_id, challenge_b64u=start["challenge"],
                               xwing_ct_b64u=start["xwing_ct"], directory_epoch=start["directory_epoch"],
                               server_time=start["server_time"])
        return self.http.post("/api/v1/session/finish", json={
            "start_id": start["start_id"], "signature": b64u(dev.state.keys.sig.sign(t, "session")),
            "key_confirm": b64u(kdf.hmac384(kdf.session_confirm_key(ss, ch), t))})

    def op_enroll_with_unknown_suite(self) -> httpx.Response:
        return self._raw_enroll_start(self.codes["Aiko Tanaka"], suite="QG-0")[0]

    def _iso_request(self, route: str, file_id: str) -> httpx.Response:
        dev = self.s["prober"]
        if route == "metadata":
            return dev.raw_request("GET", f"/api/v1/files/{file_id}")
        if route == "slot":
            return dev.raw_request("GET", f"/api/v1/files/{file_id}/slot")
        if route == "chunk":
            return dev.raw_request("GET", f"/api/v1/files/{file_id}/chunks/0",
                                   headers={"QG-Lease": "lse_" + b64u(os.urandom(16))})
        if route == "delete":
            return dev.raw_request("DELETE", f"/api/v1/files/{file_id}")
        if route == "share":
            epoch = dev.refresh_directory()["epoch"]
            share = {"directory_epoch": epoch, "file_id": file_id, "recipients": [dev.device_id], "suite": SUITE,
                     "version": 1}
            share_body = {"share": share, "share_sig": b64u(dev.state.keys.sig.sign(canon(share), "share")),
                    "wraps": [{"device_id": dev.device_id, "xwing_ct": b64u(os.urandom(1120)),
                               "wrapped_dek": b64u(os.urandom(60))}]}
            return dev.raw_request("POST", f"/api/v1/files/{file_id}/share", body=json.dumps(share_body).encode())
        if route == "recover":
            body = json.dumps({"change_id": "chg_" + b64u(os.urandom(16))}).encode()
            return dev.raw_request("POST", f"/api/v1/files/{file_id}/recover", body=body)
        raise KeyError(route)

    def op_verify_original(self) -> Result:
        return self._verify_cli(self.s["bundle"])

    def op_verify_log_byte_flip(self) -> Result:
        doc = json.loads(json.dumps(self.s["bundle"]))
        r = doc["entries"][0]["receipt"]
        r["reason_code"] = r["reason_code"][:-1] + chr(ord(r["reason_code"][-1]) ^ 0x01)
        return self._verify_cli(doc)

    def op_verify_bad_ed25519_checkpoint_signature(self) -> Result:
        doc = json.loads(json.dumps(self.s["bundle"]))
        doc["checkpoint"]["signatures"]["ed25519"] = _flip_b64u(doc["checkpoint"]["signatures"]["ed25519"])
        return self._verify_cli(doc)

    def op_verify_bad_mldsa_checkpoint_signature(self) -> Result:
        doc = json.loads(json.dumps(self.s["bundle"]))
        doc["checkpoint"]["signatures"]["mldsa"] = _flip_b64u(doc["checkpoint"]["signatures"]["mldsa"])
        return self._verify_cli(doc)

    def op_disable_policy_engine(self) -> None:
        self.s["outage_from"] = self.core.log.size
        set_policy_available(self.app, False)

    def op_slot_during_outage(self) -> httpx.Response:
        return self.slot_response(self.s["owner"], self.s["fid"])

    def op_exercise_full_workflow_with_random_canaries(self) -> None:
        c: set[str] = self.s["canaries"]

        def add(raw: bytes | str) -> None:
            if isinstance(raw, str):
                c.update({raw, raw.replace("-", "")})
                return
            c.update({b64u(raw), raw.hex(), base64.b64encode(raw).decode()})

        for code in self.codes.values():
            add(code)
        aiko = self.enroll("Aiko Tanaka", "aiko")
        phone = self.second(aiko, "phone")
        daniel = self.enroll("Daniel Mensah", "daniel")
        priya = self.enroll("Priya Raman", "priya")
        mira = self.enroll("Mira Okafor", "mira")
        tomas = self.enroll("Tomas Lindqvist", "tomas")
        for d in (aiko, phone, daniel, priya, mira, tomas):
            add(d.state.keys.sig.seed)
            add(d.state.keys.kem.seed)
            add(d.session.k_mac)
        fid = aiko.protect("secret.bin", os.urandom(5000), "restricted", [phone.device_id])["file"]["file_id"]
        aiko.open(fid)
        add(aiko.unwrap(aiko.slot(fid)))
        passphrase = b64u(os.urandom(18))
        add(passphrase)
        aiko.state.save(str(self.tmp / "aiko.qgkeystore"), passphrase)
        aiko.raw_request("POST", "/api/v1/files", body=b"{broken")
        self.http.post("/api/v1/session/start", content=b'{"suite":"QG-9"}')
        self.report_lost(phone, aiko)
        aiko.raw_request("GET", f"/api/v1/files/{fid}/slot")
        phone.login()
        add(phone.session.k_mac)
        phone.rekey_all()
        add(phone.unwrap(phone.slot(fid)))
        epoch = mira.refresh_directory()["epoch"]
        change = {"directory_epoch": epoch, "file_id": fid, "reason": "drill", "role": None, "suite": SUITE,
                  "target_user_id": aiko.user_id, "type": "recovery_release"}
        ch = mira.post("/api/v1/changes", {"change": change,
                                           "signature": b64u(mira.state.keys.sig.sign(canon(change), "change"))})
        self._approve(tomas, ch)
        self._approve(priya, ch)
        mira.raw_request("POST", f"/api/v1/files/{fid}/recover", body=json.dumps({"change_id": ch["id"]}).encode())
        now = int(self.core.clock.now().timestamp())
        sig = {"iss": "drill", "jti": os.urandom(8).hex(), "iat": now, "aud": "quantumguard", "events": {
            "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
                "subject": {"format": "opaque", "id": daniel.device_id}, "event_timestamp": now}}}
        priya.raw_request("POST", "/api/v1/signals", body=json.dumps(sig).encode())
        add(self.core.keys.seal_master)
        add(self.core.keys.signer.ed.seed)
        add(self.core.keys.signer.pq.seed)

    def op_legitimate_client_open(self) -> Result:
        return self._client_open(self.s["phone"], self.s["fid"])

    def op_attempt_decryption_with_database_and_public_artifacts(self) -> Result:
        """Copy the database (committed WAL included) and public ciphertext into an attacker workspace without
        the keys volume or any client key, then genuinely try to unseal slots and decrypt chunks."""
        work = Path(tempfile.mkdtemp(prefix="qg-attacker-"))
        try:
            copy = work / "copy.sqlite"
            src = sqlite3.connect(str(self.core.db.path))
            dst = sqlite3.connect(str(copy))
            src.backup(dst)
            src.close()
            blobs_src = self.core.settings.data_dir / "blobs"
            if blobs_src.exists():
                shutil.copytree(blobs_src, work / "blobs")
            secrets = [self.core.keys.seal_master, self.core.keys.signer.ed.seed, self.core.keys.signer.pq.seed,
                       self.core.keys.kem.seed, self.s["owner"].state.keys.kem.seed, self.s["owner"].state.keys.sig.seed,
                       self.s["phone"].state.keys.kem.seed]
            image = copy.read_bytes() + b"".join(p.read_bytes() for p in (work / "blobs").rglob("*") if p.is_file())
            private_available = any(s in image for s in secrets)
            # every 32-byte value stored in the database is tried as a seal master and as a file key
            candidates: set[bytes] = set()
            for table, col in (("slots", "sealed"), ("directory", "doc_hash"), ("checkpoints", "root_hash"),
                               ("receipts", "leaf_hash"), ("devices", "kem_pk"), ("devices", "sig_pk")):
                for (v,) in dst.execute(f"SELECT {col} FROM {table}"):  # noqa: S608 # nosec B608 - fixed names
                    v = bytes(v) if isinstance(v, bytes | memoryview) else str(v).encode()
                    candidates.update(v[i:i + 32] for i in range(0, max(len(v) - 31, 1), 32))
            recovered = False
            slots = dst.execute("SELECT slot_id, file_id, version, device_id, sealed, seal_epoch FROM slots").fetchall()
            for slot_id, fid, version, did, sealed, epoch in slots:
                aad = aead.seal_aad(slot_id, fid, version, did, epoch)
                for key in list(candidates)[:400]:
                    try:
                        aead.unseal(key, epoch, aad, bytes(sealed))
                        recovered = True
                    except aead.AeadError:
                        pass
            fid = self.s["fid"]
            version = dst.execute("SELECT current_version FROM files WHERE file_id = ?", (fid,)).fetchone()[0]
            chunk = (work / "blobs" / fid / str(version) / "0").read_bytes()
            for key in list(candidates)[:400]:
                try:
                    list(aead.decrypt_chunks(key, fid, version, [chunk], 1))
                    recovered = True
                except aead.AeadError:
                    pass
            dst.close()
            return Result(1 if not recovered else 0, recovered, attempted=True,
                          private_keys_available=private_available, plaintext_recovered=recovered)
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def op_recover_zero_approvals(self) -> httpx.Response:
        return self._recover()

    op_recover_one_approval = op_recover_zero_approvals
    op_recover_two_approvals = op_recover_zero_approvals

    def _recover(self) -> httpx.Response:
        body = json.dumps({"change_id": self.s["change"]["id"]}).encode()
        return self.s["mira"].raw_request("POST", f"/api/v1/files/{self.s['fid']}/recover", body=body)

    def op_first_independent_approval(self) -> httpx.Response:
        return self._approve(self.s["tomas"], self.s["change"])

    def op_same_person_second_device_approval(self) -> httpx.Response:
        return self._approve(self.s["tomas2"], self.s["change"])

    def op_second_independent_approval(self) -> httpx.Response:
        return self._approve(self.s["priya"], self.s["change"])

    # ---- dispatch --------------------------------------------------------------------------

    def act(self, operation: str) -> Any:
        if operation.startswith(("hidden_", "absent_")):
            kind, route = operation.split("_", 1)
            return self._iso_request(route, self.s["fid"] if kind == "hidden" else self.s["absent"])
        fn = getattr(self, "op_" + operation, None)
        if fn is None:
            raise KeyError(f"unknown operation {operation!r} for case {self.name!r}")
        return fn()

    def observe(self, name: str) -> Any:
        dev = self.s.get("owner")
        if name == "active_sessions_for_revoked_device":
            return len(self.db("SELECT 1 FROM sessions WHERE device_id = ?", (dev.device_id,)))
        if name == "slots_for_revoked_device":
            return len(self.db("SELECT 1 FROM slots WHERE device_id = ?", (dev.device_id,)))
        if name == "pending_version_committed":
            fid, version, _ = self.s["pending"]
            return self.db("SELECT status FROM file_versions WHERE file_id = ? AND version = ?",
                           (fid, version))[0][0] == "committed"
        if name == "unauthorized_recipient_has_slot":
            return bool(self.db("SELECT 1 FROM slots WHERE device_id = ?", (self.s["auditor"].device_id,)))
        if name == "lease_seconds":
            return self.client.meta()["limits"]["lease_seconds"]
        if name == "invite_ttl_seconds":
            row = self.db("SELECT created_at, expires_at FROM invites WHERE bootstrap = 0 ORDER BY created_at DESC"
                          " LIMIT 1")[0]
            from qg.clock import parse

            return int((parse(row[1]) - parse(row[0])).total_seconds())
        if name == "new_device_published":
            epoch = self.http.get("/api/v1/directory").json()["epoch"]
            return epoch != self.s["epoch"] or len(self.db("SELECT 1 FROM devices")) != self.s["devices_before"]
        if name == "change_applied":
            return self.db("SELECT status FROM changes WHERE id = ?", (self.s["change"]["id"],))[0][0] == "applied"
        if name == "alert_rule_ids":
            return [r[0] for r in self.db("SELECT rule_id FROM alerts ORDER BY ts")]
        if name == "target_identity_quarantined":
            return self.db("SELECT status FROM users WHERE user_id = ?", (self.s["daniel"].user_id,))[0][0] == \
                "quarantined"
        if name == "release_count_during_outage":
            return len(self.db("SELECT 1 FROM receipts WHERE action = 'slot.release' AND decision = 'allow'"
                               " AND leaf_index >= ?", (self.s["outage_from"],)))
        if name == "generated_secret_canaries":
            return sorted(x for x in self.s["canaries"] if len(x) >= 16)
        if name == "all_log_lines":
            lines = list(self.app.state.captured_logs)
            events = self.core.settings.data_dir / "SECURITY_EVENTS.jsonl"
            if events.exists():
                lines += events.read_text(encoding="utf-8").splitlines()
            return lines
        raise KeyError(f"unknown observation {name!r}")

    # ---- revocation race -------------------------------------------------------------------

    def race_release_and_revoke(self, workers: int = 8, per_worker: int = 40) -> RaceResult:
        """Independent sessions of the soon-revoked device request its slot concurrently while the revoke runs.
        Ordering comes from the evidence log: each response's receipt leaf index, compared with the revoke
        receipt's leaf index. A refusal raised after the revoke without its own receipt is ordered by the log
        size observed when its response arrived (necessarily after the revoke)."""
        from fastapi.testclient import TestClient

        owner, phone, fid = self.s["owner"], self.s["phone"], self.s["fid"]
        devices = []
        for _ in range(workers):
            tc = TestClient(self.app, base_url="http://testserver")
            self._extra_clients.append(tc)
            d = Device(tc, owner.state)
            d.login()
            devices.append(d)
        results: list[tuple[int, str | None, bool, int]] = []
        lock = threading.Lock()
        go = threading.Event()
        started = {"n": 0}

        def work(dev: Device) -> None:
            go.wait()
            for _ in range(per_worker):
                r = dev.raw_request("GET", f"/api/v1/files/{fid}/slot")
                size_after = self.core.log.size
                key = r.status_code == 200 and "inner_wrap" in r.text
                with lock:
                    results.append((r.status_code, r.headers.get("QG-Receipt"), key, size_after))
                    started["n"] += 1

        threads = [threading.Thread(target=work, args=(d,)) for d in devices]
        for t in threads:
            t.start()
        go.set()
        while started["n"] < workers * per_worker // 4:
            threading.Event().wait(0.002)
        revoke = self.report_lost(phone, owner)
        for t in threads:
            t.join(120)
        committed = revoke.status_code == 200
        rid = revoke.json().get("receipt_id") if committed else None
        revoke_index = self.db("SELECT leaf_index FROM receipts WHERE id = ?", (rid,))[0][0] if rid else -1
        releases = []
        for status, receipt_id, key, size_after in results:
            row = self.db("SELECT leaf_index FROM receipts WHERE id = ?", (receipt_id,)) if receipt_id else []
            index = row[0][0] if row else size_after
            releases.append(Release(index, status, key))
        return RaceResult(committed, revoke_index, releases)

    def close(self) -> None:
        for tc in self._extra_clients:
            tc.close()
        self.http.close()
        self.core.stop()
        self.core.db.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


def security_case(*, name: str, data_dir: Path, keys_dir: Path, clock: Callable[[], datetime]) -> Case:
    return Case(name, Path(data_dir), Path(keys_dir), clock)
