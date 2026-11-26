"""Build-plan 13.2: one negative test per claim (THREAT_MODEL.md section 5).

Each test drives real enrolled devices of the seeded synthetic organisation through the production app with
the `qg` client library. A test passes when the product refuses the bad thing in the way spec/API.md
specifies and releases nothing. Observations of server state are read-only queries; the only writes outside
the API are test-owned artifact corruption and fault injection, each named in its test.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import threading
from pathlib import Path

import pytest

from qg.client.api import ApiError, ClientRefused
from qg.client.device import DeviceKeys
from qg.crypto import aead, kdf
from qg.crypto.encoding import b64u, b64u_decode, canon
from qg.crypto.suite import SUITE
from qg.crypto.transcripts import enroll_transcript
from qg.ids import new_id
from qg.log.verify import verify_bundle
from qgsec import (
    absent_id,
    blob_dir,
    chunks_with_lease,
    commit_body,
    count,
    deny,
    encodings,
    new_file,
    protect_raw,
    q,
    send_commit,
    upload_chunks,
)

MULTI = 2 * 1_048_576 + 4321  # three chunks, the last one short


def _pair(env):
    """Aiko's laptop (the device that will be lost) and her phone (the one that reports it)."""
    laptop = env.device("Aiko Tanaka")
    phone = env.second_device("Aiko Tanaka", "Aiko's phone")
    return laptop, phone


def _report_lost(env, reporter, lost):
    return reporter.post(f"/api/v1/devices/{lost.device_id}/report-lost", {"lost_at": env.clock.iso()})


# ---- revocation --------------------------------------------------------------------------------


def test_revoked_device_cannot_start_session(env):
    laptop, phone = _pair(env)
    _report_lost(env, phone, laptop)

    start = env.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": laptop.device_id})
    unknown = env.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": new_id("dev")})
    assert start.status_code == unknown.status_code == 200
    assert set(start.json()) == set(unknown.json())  # same shape: no oracle at /session/start
    assert len(b64u_decode(start.json()["xwing_ct"])) == 1120

    sessions_before = count(env, "SELECT COUNT(*) FROM sessions WHERE device_id = ?", (laptop.device_id,))
    with pytest.raises(ApiError) as ei:
        laptop.login()  # the real client, holding the real private keys
    assert (ei.value.status, ei.value.code, ei.value.reason) == (403, "QG_DENY_REVOKED", "device_revoked")
    assert ei.value.receipt_id
    assert count(env, "SELECT COUNT(*) FROM sessions WHERE device_id = ?", (laptop.device_id,)) == sessions_before == 0


def test_revoked_devices_existing_session_dies_in_same_transaction(env, monkeypatch):
    laptop, phone = _pair(env)
    fid = laptop.protect("plates.csv", os.urandom(3000), "confidential", [phone.device_id])["file"]["file_id"]
    assert laptop.open(fid)
    sid = laptop.session.session_id
    epoch_before = env.http.get("/api/v1/directory").json()["epoch"]

    # Fault injection: the revocation fails after it has deleted sessions and slots but before it commits.
    # Everything must roll back together; nothing half-applied may survive.
    def boom(*a, **kw):
        raise RuntimeError("injected fault inside the revoke transaction")

    monkeypatch.setattr(env.core.log, "checkpoint", boom)
    with pytest.raises(RuntimeError):
        _report_lost(env, phone, laptop)
    monkeypatch.undo()
    assert q(env, "SELECT status FROM devices WHERE device_id = ?", (laptop.device_id,))[0][0] == "active"
    assert count(env, "SELECT COUNT(*) FROM sessions WHERE session_id = ?", (sid,)) == 1
    assert count(env, "SELECT COUNT(*) FROM slots WHERE device_id = ?", (laptop.device_id,)) == 1
    assert count(env, "SELECT COUNT(*) FROM incidents") == 0
    assert env.http.get("/api/v1/directory").json()["epoch"] == epoch_before

    rr = _report_lost(env, phone, laptop)
    assert rr["sessions_ended"] == 1 and rr["slots_deleted"] == 1
    r = laptop.raw_request("GET", f"/api/v1/files/{fid}/slot")
    deny(r, 403, "QG_DENY_REVOKED", "device_revoked")
    assert count(env, "SELECT COUNT(*) FROM sessions WHERE device_id = ?", (laptop.device_id,)) == 0
    assert count(env, "SELECT COUNT(*) FROM slots WHERE device_id = ?", (laptop.device_id,)) == 0
    assert count(env, "SELECT COUNT(*) FROM leases WHERE device_id = ? AND cancelled = 0", (laptop.device_id,)) == 0
    assert env.core.secrets.mac(sid) is None  # the MAC key is gone from memory too
    # Session deletion and the revocation are one commit: the session ended at the revocation instant.
    ended = q(env, "SELECT ended_at, reason FROM ended_sessions WHERE session_id = ?", (sid,))[0]
    inc = q(env, "SELECT reported_at FROM incidents WHERE id = ?", (rr["incident_id"],))[0]
    assert ended["reason"] == "revoked" and ended["ended_at"] == inc["reported_at"]
    assert phone.open(fid)  # the remaining device is unaffected


# ---- binding of slots, chunks and wraps ---------------------------------------------------------


@pytest.mark.parametrize("target", ["file", "device"])
def test_slot_moved_to_another_context_fails(env, target):
    laptop, phone = _pair(env)
    data_a, data_b = os.urandom(2000), os.urandom(2000)
    fa = laptop.protect("a.bin", data_a, "confidential", [phone.device_id])["file"]["file_id"]
    fb = laptop.protect("b.bin", data_b, "confidential", [phone.device_id])["file"]["file_id"]
    assert laptop.open(fa) == data_a

    # Client side: the inner wrap of another file (or of another device) inside an otherwise valid slot.
    slot = laptop.slot(fa)
    donor = laptop.slot(fb) if target == "file" else phone.slot(fa)
    with pytest.raises(ClientRefused):
        laptop.open_slot({**slot, "inner_wrap": donor["inner_wrap"]})

    # Server side: the sealed blob copied into another slot row (another file, or another device's slot).
    src_file, dst_dev = (fb, laptop.device_id) if target == "file" else (fa, phone.device_id)
    src_dev = laptop.device_id
    sealed = q(env, "SELECT sealed FROM slots WHERE file_id = ? AND device_id = ?", (src_file, src_dev))[0][0]
    victim_file = fa
    with env.core.db.tx() as conn:  # artifact corruption (test-owned)
        conn.execute("UPDATE slots SET sealed = ? WHERE file_id = ? AND device_id = ?", (sealed, victim_file, dst_dev))
    victim = laptop if target == "file" else phone
    r = victim.raw_request("GET", f"/api/v1/files/{victim_file}/slot")
    deny(r, 503, "QG_UNAVAILABLE_FAIL_CLOSED", "seal_integrity")
    assert count(env, "SELECT COUNT(*) FROM leases WHERE file_id = ? AND device_id = ?", (victim_file, dst_dev)) == (
        1 if target == "device" else 2)  # only the leases of the earlier legitimate opens


def _three_chunk_file(env):
    laptop = env.device("Aiko Tanaka")
    data = os.urandom(MULTI)
    fid = laptop.protect("scan.tiff", data, "restricted")["file"]["file_id"]
    slot = laptop.slot(fid)
    dek = laptop.unwrap(slot)
    blobs = chunks_with_lease(laptop, slot)
    assert len(blobs) == 3 and laptop.decrypt(slot, dek, blobs) == data
    return laptop, fid, slot, dek, blobs, data


@pytest.mark.parametrize("mutation", ["reordered", "truncated"])
def test_chunk_reordered_or_truncated_fails(env, mutation):
    laptop, fid, slot, dek, blobs, _ = _three_chunk_file(env)
    bad = [blobs[1], blobs[0], blobs[2]] if mutation == "reordered" else blobs[:2]
    with pytest.raises(ClientRefused):
        laptop.decrypt(slot, dek, bad)
    with pytest.raises(aead.AeadError):  # the AEAD layer alone, without the ciphertext hash check
        b"".join(aead.decrypt_chunks(dek, fid, slot["version"], bad, 3))
    # The same mutation applied to the server's stored blobs: the real open path refuses.
    d = blob_dir(env, fid, slot["version"])
    if mutation == "reordered":
        os.replace(d / "0", d / "tmp")
        os.replace(d / "1", d / "0")
        os.replace(d / "tmp", d / "1")
    else:
        (d / "2").write_bytes(blobs[1])  # the file now ends early: chunk 2 is a copy of chunk 1
    with pytest.raises((ClientRefused, ApiError)):
        laptop.open(fid)


def test_ciphertext_bit_flip_fails(env):
    laptop, fid, slot, dek, blobs, _ = _three_chunk_file(env)
    for chunk, pos in [(0, 3), (0, 12), (1, 500_000), (2, len(blobs[2]) - 1)]:  # nonce, first byte, body, tag
        bad = list(blobs)
        b = bytearray(bad[chunk])
        b[pos] ^= 0x01
        bad[chunk] = bytes(b)
        with pytest.raises(ClientRefused):
            laptop.decrypt(slot, dek, bad)
        with pytest.raises(aead.AeadError):
            b"".join(aead.decrypt_chunks(dek, fid, slot["version"], bad, 3))
    p = blob_dir(env, fid, slot["version"]) / "1"
    b = bytearray(p.read_bytes())
    b[1234] ^= 0x80
    p.write_bytes(bytes(b))
    with pytest.raises(ClientRefused):
        laptop.open(fid)


def test_wrong_aad_fails(env):
    laptop, fid, slot, dek, blobs, _ = _three_chunk_file(env)
    v = slot["version"]
    for wrong in [dict(file_id=new_id("fil"), version=v, chunk_count=3), dict(file_id=fid, version=v + 1, chunk_count=3),
                  dict(file_id=fid, version=v, chunk_count=4)]:  # chunk_count 4 moves the is_last flag
        with pytest.raises(aead.AeadError):
            b"".join(aead.decrypt_chunks(dek, wrong["file_id"], wrong["version"], blobs, wrong["chunk_count"]))
    good = aead.wrap_binding(fid, v, laptop.device_id, slot["wrap_epoch"])
    assert aead.unwrap_dek(laptop.state.keys.kem, slot["inner_wrap"], good) == dek
    for field, value in [("directory_epoch", slot["wrap_epoch"] + 1), ("version", v + 1), ("file_id", new_id("fil")),
                         ("device_id", new_id("dev")), ("suite", "QG-0")]:
        with pytest.raises(aead.AeadError):
            aead.unwrap_dek(laptop.state.keys.kem, slot["inner_wrap"], {**good, field: value})


# ---- directory epochs -----------------------------------------------------------------------------


def test_older_directory_rejected_by_client(env):
    laptop = env.device("Aiko Tanaka")
    old = laptop.refresh_directory()
    laptop.call("PATCH", f"/api/v1/devices/{laptop.device_id}", {"name": "renamed laptop"})  # publishes epoch + 1
    new = laptop.refresh_directory()
    assert new["epoch"] == old["epoch"] + 1
    served_old = env.http.get(f"/api/v1/directory?epoch={old['epoch']}").json()  # genuinely signed, just older
    with pytest.raises(ClientRefused):
        laptop.accept_directory(served_old)
    assert laptop.state.highest_epoch == new["epoch"]
    forged = json.loads(json.dumps(new))
    forged["epoch"] += 5
    with pytest.raises(ClientRefused):
        laptop.accept_directory(forged)  # a newer epoch without a valid dual signature
    assert laptop.state.highest_epoch == new["epoch"]


def test_older_directory_rejected_by_server(env):
    laptop, phone = _pair(env)
    tablet = env.second_device("Aiko Tanaka", "Aiko's tablet")

    # Case 1: an epoch superseded more than 60 seconds ago.
    data = os.urandom(1500)
    fid = new_file(laptop, "old-epoch.bin", data)
    dek, blobs = upload_chunks(laptop, fid, 1, data)
    old_epoch = laptop.refresh_directory()["epoch"]
    laptop.call("PATCH", f"/api/v1/devices/{laptop.device_id}", {"name": "renamed"})
    env.clock.advance(61)
    body = commit_body(env, laptop, fid, 1, dek, blobs, "confidential", [laptop.device_id], epoch=old_epoch)
    deny(send_commit(laptop, fid, 1, body), 409, "QG_STALE_EPOCH", "stale_epoch")
    assert q(env, "SELECT status FROM file_versions WHERE file_id = ?", (fid,))[0][0] == "pending"
    assert count(env, "SELECT COUNT(*) FROM slots WHERE file_id = ?", (fid,)) == 0

    # Case 2: inside the 60 s grace, but a device was revoked after that epoch.
    laptop.login()  # QG-R003 required a fresh session after the stale commit
    phone.login()
    fid2 = new_file(laptop, "pre-revocation.bin", data)
    dek2, blobs2 = upload_chunks(laptop, fid2, 1, data)
    pre = laptop.refresh_directory()["epoch"]
    _report_lost(env, phone, tablet)
    env.clock.advance(1)
    body2 = commit_body(env, laptop, fid2, 1, dek2, blobs2, "confidential", [laptop.device_id, phone.device_id],
                        epoch=pre)
    deny(send_commit(laptop, fid2, 1, body2), 409, "QG_STALE_EPOCH", "stale_epoch")
    assert count(env, "SELECT COUNT(*) FROM slots WHERE file_id = ?", (fid2,)) == 0


def test_manifest_naming_unauthorized_recipient_rejected(env):
    laptop, phone = _pair(env)
    jonas = env.device("Jonas Weber")  # auditor: may receive internal files only
    tablet = env.second_device("Aiko Tanaka", "Aiko's tablet")
    _report_lost(env, phone, tablet)

    for name, classification, recipient in [("payroll.xlsx", "confidential", jonas.device_id),
                                            ("notes.txt", "internal", tablet.device_id)]:  # a revoked device
        fid, r = protect_raw(env, laptop, name, os.urandom(900), classification, [laptop.device_id, recipient])
        err = deny(r, 403, "QG_DENY_POLICY", "recipient_not_allowed")
        assert err["receipt_id"]
        assert count(env, "SELECT COUNT(*) FROM slots WHERE file_id = ?", (fid,)) == 0
        assert q(env, "SELECT status FROM file_versions WHERE file_id = ?", (fid,))[0][0] == "pending"
        rc = env.core.log.receipt(err["receipt_id"])
        assert rc["decision"] == "deny" and rc["resource"] == fid


# ---- request MAC and sequence ---------------------------------------------------------------------


def test_replayed_request_rejected_and_session_ended(env):
    dev = env.device("Daniel Mensah")
    first = dev.raw_request("GET", "/api/v1/devices", seq=1)
    assert first.status_code == 200
    replay = env.http.get("/api/v1/devices", headers={k: first.request.headers[k]
                                                      for k in ("QG-Session", "QG-Seq", "QG-MAC")})
    deny(replay, 401, "QG_REPLAY", "replay")
    deny(dev.raw_request("GET", "/api/v1/devices", seq=2), 401, "QG_NO_SESSION")
    assert count(env, "SELECT COUNT(*) FROM sessions WHERE device_id = ?", (dev.device_id,)) == 0
    assert any(a["rule_id"] == "QG-R002" for a in env.alerts())


def test_sequence_gap_tolerated_but_regression_rejected(env):
    dev = env.device("Daniel Mensah")
    assert dev.raw_request("GET", "/api/v1/devices", seq=1).status_code == 200
    assert dev.raw_request("GET", "/api/v1/devices", seq=100).status_code == 200
    deny(dev.raw_request("GET", "/api/v1/devices", seq=99), 401, "QG_REPLAY", "replay")


# ---- leases ---------------------------------------------------------------------------------------


def test_expired_lease_stops_download_mid_file(env):
    laptop = env.device("Aiko Tanaka")
    fid = laptop.protect("scan.tiff", os.urandom(MULTI), "restricted")["file"]["file_id"]
    slot = laptop.slot(fid)
    lease = slot["lease"]["lease_id"]
    r0 = laptop.raw_request("GET", f"/api/v1/files/{fid}/chunks/0", headers={"QG-Lease": lease})
    assert r0.status_code == 200 and len(r0.content) == 1_048_576 + 28
    env.clock.advance(env.http.get("/api/v1/meta").json()["limits"]["lease_seconds"] + 1)
    r1 = laptop.raw_request("GET", f"/api/v1/files/{fid}/chunks/1", headers={"QG-Lease": lease})
    err = deny(r1, 403, "QG_LEASE_EXPIRED", "lease_expired")
    assert r1.headers["content-type"].startswith("application/json")
    assert env.core.log.receipt(err["receipt_id"])["decision"] == "deny"


# ---- enrolment ------------------------------------------------------------------------------------


def _start(env, code, keys=None, suite=SUITE):
    keys = keys or DeviceKeys.generate()
    r = env.http.post("/api/v1/enroll/start", json={"suite": suite, "code": code, "device_name": "probe",
                                                    "kem_pk": keys.kem_pk_b64u, "sig_pk": keys.sig_pk_b64u})
    return r, keys


def test_expired_invite_rejected(env):
    dev = env.device("Daniel Mensah")
    stale = dev.post("/api/v1/invites", {"user_id": dev.user_id})["code"]
    env.clock.advance(14 * 60)
    dev.login()  # the idle session expired meanwhile (600 s)
    fresh =dev.post("/api/v1/invites", {"user_id": dev.user_id})["code"]
    env.clock.advance(60 + 1)  # stale is now 15 min + 1 s old, fresh 61 s
    r, _ = _start(env, stale)
    err = deny(r, 400, "QG_INVALID_INPUT", "invite_invalid")
    assert env.core.log.receipt(err["receipt_id"])["action"] == "enroll"
    assert _start(env, fresh)[0].status_code == 200
    r, _ = _start(env, "K7QM-2XVD-9RTA-HB4N")  # unknown code: the same answer
    deny(r, 400, "QG_INVALID_INPUT", "invite_invalid")


def test_invite_reused_rejected(env):
    dev = env.device("Daniel Mensah")
    code = dev.post("/api/v1/invites", {"user_id": dev.user_id})["code"]
    devices_before = count(env, "SELECT COUNT(*) FROM devices")
    # Two enrolments started with one code, finished concurrently: exactly one device may result.
    starts = [_start(env, code) for _ in range(2)]
    assert all(r.status_code == 200 for r, _ in starts)
    meta = env.client.meta()
    outcomes = []

    def finish(i):
        r, keys = starts[i]
        try:
            env.client.finish_enroll(r.json(), keys, "probe", meta)
            outcomes.append("ok")
        except ApiError as e:
            outcomes.append((e.code, e.reason))

    threads = [threading.Thread(target=finish, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(map(str, outcomes)) == sorted(["ok", str(("QG_INVALID_INPUT", "invite_invalid"))])
    assert count(env, "SELECT COUNT(*) FROM devices") == devices_before + 1
    r, _ = _start(env, code)
    deny(r, 400, "QG_INVALID_INPUT", "invite_invalid")


@pytest.mark.parametrize("proof", ["kem", "signing"])
def test_enrollment_without_key_possession_proof_rejected(env, proof):
    victim = env.device("Daniel Mensah")
    code = victim.post("/api/v1/invites", {"user_id": victim.user_id})["code"]
    epoch_before = env.http.get("/api/v1/directory").json()["epoch"]
    devices_before = count(env, "SELECT COUNT(*) FROM devices")
    mine = DeviceKeys.generate()
    entry = victim.device_entry(victim.device_id)
    # Present a public key the attacker does not hold the private key for (copied from the directory).
    kem_pk = entry["kem_pk"] if proof == "kem" else mine.kem_pk_b64u
    sig_pk = entry["sig_pk"] if proof == "signing" else mine.sig_pk_b64u
    start = env.http.post("/api/v1/enroll/start", json={"suite": SUITE, "code": code, "device_name": "probe",
                                                        "kem_pk": kem_pk, "sig_pk": sig_pk}).json()
    t = enroll_transcript(enroll_id=start["enroll_id"], user_id=start["user"]["user_id"], device_name="probe",
                          kem_pk_b64u=kem_pk, sig_pk_b64u=sig_pk, challenge_b64u=start["challenge"],
                          xwing_ct_b64u=start["xwing_ct"], directory_epoch=start["directory_epoch"],
                          server_time=start["server_time"])
    if proof == "kem":  # can sign, cannot decapsulate: best guess at the confirmation key
        confirm = kdf.hmac384(os.urandom(48), t)
    else:  # can decapsulate, cannot sign for the presented key
        ss = mine.kem.decapsulate(b64u_decode(start["xwing_ct"]))
        confirm = kdf.hmac384(kdf.enroll_confirm_key(ss, b64u_decode(start["challenge"])), t)
    signature = mine.sig.sign(t, "enroll")
    r = env.http.post("/api/v1/enroll/finish", json={"enroll_id": start["enroll_id"], "signature": b64u(signature),
                                                     "key_confirm": b64u(confirm)})
    deny(r, 400, "QG_BAD_SIGNATURE", "proof_failed")
    assert "certificate" not in r.text
    assert env.http.get("/api/v1/directory").json()["epoch"] == epoch_before
    assert count(env, "SELECT COUNT(*) FROM devices") == devices_before


# ---- changes, approvals and recovery ---------------------------------------------------------------


def _approve_raw(dev, change):
    approval = {"change_hash": change["change_hash"], "change_id": change["id"], "decision": "approve",
                "purpose": "approve", "suite": SUITE}
    body = {"signature": b64u(dev.state.keys.sig.sign(canon(approval), "change"))}
    return dev.raw_request("POST", f"/api/v1/changes/{change['id']}/approve", body=json.dumps(body).encode())


def test_self_approval_of_sensitive_change_rejected(env):
    mira = env.device("Mira Okafor")
    mira_phone = env.second_device("Mira Okafor", "Mira's phone")
    tomas = env.device("Tomas Lindqvist")
    change = mira.request_change("role_grant", tomas.user_id, role="operator", reason="cover on-call")
    assert change["status"] == "pending" and change["approvals_required"] == 1
    deny(_approve_raw(mira, change), 403, "QG_DENY_POLICY", "self_approval")
    deny(_approve_raw(mira_phone, change), 403, "QG_DENY_POLICY", "self_approval")  # requester's second device
    deny(_approve_raw(tomas, change), 403, "QG_DENY_POLICY", "self_approval")  # the target
    assert q(env, "SELECT status FROM changes WHERE id = ?", (change["id"],))[0][0] == "pending"
    assert count(env, "SELECT COUNT(*) FROM change_approvals WHERE change_id = ?", (change["id"],)) == 0
    assert "operator" not in env.core.directory.roles(env.core.db.read(), tomas.user_id)


def _signal(env, priya, subject_id, role):
    now = int(env.clock.now().timestamp())
    body = {"iss": "sandbox-identity-source", "jti": os.urandom(8).hex(), "iat": now, "aud": "quantumguard",
            "events": {"urn:qg:event-type:privilege-observed": {
                "subject": {"format": "opaque", "id": subject_id}, "event_timestamp": now, "role": role}}}
    return priya.post("/api/v1/signals", body)


def test_privilege_without_signed_record_raises_qg_r005(env):
    priya = env.device("Priya Raman")
    dan = env.device("Daniel Mensah")
    aiko = env.device("Aiko Tanaka")
    secret = dan.protect("budget.xlsx", b"sensitive", "confidential")["file"]["file_id"]
    plain = dan.protect("lunch.txt", b"menu", "internal")["file"]["file_id"]
    own = aiko.protect("aiko.txt", b"aiko's", "restricted")["file"]["file_id"]
    _signal(env, priya, dan.user_id, "admin")  # the identity source reports a role no signed change granted
    alerts = env.alerts("QG-R005")
    assert len(alerts) == 1 and alerts[0]["subject"]["user_id"] == dan.user_id
    assert alerts[0]["response"]["action"] == "quarantine_identity"
    deny(dan.raw_request("GET", f"/api/v1/files/{secret}/slot"), 403, "QG_QUARANTINED")
    assert dan.open(plain) == b"menu"  # quarantine is scoped to sensitive files
    assert aiko.open(own) == b"aiko's"  # and to that identity
    assert "admin" not in env.core.directory.roles(env.core.db.read(), dan.user_id)


def test_recovery_slot_unusable_without_two_independent_approvals(env):
    aiko = env.device("Aiko Tanaka")
    mira = env.device("Mira Okafor")
    tomas = env.device("Tomas Lindqvist")
    tomas_phone = env.second_device("Tomas Lindqvist", "Tomas's phone")
    priya = env.device("Priya Raman")
    fid = aiko.protect("handover.docx", b"only aiko", "restricted")["file"]["file_id"]
    change = mira.request_change("recovery_release", aiko.user_id, file_id=fid, reason="owner unavailable")
    assert change["approvals_required"] == 2

    def recover():
        return mira.raw_request("POST", f"/api/v1/files/{fid}/recover",
                                body=json.dumps({"change_id": change["id"]}).encode())

    deny(recover(), 403, "QG_DENY_POLICY", "approvals_incomplete")
    assert tomas.approve_change(change)["status"] == "pending"
    deny(recover(), 403, "QG_DENY_POLICY", "approvals_incomplete")
    dup = _approve_raw(tomas_phone, change)  # the same person through a second device
    assert dup.status_code in (403, 409) and "inner_wrap" not in dup.text
    assert count(env, "SELECT COUNT(*) FROM change_approvals WHERE change_id = ?", (change["id"],)) == 1
    deny(recover(), 403, "QG_DENY_POLICY", "approvals_incomplete")
    assert priya.approve_change(change)["status"] == "applied"
    r = recover()
    assert r.status_code == 200 and "recovery_wrap" in r.json()
    deny(recover(), 409, "QG_CONFLICT", "already_used")


# ---- detection rules that exist -------------------------------------------------------------------


def test_decoy_touch_raises_qg_r004_and_quarantines_device(env):
    aiko = env.device("Aiko Tanaka")
    dan = env.device("Daniel Mensah")
    own = aiko.protect("own.txt", b"mine", "confidential")["file"]["file_id"]
    decoy = env.decoy_file_id()
    r = dan.raw_request("GET", f"/api/v1/files/{decoy}/slot")
    deny(r, 403, "QG_DENY_POLICY")
    alerts = env.alerts("QG-R004")
    assert len(alerts) == 1 and alerts[0]["subject"]["device_id"] == dan.device_id
    assert alerts[0]["response"]["action"] == "quarantine_device"
    deny(dan.raw_request("GET", "/api/v1/files"), 403, "QG_QUARANTINED")  # the same device, old session
    with pytest.raises(ApiError) as ei:
        dan.login()  # and a fresh session
    assert (ei.value.status, ei.value.code) == (403, "QG_QUARANTINED")
    assert aiko.open(own) == b"mine"  # unrelated device unaffected
    assert count(env, "SELECT COUNT(*) FROM releases WHERE file_id = ?", (decoy,)) == 0


def test_unknown_suite_rejected(env):
    r, _ = _start(env, env.people["Daniel Mensah"]["code"], suite="QG-2")
    deny(r, 400, "QG_BAD_SUITE")
    dev = env.device("Daniel Mensah")  # the code was not consumed by the refused attempt
    r = env.http.post("/api/v1/session/start", json={"suite": "QG-0", "device_id": dev.device_id})
    deny(r, 400, "QG_BAD_SUITE")
    assert len(env.alerts("QG-R014")) >= 2


# ---- object isolation -------------------------------------------------------------------------------

ROUTES = ["metadata", "slot", "chunk", "share", "unshare", "delete", "versions", "put_chunk", "commit"]


def _file_request(dev, route, fid):
    body = None
    method, path, headers = "GET", f"/api/v1/files/{fid}", {}
    if route == "slot":
        path += "/slot"
    elif route == "chunk":
        path += "/chunks/0"
        headers = {"QG-Lease": new_id("lse")}
    elif route == "delete":
        method = "DELETE"
    elif route == "versions":
        method, path, body = "POST", path + "/versions", {"reason": "rekey", "size_bytes": 10, "chunk_count": 1}
    elif route == "unshare":
        method, path, body = "POST", path + "/unshare", {"user_id": new_id("usr")}
    elif route == "share":
        stmt = {"directory_epoch": 1, "file_id": fid, "recipients": [dev.device_id], "suite": SUITE, "version": 1}
        wrap = {"device_id": dev.device_id, "xwing_ct": b64u(os.urandom(1120)), "wrapped_dek": b64u(os.urandom(60))}
        method, path, body = "POST", path + "/share", {"share": stmt, "share_sig": b64u(os.urandom(3309)),
                                                        "wraps": [wrap]}
    elif route == "commit":
        manifest = {"chunk_count": 1, "ciphertext_sha256": b64u(os.urandom(32)), "classification": "confidential",
                    "directory_epoch": 1, "file_id": fid, "recipients": [dev.device_id], "suite": SUITE, "version": 1}
        wrap = {"xwing_ct": b64u(os.urandom(1120)), "wrapped_dek": b64u(os.urandom(60))}
        method, path, body = "POST", path + "/versions/1/commit", {
            "manifest": manifest, "manifest_sig": b64u(os.urandom(3309)),
            "wraps": [{"device_id": dev.device_id, **wrap}], "recovery_wrap": wrap}
    if route == "put_chunk":
        return dev.raw_request("PUT", f"/api/v1/files/{fid}/versions/1/chunks/0", body=os.urandom(64),
                               content_type="application/octet-stream")
    raw = b"" if body is None else json.dumps(body).encode()
    return dev.raw_request(method, path, body=raw, headers=headers)


@pytest.mark.parametrize("route", ROUTES)
def test_other_users_object_ids_return_not_found_without_existence_leak(env, route):
    aiko = env.device("Aiko Tanaka")
    dan = env.device("Daniel Mensah")
    data = os.urandom(1000)
    hidden_id = aiko.protect("salaries.xlsx", data, "confidential")["file"]["file_id"]
    hidden = _file_request(dan, route, hidden_id)
    absent = _file_request(dan, route, absent_id("fil"))
    a = deny(hidden, 404, "QG_NOT_FOUND")
    b = deny(absent, 404, "QG_NOT_FOUND")
    for f in ("code", "message", "reason"):
        assert a[f] == b[f]
    assert (a["receipt_id"] is None) == (b["receipt_id"] is None)
    assert ("qg-receipt" in hidden.headers) == ("qg-receipt" in absent.headers)
    assert set(hidden.headers) == set(absent.headers)
    assert aiko.open(hidden_id) == data  # and nothing changed for the owner


# ---- evidence ----------------------------------------------------------------------------------------


def _incident_bundle(env, tmp_path):
    laptop, phone = _pair(env)
    priya = env.device("Priya Raman")
    fid = laptop.protect("plates.csv", os.urandom(4000), "confidential", [phone.device_id])["file"]["file_id"]
    laptop.open(fid)
    rr = _report_lost(env, phone, laptop)
    laptop.raw_request("GET", f"/api/v1/files/{fid}/slot")  # a denied attempt after the revoke
    bundle = priya.get(f"/api/v1/incidents/{rr['incident_id']}/bundle")
    keys = env.http.get("/api/v1/meta").json()["server_keys"]
    pinned = {"ed25519_pk": keys["ed25519_pk"], "mldsa_pk": keys["mldsa_pk"]}
    assert verify_bundle(bundle, pinned)["ok"] is True
    return bundle, pinned


def _cli_verify(tmp_path, bundle, pinned):
    from qg.client.cli import main

    bp, kp = tmp_path / "bundle.json", tmp_path / "keys.json"
    bp.write_text(json.dumps(bundle))
    kp.write_text(json.dumps(pinned))
    return main(["verify", str(bp), "--keys", str(kp), "--json"])


def test_log_byte_flip_detected_by_offline_verifier(env, tmp_path, capsys):
    bundle, pinned = _incident_bundle(env, tmp_path)
    assert _cli_verify(tmp_path, bundle, pinned) == 0
    assert len(bundle["entries"]) >= 3
    for k in range(len(bundle["entries"])):
        bad = json.loads(json.dumps(bundle))
        e = bad["entries"][k]
        e["receipt"]["reason_code"] = e["receipt"]["reason_code"][:-1] + chr(ord(e["receipt"]["reason_code"][-1]) ^ 1)
        res = verify_bundle(bad, pinned)
        assert res["ok"] is False and res["failed_step"] == "entries"
        assert res["first_bad_index"] == e["leaf_index"]
    bad = json.loads(json.dumps(bundle))
    path = bad["entries"][0]["audit_path"]
    if path:
        raw = bytearray(b64u_decode(path[0]))
        raw[0] ^= 1
        path[0] = b64u(bytes(raw))
        assert verify_bundle(bad, pinned)["ok"] is False
    bad = json.loads(json.dumps(bundle))
    bad["entries"][-1]["receipt"]["decision"] = "allow" if bad["entries"][-1]["receipt"]["decision"] == "deny" else "deny"
    assert _cli_verify(tmp_path, bad, pinned) == 1


@pytest.mark.parametrize("signature", ["ed25519", "mldsa"])
def test_checkpoint_with_one_bad_signature_rejected(env, tmp_path, signature, capsys):
    bundle, pinned = _incident_bundle(env, tmp_path)
    variants = []
    flipped = json.loads(json.dumps(bundle))
    raw = bytearray(b64u_decode(flipped["checkpoint"]["signatures"][signature]))
    raw[len(raw) // 2] ^= 0x01
    flipped["checkpoint"]["signatures"][signature] = b64u(bytes(raw))
    variants.append(flipped)
    missing = json.loads(json.dumps(bundle))
    del missing["checkpoint"]["signatures"][signature]
    variants.append(missing)
    swapped = json.loads(json.dumps(bundle))  # a valid signature, but over another checkpoint
    swapped["checkpoint"]["signatures"][signature] = bundle["revocation_checkpoint"]["signatures"][signature]
    if bundle["revocation_checkpoint"]["tree_size"] != bundle["checkpoint"]["tree_size"]:
        variants.append(swapped)
    for bad in variants:
        res = verify_bundle(bad, pinned)
        assert res["ok"] is False and res["failed_step"] == "checkpoint"
        assert _cli_verify(tmp_path, bad, pinned) == 1


# ---- fail closed -----------------------------------------------------------------------------------------


def test_policy_engine_down_means_deny_without_key_release(env):
    laptop = env.device("Aiko Tanaka")
    fid = laptop.protect("plates.csv", os.urandom(MULTI), "confidential")["file"]["file_id"]
    slot = laptop.slot(fid)
    releases = count(env, "SELECT COUNT(*) FROM releases")
    leases = count(env, "SELECT COUNT(*) FROM leases")
    env.set_policy_available(False)
    try:
        deny(laptop.raw_request("GET", f"/api/v1/files/{fid}/slot"), 503, "QG_UNAVAILABLE_FAIL_CLOSED",
             "policy_unavailable")
        r = laptop.raw_request("GET", f"/api/v1/files/{fid}/chunks/0", headers={"QG-Lease": slot["lease"]["lease_id"]})
        deny(r, 503, "QG_UNAVAILABLE_FAIL_CLOSED")
        assert not r.content.startswith(b"\x00") and r.headers["content-type"].startswith("application/json")
        deny(laptop.raw_request("POST", "/api/v1/files", body=json.dumps(
            {"name": "x", "classification": "internal", "size_bytes": 1, "chunk_count": 1}).encode()),
             503, "QG_UNAVAILABLE_FAIL_CLOSED")
        assert count(env, "SELECT COUNT(*) FROM releases") == releases
        assert count(env, "SELECT COUNT(*) FROM leases") == leases
    finally:
        env.set_policy_available(True)
    assert laptop.open(fid)


# ---- secrets in logs ---------------------------------------------------------------------------------------


def test_no_generated_secret_appears_in_any_log_line(env, tmp_path, caplog, capfd):
    import logging

    caplog.set_level(logging.DEBUG)
    secrets: list[bytes] = []
    texts: list[str] = []
    for person in env.people.values():  # every bootstrap code, as printed and as normalised
        texts += [person["code"], person["code"].replace("-", ""), person["code"].lower()]

    laptop, phone = _pair(env)
    dan = env.device("Daniel Mensah")
    priya = env.device("Priya Raman")
    inv = dan.post("/api/v1/invites", {"user_id": dan.user_id})["code"]
    texts += [inv, inv.replace("-", "")]
    tablet = env.enroll("Daniel Mensah", "Daniel's tablet", code=inv)
    devices = [laptop, phone, dan, priya, tablet]

    data = os.urandom(5000)
    fid = laptop.protect("plates.csv", data, "confidential", [phone.device_id])["file"]["file_id"]
    slot = laptop.slot(fid)
    secrets.append(laptop.unwrap(slot))
    laptop.share(fid, [dan.device_id])
    laptop.raw_request("POST", f"/api/v1/files/{fid}/unshare", body=json.dumps({"user_id": dan.user_id}).encode())
    laptop.raw_request("GET", "/api/v1/devices", headers={"QG-MAC": b64u(os.urandom(48))})  # bad MAC
    env.http.post("/api/v1/enroll/start", json={"suite": SUITE, "code": "K7QM-2XVD-9RTA-HB4N", "device_name": "x",
                                                "kem_pk": DeviceKeys.generate().kem_pk_b64u,
                                                "sig_pk": DeviceKeys.generate().sig_pk_b64u})
    dan.raw_request("GET", f"/api/v1/files/{env.decoy_file_id()}/slot")
    passphrase = "correct horse battery staple " + os.urandom(6).hex()
    texts.append(passphrase)
    laptop.state.save(str(tmp_path / "laptop.qgkeystore"), passphrase)
    for d in devices:
        secrets += [d.state.keys.sig.seed, d.state.keys.kem.seed]
        if d.session is not None:
            secrets.append(d.session.k_mac)
    rr = _report_lost(env, phone, laptop)
    for item in phone.rekey_pending()["rekeys"]:
        phone.rekey_one(item)
    new_slot = phone.slot(fid)
    secrets.append(phone.unwrap(new_slot))
    priya.get(f"/api/v1/incidents/{rr['incident_id']}/bundle")
    phone.call("POST", "/api/v1/session/end", {})
    keys_dir = env.root / "keys"
    doc = json.loads((keys_dir / "server-keys.json").read_text())
    for k in ("ed25519_seed", "mldsa_seed", "kem_seed", "seal_master"):
        secrets.append(b64u_decode(doc[k]))
    if env.recovery_kit:  # the operator's private recovery kit (never given to the server)
        secrets.append(b64u_decode(env.recovery_kit["kem_seed"]))
    secrets.append(kdf.seal_key(env.core.keys.seal_master, env.core.keys.seal_epoch))

    canaries = texts + [form for s in secrets for form in encodings(s)]
    assert len(secrets) >= 15 and len(texts) >= 15
    out, err = capfd.readouterr()
    events = env.root / "data" / "SECURITY_EVENTS.jsonl"
    lines = list(env.logs) + caplog.messages + out.splitlines() + err.splitlines()
    lines += events.read_text().splitlines() if events.exists() else []
    assert len(env.logs) > 20, "the server log must have been captured, including startup"
    assert any('"event":"alert"' in line for line in lines), "security-event lines must be part of the scan"
    leaked = sum(1 for c in canaries for line in lines if c in line)
    assert leaked == 0, f"{leaked} occurrences of a generated secret in captured logs"  # never print the secret


# ---- server database copy ------------------------------------------------------------------------------------


def test_server_database_copy_alone_cannot_decrypt_file(env, tmp_path):
    laptop, phone = _pair(env)
    data = os.urandom(MULTI)
    fid = laptop.protect("plates.csv", data, "confidential", [phone.device_id])["file"]["file_id"]
    slot = laptop.slot(fid)
    dek = laptop.unwrap(slot)
    assert laptop.open_slot(slot) == data  # the legitimate client decrypts first

    # The attacker's workspace: a consistent copy of the database (committed WAL state included) and the
    # ciphertext store. Nothing from keys/ and no client private material.
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    db_copy = attacker / "quantumguard.sqlite"
    with env.core.db._lock:  # noqa: SLF001 - a quiescent copy, as a backup tool would take
        dst = sqlite3.connect(db_copy)
        env.core.db._conn.backup(dst)  # noqa: SLF001
        dst.close()
    for suffix in ("", "-wal"):
        src = env.root / "data" / ("quantumguard.sqlite" + suffix)
        if src.exists():
            shutil.copy(src, attacker / ("raw.sqlite" + suffix))
    shutil.copytree(env.root / "data" / "blobs", attacker / "blobs")
    assert not any(p.name.endswith(".json") and "key" in p.name for p in attacker.rglob("*"))

    # 1. No private key, seal key, file key or session key is present in any form.
    corpus = b"".join(p.read_bytes() for p in attacker.rglob("*") if p.is_file())
    keys_doc = json.loads((env.root / "keys" / "server-keys.json").read_text())
    secrets = [dek, b64u_decode(keys_doc["seal_master"]), b64u_decode(env.recovery_kit["kem_seed"]),
               kdf.seal_key(env.core.keys.seal_master, env.core.keys.seal_epoch),
               laptop.state.keys.kem.seed, phone.state.keys.kem.seed, laptop.session.k_mac, phone.session.k_mac]
    for s in secrets:
        assert s not in corpus
        for form in encodings(s):
            assert form.encode() not in corpus

    # 2. Actually try: every 32-byte value stored in the copy, at every offset, as the file key and as the seal
    # master key. None opens chunk 0 or the sealed slot.
    con = sqlite3.connect(db_copy)
    sealed_row = con.execute("SELECT slot_id, version, device_id, sealed, seal_epoch FROM slots WHERE file_id = ?"
                             " AND device_id = ?", (fid, laptop.device_id)).fetchone()
    con.close()
    slot_id, version, device_id, sealed, seal_epoch = sealed_row
    seal_aad = aead.seal_aad(slot_id, fid, version, device_id, seal_epoch)
    chunk0 = (attacker / "blobs" / fid / str(version) / "0").read_bytes()
    aad0 = aead.chunk_aad(fid, version, 0, False)
    db_bytes = db_copy.read_bytes()
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    opened = 0
    tried = set()
    for i in range(0, len(db_bytes) - 31):
        cand = db_bytes[i : i + 32]
        if cand in tried:
            continue
        tried.add(cand)
        try:
            AESGCM(cand).decrypt(chunk0[:12], chunk0[12:], aad0)
            opened += 1
        except InvalidTag:
            pass
        if i % 7 == 0:  # the seal key needs an HKDF per candidate: sample one offset in seven
            try:
                aead.unseal(cand, seal_epoch, seal_aad, bytes(sealed))
                opened += 1
            except aead.AeadError:
                pass
    assert len(tried) > 10_000
    assert opened == 0
