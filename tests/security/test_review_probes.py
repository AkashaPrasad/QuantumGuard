"""Review r1 probes beyond the 13.2 list (review checklist 14.4). Each test is an attack the product is
expected to refuse; all of these pass on the reviewed commit. Weaknesses that were demonstrated live in
tests/attacks/ instead."""

from __future__ import annotations

import json
import os

import pytest

from qg.client.api import ApiError
from qg.crypto.encoding import b64u, b64u_decode
from qg.crypto.suite import SUITE
from qg.crypto.transcripts import request_mac
from qg.ids import new_id
from qg.log import merkle
from qg.log.verify import verify_bundle
from qgsec import absent_id, count, deny, q

# ---- request MAC -------------------------------------------------------------------------------------


def _send(env, dev, method, path, body=b"", *, sign_method=None, sign_path=None, sign_body=None, seq=None,
          session=None):
    dev.session.seq += 1
    s = seq if seq is not None else dev.session.seq
    mac = request_mac(dev.session.k_mac, sign_method or method, sign_path or path, s,
                      body if sign_body is None else sign_body)
    headers = {"QG-Session": session or dev.session.session_id, "QG-Seq": str(s), "QG-MAC": mac}
    if body:
        headers["Content-Type"] = "application/json"
    return env.http.request(method, path, content=body, headers=headers)


@pytest.mark.parametrize("tamper", ["query", "body", "method", "path", "seq", "session"])
def test_request_mac_binds_every_part(env, tamper):
    dev = env.device("Daniel Mensah")
    other = env.device("Aiko Tanaka")
    body = json.dumps({"user_id": dev.user_id}).encode()
    if tamper == "query":
        r = _send(env, dev, "GET", "/api/v1/devices?scope=all", sign_path="/api/v1/devices")
    elif tamper == "body":
        r = _send(env, dev, "POST", "/api/v1/invites", body, sign_body=json.dumps({"user_id": other.user_id}).encode())
    elif tamper == "method":
        r = _send(env, dev, "DELETE", f"/api/v1/invites/{new_id('inv')}", sign_method="GET",
                  sign_path=f"/api/v1/invites/{new_id('inv')}")
    elif tamper == "path":
        r = _send(env, dev, "GET", "/api/v1/log/receipts", sign_path="/api/v1/devices")
    elif tamper == "seq":
        dev.session.seq += 1
        mac = request_mac(dev.session.k_mac, "GET", "/api/v1/devices", dev.session.seq, b"")
        r = env.http.get("/api/v1/devices", headers={"QG-Session": dev.session.session_id,
                                                     "QG-Seq": str(dev.session.seq + 5), "QG-MAC": mac})
    else:
        r = _send(env, dev, "GET", "/api/v1/devices", session=other.session.session_id)
    deny(r, 401, "QG_BAD_MAC", "bad_mac")
    # a bad MAC neither advances the sequence nor ends the session
    assert dev.raw_request("GET", "/api/v1/devices", seq=1).status_code == 200


def test_session_start_is_single_use_and_expires(env):
    from qg.crypto import kdf
    from qg.crypto.transcripts import session_transcript

    dev = env.device("Daniel Mensah")

    def finish(s):
        ct, ch = b64u_decode(s["xwing_ct"]), b64u_decode(s["challenge"])
        ss = dev.state.keys.kem.decapsulate(ct)
        t = session_transcript(start_id=s["start_id"], device_id=dev.device_id, challenge_b64u=s["challenge"],
                               xwing_ct_b64u=s["xwing_ct"], directory_epoch=s["directory_epoch"],
                               server_time=s["server_time"])
        return env.http.post("/api/v1/session/finish", json={
            "start_id": s["start_id"], "signature": b64u(dev.state.keys.sig.sign(t, "session")),
            "key_confirm": b64u(kdf.hmac384(kdf.session_confirm_key(ss, ch), t))})

    s = env.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": dev.device_id}).json()
    assert finish(s).status_code == 200
    deny(finish(s), 400, "QG_BAD_SIGNATURE")  # replay of a used start
    s2 = env.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": dev.device_id}).json()
    env.clock.advance(61)
    deny(finish(s2), 400, "QG_BAD_SIGNATURE")


# ---- leases, re-key, unshare --------------------------------------------------------------------------


def test_lease_misuse_refused(env):
    laptop = env.device("Aiko Tanaka")
    phone = env.second_device("Aiko Tanaka", "Aiko's phone")
    fid = laptop.protect("a.bin", os.urandom(800), "confidential", [phone.device_id])["file"]["file_id"]
    lease = laptop.slot(fid)["lease"]["lease_id"]
    path = f"/api/v1/files/{fid}/chunks/0"
    deny(phone.raw_request("GET", path, headers={"QG-Lease": lease}), 403, "QG_LEASE_EXPIRED")  # other device
    deny(laptop.raw_request("GET", path), 403, "QG_LEASE_EXPIRED")  # no lease
    deny(laptop.raw_request("GET", path, headers={"QG-Lease": "../" + lease}), 403, "QG_LEASE_EXPIRED")
    deny(laptop.raw_request("GET", f"/api/v1/files/{fid}/chunks/7", headers={"QG-Lease": lease}), 404,
         "QG_NOT_FOUND")
    deny(laptop.raw_request("GET", f"/api/v1/files/{fid}/chunks/-1", headers={"QG-Lease": lease}), 404,
         "QG_NOT_FOUND")


def test_rekey_after_unshare_removes_person_and_old_version(env):
    aiko = env.device("Aiko Tanaka")
    dan = env.device("Daniel Mensah")
    data = os.urandom(3000)
    fid = aiko.protect("plan.txt", data, "confidential", [dan.device_id])["file"]["file_id"]
    dan_lease = dan.slot(fid)["lease"]["lease_id"]
    aiko_slot = aiko.slot(fid)
    # a holder who is not the owner cannot unshare or delete
    deny(dan.raw_request("POST", f"/api/v1/files/{fid}/unshare",
                         body=json.dumps({"user_id": aiko.user_id}).encode()), 403, "QG_DENY_POLICY")
    deny(dan.raw_request("DELETE", f"/api/v1/files/{fid}"), 403, "QG_DENY_POLICY")
    aiko.post(f"/api/v1/files/{fid}/unshare", {"user_id": dan.user_id})
    deny(dan.raw_request("GET", f"/api/v1/files/{fid}/chunks/0", headers={"QG-Lease": dan_lease}), 404,
         "QG_NOT_FOUND")
    deny(dan.raw_request("GET", f"/api/v1/files/{fid}/slot"), 404, "QG_NOT_FOUND")
    assert dan.rekey_pending()["rekeys"] == []
    item = aiko.rekey_pending()["rekeys"][0]
    assert item["recipients"] == [aiko.device_id] and item["reason"] == "unshare"
    aiko.rekey_one(item)
    v1 = aiko_slot["version"]
    assert count(env, "SELECT COUNT(*) FROM slots WHERE file_id = ? AND version = ?", (fid, v1)) == 0
    assert not (env.core.blobs.root / fid / str(v1)).exists()
    deny(aiko.raw_request("GET", f"/api/v1/files/{fid}/chunks/0", headers={"QG-Lease": aiko_slot["lease"]["lease_id"]}),
         403, "QG_LEASE_EXPIRED")  # a lease for the old version
    assert aiko.open(fid) == data
    devs = [r[0] for r in q(env, "SELECT device_id FROM slots WHERE file_id = ?", (fid,))]
    assert dan.device_id not in devs
    # the removed holder cannot commit an old pending re-key either
    with pytest.raises(ApiError):
        dan.post(f"/api/v1/files/{fid}/versions", {"reason": "rekey", "size_bytes": 1, "chunk_count": 1})


def test_share_to_revoked_device_and_revoke_rules(env):
    laptop = env.device("Aiko Tanaka")
    phone = env.second_device("Aiko Tanaka", "Aiko's phone")
    dan = env.device("Daniel Mensah")
    mira = env.device("Mira Okafor")
    fid = phone.protect("a.bin", b"x" * 100, "confidential")["file"]["file_id"]
    deny(dan.raw_request("POST", f"/api/v1/devices/{laptop.device_id}/revoke", body=json.dumps(
        {"compromise_time": env.clock.iso(), "reason": "x"}).encode()), 404, "QG_NOT_FOUND")
    deny(mira.raw_request("POST", f"/api/v1/devices/{laptop.device_id}/revoke", body=json.dumps(
        {"compromise_time": env.clock.iso(), "reason": "x"}).encode()), 403, "QG_DENY_POLICY")
    deny(dan.raw_request("POST", f"/api/v1/devices/{laptop.device_id}/report-lost", body=json.dumps(
        {"lost_at": env.clock.iso()}).encode()), 404, "QG_NOT_FOUND")
    phone.post(f"/api/v1/devices/{laptop.device_id}/report-lost", {"lost_at": env.clock.iso()})
    with pytest.raises(Exception):  # noqa: B017 - the client refuses (not in directory) or the server does
        phone.share(fid, [laptop.device_id])
    assert count(env, "SELECT COUNT(*) FROM slots WHERE device_id = ?", (laptop.device_id,)) == 0


# ---- existence leaks beyond files --------------------------------------------------------------------------


def _pair_requests(dev, other_ids):
    return {
        "incident": ("GET", f"/api/v1/incidents/{other_ids['incident']}", f"/api/v1/incidents/{absent_id('inc')}", None),
        "exposure": ("GET", f"/api/v1/incidents/{other_ids['incident']}/exposure",
                     f"/api/v1/incidents/{absent_id('inc')}/exposure", None),
        "receipt": ("GET", f"/api/v1/log/receipts/{other_ids['receipt']}", f"/api/v1/log/receipts/{absent_id('rcp')}",
                    None),
        "rename": ("PATCH", f"/api/v1/devices/{other_ids['device']}", f"/api/v1/devices/{absent_id('dev')}",
                   {"name": "mine now"}),
        "invite_cancel": ("DELETE", f"/api/v1/invites/{other_ids['invite']}", f"/api/v1/invites/{absent_id('inv')}",
                          None),
    }


@pytest.mark.parametrize("kind", ["incident", "exposure", "receipt", "rename", "invite_cancel"])
def test_other_peoples_objects_are_indistinguishable_from_absent(env, kind):
    laptop = env.device("Aiko Tanaka")
    phone = env.second_device("Aiko Tanaka", "Aiko's phone")
    dan = env.device("Daniel Mensah")
    inv = phone.post("/api/v1/invites", {"user_id": phone.user_id})
    rr = phone.post(f"/api/v1/devices/{laptop.device_id}/report-lost", {"lost_at": env.clock.iso()})
    ids = {"incident": rr["incident_id"], "receipt": rr["receipt_id"], "device": phone.device_id,
           "invite": inv["invite_id"]}
    method, hidden_path, absent_path, body = _pair_requests(dan, ids)[kind]
    raw = b"" if body is None else json.dumps(body).encode()
    a = deny(dan.raw_request(method, hidden_path, body=raw), 404, "QG_NOT_FOUND")
    b = deny(dan.raw_request(method, absent_path, body=raw), 404, "QG_NOT_FOUND")
    assert (a["code"], a["message"], a["reason"]) == (b["code"], b["message"], b["reason"])


# ---- input handling ------------------------------------------------------------------------------------


@pytest.mark.parametrize("case", ["too_large", "too_deep", "unknown_field", "float", "duplicate_key", "wrong_type",
                                  "traversal_id", "chunk_count"])
def test_malformed_input_refused(env, case):
    dev = env.device("Aiko Tanaka")
    good = {"name": "a", "classification": "internal", "size_bytes": 1, "chunk_count": 1}
    path, method = "/api/v1/files", "POST"
    if case == "too_large":
        body = json.dumps({**good, "name": "x" * 300_000}).encode()
    elif case == "too_deep":
        nested: object = 1
        for _ in range(40):
            nested = {"a": nested}
        body = json.dumps({**good, "x": nested}).encode()
    elif case == "unknown_field":
        body = json.dumps({**good, "owner_user_id": "usr_x"}).encode()
    elif case == "float":
        body = json.dumps({**good, "size_bytes": 1.0}).encode()
    elif case == "duplicate_key":
        body = b'{"name":"a","name":"b","classification":"internal","size_bytes":1,"chunk_count":1}'
    elif case == "wrong_type":
        body = json.dumps({**good, "size_bytes": "1"}).encode()
    elif case == "chunk_count":
        body = json.dumps({**good, "size_bytes": 1, "chunk_count": 10**9}).encode()
    else:
        method, path, body = "GET", "/api/v1/files/..%2F..%2Fkeys%2Fserver-keys.json/slot", b""
    r = dev.raw_request(method, path, body=body)
    assert r.status_code in (400, 404), r.status_code
    assert r.json()["error"]["code"] in ("QG_INVALID_INPUT", "QG_NOT_FOUND")
    assert r.headers.get("QG-Request-Id")
    assert count(env, "SELECT COUNT(*) FROM files WHERE is_decoy = 0") == 0


def test_chunk_upload_bounds(env):
    dev = env.device("Aiko Tanaka")
    fid = dev.post("/api/v1/files", {"name": "a", "classification": "internal", "size_bytes": 10,
                                      "chunk_count": 1})["file_id"]
    base = f"/api/v1/files/{fid}/versions/1/chunks"
    deny(dev.raw_request("PUT", f"{base}/1", body=os.urandom(40), content_type="application/octet-stream"), 400,
         "QG_INVALID_INPUT", "chunk_index")
    deny(dev.raw_request("PUT", f"{base}/0", body=os.urandom(10), content_type="application/octet-stream"), 400,
         "QG_INVALID_INPUT", "chunk_size")
    assert env.core.blobs.count(fid, 1) == 0  # nothing was stored for either refused chunk


# ---- fail closed on storage ----------------------------------------------------------------------------


def test_storage_failure_fails_closed(env, monkeypatch):
    dev = env.device("Aiko Tanaka")
    fid = dev.protect("a.bin", os.urandom(500), "internal")["file"]["file_id"]
    slot = dev.slot(fid)
    (env.core.blobs.root / fid / str(slot["version"]) / "0").unlink()  # fault injection: blob lost
    deny(dev.raw_request("GET", f"/api/v1/files/{fid}/chunks/0", headers={"QG-Lease": slot["lease"]["lease_id"]}),
         503, "QG_UNAVAILABLE_FAIL_CLOSED", "storage_unavailable")
    fid2 = dev.post("/api/v1/files", {"name": "b", "classification": "internal", "size_bytes": 5,
                                       "chunk_count": 1})["file_id"]

    def disk_full(*a, **kw):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(env.core.blobs, "put", disk_full)
    deny(dev.raw_request("PUT", f"/api/v1/files/{fid2}/versions/1/chunks/0", body=os.urandom(40),
                         content_type="application/octet-stream"), 503, "QG_UNAVAILABLE_FAIL_CLOSED")


# ---- evidence ---------------------------------------------------------------------------------------------


def test_proofs_reject_wrong_index_and_rollback(env):
    laptop = env.device("Aiko Tanaka")
    phone = env.second_device("Aiko Tanaka", "Aiko's phone")
    priya = env.device("Priya Raman")
    fid = laptop.protect("a.bin", os.urandom(300), "confidential", [phone.device_id])["file"]["file_id"]
    laptop.open(fid)
    deny(laptop.raw_request("GET", f"/api/v1/files/{absent_id('fil')}/slot"), 404, "QG_NOT_FOUND")
    early = env.http.get("/api/v1/log/checkpoint").json()  # a genuinely signed, smaller tree
    rr = phone.post(f"/api/v1/devices/{laptop.device_id}/report-lost", {"lost_at": env.clock.iso()})
    p = priya.get("/api/v1/log/proof/3")
    cp = p["checkpoint"]
    root = b64u_decode(cp["root_hash"])
    path = [b64u_decode(h) for h in p["audit_path"]]
    leaf = b64u_decode(p["leaf_hash"])
    assert merkle.verify_inclusion(3, cp["tree_size"], leaf, path, root)
    other = b64u_decode(priya.get("/api/v1/log/proof/4")["leaf_hash"])
    assert not merkle.verify_inclusion(3, cp["tree_size"], other, path, root)
    assert not merkle.verify_inclusion(4, cp["tree_size"], leaf, path, root)
    deny(priya.raw_request("GET", f"/api/v1/log/proof/{cp['tree_size'] + 5}"), 404, "QG_NOT_FOUND")
    deny(priya.raw_request("GET", "/api/v1/log/consistency?from=9&to=3"), 400, "QG_INVALID_INPUT")
    # every refusal above wrote a receipt
    assert count(env, "SELECT COUNT(*) FROM receipts WHERE decision = 'deny' AND action = 'slot.release'") >= 1

    # Rollback: a bundle whose newest checkpoint is older than the revocation checkpoint is refused, even when
    # it is correctly signed by the server keys (simulated with this test server's own keys).
    bundle = priya.get(f"/api/v1/incidents/{rr['incident_id']}/bundle")
    keys = {k: bundle["server_keys"][k] for k in ("ed25519_pk", "mldsa_pk")}
    assert early["tree_size"] < bundle["revocation_checkpoint"]["tree_size"]
    rolled = {k: v for k, v in bundle.items() if k != "signatures"}
    rolled.update({"checkpoint": early, "entries": [], "consistency": []})
    rolled = env.core.keys.signer.sign_object(rolled, "report")
    res = verify_bundle(rolled, keys)
    assert res["ok"] is False and res["failed_step"] == "consistency"


def test_response_headers(env):
    dev = env.device("Aiko Tanaka")
    responses = [env.http.get("/api/v1/meta"), dev.raw_request("GET", "/api/v1/files"),
                 dev.raw_request("GET", f"/api/v1/files/{absent_id('fil')}"),
                 env.http.post("/api/v1/session/start", content=b"x" * 300_000,
                               headers={"content-type": "application/json"}),
                 env.http.get("/api/v1/nope")]
    for r in responses:
        for h in ("content-security-policy", "x-content-type-options", "referrer-policy", "qg-request-id",
                  "cross-origin-resource-policy"):
            assert h in r.headers, (r.request.url, h)
        assert r.headers.get("cache-control") == "no-store"
        assert "server" not in r.headers
        assert "traceback" not in r.text.lower()


# ---- changes, responses, signals, messages ------------------------------------------------------------------


def test_approval_roles_and_duplicates(env):
    mira = env.device("Mira Okafor")
    tomas = env.device("Tomas Lindqvist")
    priya = env.device("Priya Raman")
    jonas = env.device("Jonas Weber")
    dan = env.device("Daniel Mensah")
    change = mira.request_change("role_grant", dan.user_id, role="operator", reason="on-call")
    for who in (priya, jonas, dan):  # operator (not recovery), auditor, the target
        with pytest.raises(ApiError) as ei:
            who.approve_change(change)
        assert ei.value.code == "QG_DENY_POLICY"
    with pytest.raises(ApiError) as ei:
        dan.request_change("role_grant", dan.user_id, role="admin")
    assert ei.value.code == "QG_DENY_POLICY"
    assert tomas.approve_change(change)["status"] == "applied"
    with pytest.raises(ApiError) as ei:
        tomas.approve_change(change)
    assert ei.value.code == "QG_CONFLICT"


def test_lift_requires_operator(env):
    dan = env.device("Daniel Mensah")
    mira = env.device("Mira Okafor")
    dan.raw_request("GET", f"/api/v1/files/{env.decoy_file_id()}/slot")
    rsp = env.alerts("QG-R004")[0]["response"]["id"]
    for who in (mira, env.device("Jonas Weber"), env.device("Aiko Tanaka")):
        r = who.raw_request("POST", f"/api/v1/responses/{rsp}/lift", body=json.dumps({"reason": "x"}).encode())
        assert r.status_code == 403
    assert env.alerts("QG-R004")[0]["response"]["lifted_at"] is None


def test_signals_dedup_order_and_role(env):
    priya = env.device("Priya Raman")
    dan = env.device("Daniel Mensah")
    victim = env.device("Aiko Tanaka")
    now = int(env.clock.now().timestamp())

    def sig(jti, ts, status):
        return {"iss": "mdm", "jti": jti, "iat": now, "aud": "quantumguard", "events": {
            "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change": {
                "subject": {"format": "opaque", "id": victim.device_id}, "event_timestamp": ts,
                "previous_status": "compliant", "current_status": status}}}

    r = dan.raw_request("POST", "/api/v1/signals", body=json.dumps(sig("j0", now, "not-compliant")).encode())
    deny(r, 403, "QG_DENY_POLICY")
    assert q(env, "SELECT status FROM devices WHERE device_id = ?", (victim.device_id,))[0][0] == "active"
    assert priya.post("/api/v1/signals", sig("j1", now, "not-compliant"))["duplicate"] is False
    assert priya.post("/api/v1/signals", sig("j1", now, "compliant"))["duplicate"] is True  # replayed jti
    assert q(env, "SELECT status FROM devices WHERE device_id = ?", (victim.device_id,))[0][0] == "quarantined"
    priya.post("/api/v1/signals", sig("j2", now - 30, "compliant"))  # older than the applied one
    assert q(env, "SELECT status FROM devices WHERE device_id = ?", (victim.device_id,))[0][0] == "quarantined"


def test_messages_not_addressable_to_revoked_device(env):
    laptop = env.device("Aiko Tanaka")
    phone = env.second_device("Aiko Tanaka", "Aiko's phone")
    dan = env.device("Daniel Mensah")
    dan.send_message(laptop.user_id, b"before")
    phone.post(f"/api/v1/devices/{laptop.device_id}/report-lost", {"lost_at": env.clock.iso()})
    with pytest.raises(Exception):  # noqa: B017 - client (directory) or server refuses
        dan.send_message(laptop.user_id, b"after", device_ids=[laptop.device_id])
    assert [m["plaintext"] for m in phone.read_messages()] == [b"before"]
    deny(laptop.raw_request("GET", "/api/v1/messages"), 403, "QG_DENY_REVOKED")
