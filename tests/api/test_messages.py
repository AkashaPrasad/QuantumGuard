"""Messages: every recipient device verifies the sender's signature from its own envelope plus the signed list
of envelope digests, without receiving other devices' ciphertext (spec/SUITE.md section 11)."""

import json

import pytest

from qg.client.api import ApiError, ClientRefused
from qg.crypto.encoding import b64u, b64u_decode
from qg.crypto.messages import digests_for, envelope_digest, statement
from qg.crypto.sign import mldsa_verify


def test_each_of_three_recipient_devices_verifies_the_signature(env):
    aiko = env.device("Aiko Tanaka")
    d1 = env.device("Daniel Mensah")
    d2 = env.second_device("Daniel Mensah", "phone")
    d3 = env.second_device("Daniel Mensah", "tablet")
    aiko.send_message(d1.user_id, b"centrifuge 2 is out of order")
    for dev in (d1, d2, d3):
        items = dev.get("/api/v1/messages")["items"]
        assert len(items) == 1
        m = items[0]
        # only this device's ciphertext is returned, plus a digest for every envelope
        assert len(m["envelope_digests"]) == 3 and "envelopes" not in m
        assert {d["device_id"] for d in m["envelope_digests"]} == {d1.device_id, d2.device_id, d3.device_id}
        mine = envelope_digest(dev.device_id, m["envelope"]["xwing_ct"], m["envelope"]["ciphertext"])
        assert {"device_id": dev.device_id, "digest": mine} in m["envelope_digests"]
        assert mldsa_verify(aiko.state.keys.sig.public_key, b64u_decode(m["signature"]),
                            statement(dev.user_id, m["envelope_digests"]), "message")
        assert [x["plaintext"] for x in dev.read_messages()] == [b"centrifuge 2 is out of order"]


def test_client_refuses_an_envelope_not_covered_by_the_signature(env, monkeypatch):
    aiko = env.device("Aiko Tanaka")
    dan = env.device("Daniel Mensah")
    aiko.send_message(dan.user_id, b"hello")
    real_get = dan.get

    def tampered(path, **kw):
        out = real_get(path, **kw)
        if path.startswith("/api/v1/messages"):
            for m in out["items"]:
                raw = bytearray(b64u_decode(m["envelope"]["ciphertext"]))
                raw[-1] ^= 1
                m["envelope"]["ciphertext"] = b64u(bytes(raw))
        return out

    monkeypatch.setattr(dan, "get", tampered)
    with pytest.raises(ClientRefused):
        dan.read_messages()


def test_server_refuses_a_signature_over_other_digests(env):
    aiko = env.device("Aiko Tanaka")
    dan = env.device("Daniel Mensah")
    from qg.crypto import aead, kdf, xwing
    from qg.crypto.encoding import canon

    entry = aiko.device_entry(dan.device_id) or (aiko.refresh_directory() and aiko.device_entry(dan.device_id))
    ss, ct = xwing.encapsulate(b64u_decode(entry["kem_pk"]))
    aad = canon({"device_id": dan.device_id, "suite": "QG-1", "to_user_id": dan.user_id})
    env1 = {"ciphertext": b64u(b"\x00" * 12 + aead.gcm_encrypt(kdf.message_key(ss), b"\x00" * 12, b"x", aad)),
            "device_id": dan.device_id, "xwing_ct": b64u(ct)}
    other = dict(env1, ciphertext=b64u(b"\x01" * 40))
    sig = aiko.state.keys.sig.sign(statement(dan.user_id, digests_for([other])), "message")
    r = aiko.raw_request("POST", "/api/v1/messages", body=json.dumps(
        {"to_user_id": dan.user_id, "envelopes": [env1], "signature": b64u(sig)}).encode())
    assert r.status_code == 400 and r.json()["error"]["code"] == "QG_BAD_SIGNATURE"
    with pytest.raises(ApiError):
        aiko.call("POST", "/api/v1/messages", {"to_user_id": dan.user_id, "envelopes": [env1], "signature": b64u(sig)})
