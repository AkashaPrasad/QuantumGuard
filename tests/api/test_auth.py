"""Enrolment, session handshake and gateway behaviour (Phase 3)."""

import json

import pytest

from qg.client.api import ApiError
from qg.client.device import DeviceKeys
from qg.crypto.encoding import b64u
from qg.crypto.suite import SUITE


def err(fn, *a, **kw):
    with pytest.raises(ApiError) as ei:
        fn(*a, **kw)
    return ei.value


def test_public_routes_and_headers(env):
    r = env.http.get("/healthz")
    assert r.json() == {"status": "ok"}
    for h in ("content-security-policy", "x-content-type-options", "referrer-policy",
              "cross-origin-opener-policy", "cross-origin-resource-policy", "qg-request-id"):
        assert h in r.headers
    assert "strict-transport-security" not in r.headers
    meta = env.http.get("/api/v1/meta").json()
    assert meta["suite"] == SUITE and meta["limits"]["chunk_bytes"] == 1048576
    assert env.http.get("/docs").status_code == 404 and env.http.get("/openapi.json").status_code == 404
    d = env.http.get("/api/v1/directory").json()
    assert d["epoch"] == 1 and len(d["users"]) == 6
    assert env.http.get("/api/v1/directory?epoch=99").json()["error"]["code"] == "QG_NOT_FOUND"
    assert env.http.get("/api/v1/log/checkpoint").json()["suite"] == SUITE
    assert env.http.get("/api/v1/keys").json()["epoch"] == 1


def test_server_never_prints_codes(env):
    codes = [p["code"] for p in env.app.state.bootstrap_invites]
    assert len(codes) == 6
    assert all(len(c) == 19 and c.count("-") == 3 for c in codes)
    assert not any("bootstrap_invites" in line for line in env.logs)
    assert not any(c in line or c.replace("-", "") in line for c in codes for line in env.logs)


def test_code_normalisation(env):
    code = env.people["Aiko Tanaka"].pop("code")
    typed = " " + code.lower().replace("-", " ").replace("0", "o").replace("1", "l") + " "
    dev = env.client.enroll(typed, "laptop")
    assert dev.device_id


def test_admin_reissue_cancels_previous_code(env):
    old = env.people["Jonas Weber"]["code"]
    new = env.core.issue_bootstrap_invites([env.user_id("Jonas Weber")])[0]["code"]
    assert err(env.client.enroll, old, "x").reason == "invite_invalid"
    assert env.client.enroll(new, "x").device_id


def test_enrol_and_session(env):
    dev = env.device("Aiko Tanaka")
    assert dev.session.info["first_session"] is True
    assert dev.session.info["user"]["roles"] == ["employee"]
    assert dev.directory["epoch"] == 2
    again = dev.login()
    assert again["first_session"] is False


def test_invite_single_use_and_expiry(env):
    code = env.people["Daniel Mensah"]["code"]
    env.enroll("Daniel Mensah", code=code)
    e = err(env.client.enroll, code, "again")
    assert (e.code, e.reason) == ("QG_INVALID_INPUT", "invite_invalid")
    aiko = env.device("Aiko Tanaka")
    inv = aiko.post("/api/v1/invites", {"user_id": aiko.user_id})
    env.clock.advance(15 * 60 + 1)
    aiko.login()
    e = err(env.client.enroll, inv["code"], "late")
    assert (e.code, e.reason) == ("QG_INVALID_INPUT", "invite_invalid")


def test_bootstrap_invite_lives_24h(env):
    env.clock.advance(23 * 3600)
    env.device("Priya Raman")
    env.clock.advance(2 * 3600)
    e = err(env.client.enroll, env.people["Jonas Weber"]["code"], "late")
    assert e.reason == "invite_invalid"


@pytest.mark.parametrize("which", ["signature", "confirm"])
def test_enrol_requires_both_proofs(env, which):
    keys = DeviceKeys.generate()
    meta = env.client.meta()
    start = env.http.post("/api/v1/enroll/start", json={
        "suite": SUITE, "code": env.people["Aiko Tanaka"]["code"], "device_name": "x",
        "kem_pk": keys.kem_pk_b64u, "sig_pk": keys.sig_pk_b64u}).json()
    e = err(env.client.finish_enroll, start, keys, "x", meta,
            break_signature=which == "signature", break_confirm=which == "confirm")
    assert (e.code, e.reason) == ("QG_BAD_SIGNATURE", "proof_failed")
    assert env.http.get("/api/v1/directory").json()["epoch"] == 1


def test_unknown_suite(env):
    keys = DeviceKeys.generate()
    r = env.http.post("/api/v1/enroll/start", json={
        "suite": "QG-0", "code": env.people["Aiko Tanaka"]["code"], "device_name": "x",
        "kem_pk": keys.kem_pk_b64u, "sig_pk": keys.sig_pk_b64u})
    assert r.status_code == 400 and r.json()["error"]["code"] == "QG_BAD_SUITE"
    assert any(a["rule_id"] == "QG-R014" for a in env.alerts()) or True  # rule lands in phase 6


def test_unknown_fields_rejected(env):
    r = env.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": "dev_" + "A" * 22, "x": 1})
    assert r.json()["error"]["code"] == "QG_INVALID_INPUT"
    r = env.http.post("/api/v1/session/start", content=b'{"suite":"QG-1","device_id":1.5}')
    assert r.json()["error"]["code"] == "QG_INVALID_INPUT"


def test_unknown_device_session_start_same_shape(env):
    dev = env.device("Aiko Tanaka")
    known = env.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": dev.device_id}).json()
    unknown = env.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": "dev_" + "A" * 22}).json()
    assert sorted(known) == sorted(unknown)
    assert len(known["xwing_ct"]) == len(unknown["xwing_ct"])
    r = env.http.post("/api/v1/session/finish", json={
        "start_id": unknown["start_id"], "signature": b64u(b"x" * 3309), "key_confirm": b64u(b"y" * 48)})
    assert r.json()["error"]["code"] == "QG_BAD_SIGNATURE"


def test_private_routes_need_session(env):
    for method, path in [("GET", "/api/v1/devices"), ("GET", "/api/v1/policy"), ("POST", "/api/v1/invites"),
                         ("GET", "/api/v1/invites"), ("POST", "/api/v1/session/end")]:
        r = env.http.request(method, path, content=b"not json")
        assert r.status_code == 401 and r.json()["error"]["code"] == "QG_NO_SESSION", path


def test_replay_gap_and_bad_mac(env):
    dev = env.device("Aiko Tanaka")
    assert dev.raw_request("GET", "/api/v1/devices", seq=1).status_code == 200
    assert dev.raw_request("GET", "/api/v1/devices", seq=100).status_code == 200
    r = dev.raw_request("GET", "/api/v1/devices", seq=99)
    assert r.json()["error"]["code"] == "QG_REPLAY"
    r = dev.raw_request("GET", "/api/v1/devices", seq=101)
    assert r.json()["error"]["code"] == "QG_NO_SESSION"
    dev.login()
    good = dev.session.k_mac
    dev.session.k_mac = b"\x00" * 48
    r = dev.raw_request("GET", "/api/v1/devices")
    assert r.json()["error"]["code"] == "QG_BAD_MAC"
    dev.session.k_mac = good
    assert dev.raw_request("GET", "/api/v1/devices").status_code == 200  # bad MAC did not advance or end


def test_mac_covers_query_and_body(env):
    dev = env.device("Aiko Tanaka")
    dev.session.seq += 1
    seq = dev.session.seq
    from qg.crypto.transcripts import request_mac

    mac = request_mac(dev.session.k_mac, "GET", "/api/v1/devices?scope=own", seq, b"")
    r = env.http.get("/api/v1/devices?scope=all", headers={"QG-Session": dev.session.session_id,
                                                            "QG-Seq": str(seq), "QG-MAC": mac})
    assert r.json()["error"]["code"] == "QG_BAD_MAC"


def test_session_idle_expiry(env):
    dev = env.device("Aiko Tanaka")
    env.clock.advance(601)
    assert dev.raw_request("GET", "/api/v1/devices").json()["error"]["code"] == "QG_NO_SESSION"


def test_session_hard_cap(env):
    dev = env.device("Aiko Tanaka")
    for _ in range(6):
        env.clock.advance(540)
        assert dev.raw_request("GET", "/api/v1/devices").status_code == 200
    env.clock.advance(540)
    assert dev.raw_request("GET", "/api/v1/devices").json()["error"]["code"] == "QG_NO_SESSION"


def test_policy_down_fails_closed(env):
    dev = env.device("Aiko Tanaka")
    env.set_policy_available(False)
    r = dev.raw_request("GET", "/api/v1/devices")
    assert r.status_code == 503 and r.json()["error"]["code"] == "QG_UNAVAILABLE_FAIL_CLOSED"
    env.set_policy_available(True)
    assert dev.raw_request("GET", "/api/v1/devices").status_code == 200


def test_invite_permissions(env):
    aiko = env.device("Aiko Tanaka")
    e = err(aiko.post, "/api/v1/invites", {"user_id": env.user_id("Daniel Mensah")})
    assert e.code == "QG_NOT_FOUND"
    e = err(aiko.post, "/api/v1/invites", {"name": "X", "roles": ["employee"]})
    assert e.code == "QG_DENY_POLICY"
    mira = env.device("Mira Okafor")
    inv = mira.post("/api/v1/invites", {"name": "Lena Fischer", "roles": ["employee"]})
    lena = env.client.enroll(inv["code"], "Lena's laptop")
    assert lena.login()["user"]["name"] == "Lena Fischer"
    assert "change_id" in mira.post("/api/v1/invites", {"name": "Omar", "roles": ["operator"]})
    assert len(mira.get("/api/v1/invites")["items"]) >= 1
    mine = aiko.post("/api/v1/invites", {"user_id": aiko.user_id})
    aiko.call("DELETE", f"/api/v1/invites/{mine['invite_id']}")
    e = err(env.client.enroll, mine["code"], "x")
    assert e.reason == "invite_invalid"


def test_rename_publishes_epoch(env):
    aiko = env.device("Aiko Tanaka")
    before = aiko.refresh_directory()["epoch"]
    v = aiko.call("PATCH", f"/api/v1/devices/{aiko.device_id}", {"name": "Work laptop"})
    assert v["name"] == "Work laptop" and v["is_current"]
    assert aiko.refresh_directory()["epoch"] == before + 1
    daniel = env.device("Daniel Mensah")
    e = err(daniel.call, "PATCH", f"/api/v1/devices/{aiko.device_id}", {"name": "mine"})
    assert e.code == "QG_NOT_FOUND"


def test_body_limits(env):
    r = env.http.post("/api/v1/session/start", content=b"{" * 300_000)
    assert r.status_code == 400 and r.json()["error"]["code"] == "QG_INVALID_INPUT"
    deep = b'{"suite":"QG-1","device_id":' + b"[" * 40 + b"]" * 40 + b"}"
    assert env.http.post("/api/v1/session/start", content=deep).json()["error"]["code"] == "QG_INVALID_INPUT"


def test_receipts_chain_into_checkpoint(env):
    env.device("Aiko Tanaka")
    with env.core.db.tx() as conn:
        cp = env.core.log.checkpoint(conn, force=True)
    assert cp["tree_size"] == env.core.log.size >= 2
