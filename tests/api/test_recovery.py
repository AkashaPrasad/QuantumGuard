"""Recovery kit: the server holds only its public key; the kit holder recovers a file only with an applied
two-approval recovery_release change."""

import json
import re
from pathlib import Path

import pytest

from qg.client.api import ApiError, ClientRefused
from qg.crypto import aead
from qg.crypto.encoding import EncodingError, b64u, b64u_decode
from qg.crypto.suite import RECOVERY_DEVICE_ID
from qg.crypto.xwing import XWingPrivateKey
from qg.keys import load_recovery_kit
from qg.testing import TestEnv


def _kit(env) -> XWingPrivateKey:
    return XWingPrivateKey.from_seed(b64u_decode(env.recovery_kit["kem_seed"]))


def _approved_release(env, file_id):
    mira, tomas, priya = env.device("Mira Okafor"), env.device("Tomas Lindqvist"), env.device("Priya Raman")
    change = mira.request_change("recovery_release", env.user_id("Aiko Tanaka"), file_id=file_id,
                                 reason="Aiko's devices were destroyed")
    assert change["approvals_required"] == 2 and change["status"] == "pending"
    return mira, tomas, priya, change


def test_recover_requires_two_approvals_then_opens(env):
    aiko = env.device("Aiko Tanaka")
    data = b"lab notebook " * 9000
    fid = aiko.protect("notebook.txt", data, "restricted")["file"]["file_id"]
    mira, tomas, priya, change = _approved_release(env, fid)
    e = pytest.raises(ApiError, mira.recover, fid, change["id"], _kit(env)).value
    assert (e.code, e.reason) == ("QG_DENY_POLICY", "approvals_incomplete") and e.receipt_id
    e = pytest.raises(ApiError, mira.approve_change, change).value
    assert (e.code, e.reason) == ("QG_DENY_POLICY", "self_approval")
    assert tomas.approve_change(change)["status"] == "pending"
    e = pytest.raises(ApiError, mira.recover, fid, change["id"], _kit(env)).value
    assert e.reason == "approvals_incomplete"
    assert priya.approve_change(change)["status"] == "applied"
    assert mira.recover(fid, change["id"], _kit(env)) == data
    e = pytest.raises(ApiError, mira.recover, fid, change["id"], _kit(env)).value
    assert (e.code, e.reason) == ("QG_CONFLICT", "already_used")


def test_wrong_kit_is_refused(env):
    aiko = env.device("Aiko Tanaka")
    fid = aiko.protect("plan.txt", b"plan", "confidential")["file"]["file_id"]
    mira, tomas, priya, change = _approved_release(env, fid)
    tomas.approve_change(change)
    priya.approve_change(change)
    with pytest.raises(ClientRefused):
        mira.recover(fid, change["id"], XWingPrivateKey.generate())


def test_non_admin_cannot_recover(env):
    aiko = env.device("Aiko Tanaka")
    fid = aiko.protect("plan.txt", b"plan", "confidential")["file"]["file_id"]
    mira, tomas, priya, change = _approved_release(env, fid)
    tomas.approve_change(change)
    priya.approve_change(change)
    e = pytest.raises(ApiError, env.device("Daniel Mensah").recover, fid, change["id"], _kit(env)).value
    assert e.code == "QG_DENY_POLICY"


def _volume_bytes(env) -> list[bytes]:
    root = env.root
    return [p.read_bytes() for d in (root / "data", root / "keys") for p in d.rglob("*") if p.is_file()]


def test_data_and_keys_volumes_together_cannot_open_a_recovery_slot(env):
    aiko = env.device("Aiko Tanaka")
    fid = aiko.protect("formula.txt", b"secret formula", "restricted")["file"]["file_id"]
    seed = b64u_decode(env.recovery_kit["kem_seed"])
    blobs = _volume_bytes(env)
    for form in (seed, b64u(seed).encode(), seed.hex().encode()):
        assert not any(form in b for b in blobs), "recovery private key found in a server volume"
    # An attacker with both volumes can unseal the recovery slot (the seal master is in keys/) ...
    with env.core.db.tx() as conn:
        slot = conn.execute("SELECT * FROM slots WHERE file_id = ? AND device_id = ?",
                            (fid, RECOVERY_DEVICE_ID)).fetchone()
    inner = json.loads(aead.unseal(env.core.keys.seal_master, slot["seal_epoch"],
                                   aead.seal_aad(slot["slot_id"], fid, slot["version"], RECOVERY_DEVICE_ID,
                                                 slot["seal_epoch"]), bytes(slot["sealed"])))
    binding = aead.wrap_binding(fid, slot["version"], RECOVERY_DEVICE_ID, slot["wrap_epoch"])
    # ... but no 32-byte value stored anywhere in either volume opens the inner wrap.
    candidates = set()
    for b in blobs:
        for tok in re.findall(rb"[A-Za-z0-9_-]{43}", b):
            try:
                candidates.add(b64u_decode(tok.decode()))
            except EncodingError:
                pass
        candidates.update(bytes.fromhex(h.decode()) for h in re.findall(rb"\b[0-9a-f]{64}\b", b))
    assert len(candidates) > 10
    for c in candidates:
        with pytest.raises(aead.AeadError):
            aead.unwrap_dek(XWingPrivateKey.from_seed(c), inner, binding)


def test_server_without_kit_then_admin_issues_it(tmp_path, monkeypatch, capsys):
    from qg import admin
    from qg.testing import create_test_app

    app = create_test_app(data_dir=tmp_path / "data", keys_dir=tmp_path / "keys", recovery_kit=False)
    from fastapi.testclient import TestClient

    from qg.client import QGClient

    http = TestClient(app)
    assert http.get("/api/v1/meta").json()["recovery_pk"] is None
    assert http.get("/api/v1/directory").json()["recovery_pk"] is None
    people = {p["name"]: p for p in app.state.bootstrap_invites}
    aiko = QGClient(http).enroll(people["Aiko Tanaka"]["code"], "laptop")
    aiko.login()
    before = aiko.protect("early.txt", b"before the kit", "internal")["file"]["file_id"]

    monkeypatch.setenv("QG_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("QG_KEYS_DIR", str(tmp_path / "keys"))
    assert admin.main(["recovery-kit", "init", "--out", str(tmp_path / "keys" / "kit.json")]) == 1  # inside a volume
    out = tmp_path / "operator" / "kit.json"
    out.parent.mkdir()
    assert admin.main(["recovery-kit", "init", "--out", str(out)]) == 0
    kit = load_recovery_kit(out)
    assert oct(out.stat().st_mode & 0o777) == "0o600"
    assert admin.main(["recovery-kit", "init", "--out", str(tmp_path / "operator" / "again.json")]) == 1
    assert not (tmp_path / "operator" / "again.json").exists()
    capsys.readouterr()

    meta = http.get("/api/v1/meta").json()
    assert meta["recovery_pk"] == b64u(kit.public_key)  # the running server picked it up
    assert http.get("/api/v1/directory").json()["recovery_pk"] == meta["recovery_pk"]
    after = aiko.protect("later.txt", b"after the kit", "internal")["file"]["file_id"]
    with app.state.core.db.tx() as conn:
        rec = {r[0] for r in conn.execute("SELECT file_id FROM slots WHERE device_id = ?", (RECOVERY_DEVICE_ID,))}
    assert after in rec and before not in rec
    assert not any(b64u(kit.seed).encode() in p.read_bytes()
                   for d in (tmp_path / "data", tmp_path / "keys") for p in Path(d).rglob("*") if p.is_file())


def test_kit_to_stdout(tmp_path, monkeypatch, capsys):
    from qg import admin

    monkeypatch.setenv("QG_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("QG_KEYS_DIR", str(tmp_path / "keys"))
    assert admin.main(["recovery-kit", "init"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["format"] == "qg-recovery-kit/1" and printed["kem_seed"]
    assert not any(printed["kem_seed"].encode() in p.read_bytes() for p in (tmp_path / "keys").rglob("*") if p.is_file())


@pytest.fixture
def env(tmp_path):
    e = TestEnv(tmp_path)
    yield e
    e.close()
