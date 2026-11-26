"""CLI tests: a real server process, `main([...])` called in-process."""

from __future__ import annotations

import json
import warnings

import pytest

from qg.client.cli import main
from qg.scenarios.harness import Server

warnings.filterwarnings("ignore", category=DeprecationWarning)


@pytest.fixture
def server():
    s = Server().start()
    yield s
    s.close()


@pytest.fixture(autouse=True)
def _pass(monkeypatch):
    monkeypatch.setenv("QG_PASSPHRASE", "correct horse battery staple")


class Cli:
    def __init__(self, capsys):
        self.capsys = capsys

    def run(self, *argv, expect=0):
        self.capsys.readouterr()
        rc = main([str(a) for a in argv])
        cap = self.capsys.readouterr()
        assert rc == expect, cap.err or cap.out
        return cap

    def json(self, *argv, expect=0):
        cap = self.run(*argv, "--json", expect=expect)
        return json.loads(cap.out)


@pytest.fixture
def cli(capsys):
    return Cli(capsys)


def enroll(cli, server, tmp_path, person, label, via_keygen=False):
    ks = tmp_path / f"{label}.qgkeystore"
    if via_keygen:
        cli.run("keygen", "--keystore", ks, "--device-name", label)
    out = cli.json("enroll", "--server", server.url, "--code", server.code(person), "--device-name", label,
                   "--keystore", ks)
    return ks, out


def test_keygen_enroll_whoami(cli, server, tmp_path):
    ks, out = enroll(cli, server, tmp_path, "Aiko Tanaka", "aiko-a", via_keygen=True)
    assert out["device_id"].startswith("dev_") and out["user_id"]
    info = cli.json("whoami", "--keystore", ks)
    assert json.dumps(info).count(out["device_id"]) >= 1
    assert (ks.stat().st_mode & 0o777) == 0o600


def test_protect_open_roundtrip(cli, server, tmp_path):
    ks, _ = enroll(cli, server, tmp_path, "Aiko Tanaka", "aiko-p")
    src = tmp_path / "plain.bin"
    payload = bytes(range(256)) * 50
    src.write_bytes(payload)
    res = cli.json("protect", src, "--keystore", ks)
    out = tmp_path / "out.bin"
    cli.run("open", res["file_id"], "--out", out, "--keystore", ks)
    assert out.read_bytes() == payload
    assert (out.stat().st_mode & 0o777) == 0o600
    cli.run("open", res["file_id"], "--out", out, "--keystore", ks, expect=1)
    cli.run("open", res["file_id"], "--out", out, "--force", "--keystore", ks)
    files = cli.json("files", "--keystore", ks)["files"]
    assert any(f["file_id"] == res["file_id"] for f in files)


def test_share_then_open(cli, server, tmp_path):
    a, _ = enroll(cli, server, tmp_path, "Aiko Tanaka", "aiko-s")
    d, dout = enroll(cli, server, tmp_path, "Daniel Mensah", "daniel-s")
    src = tmp_path / "s.txt"
    src.write_bytes(b"shared secret contents")
    res = cli.json("protect", src, "--keystore", a)
    cli.run("open", res["file_id"], "--out", tmp_path / "x", "--keystore", d, expect=1)
    cli.run("share", res["file_id"], "--to", dout["device_id"], "--keystore", a)
    cli.run("open", res["file_id"], "--out", tmp_path / "y", "--keystore", d)
    assert (tmp_path / "y").read_bytes() == b"shared secret contents"


def test_report_lost_bundle_verify_selftest(cli, server, tmp_path):
    lost, lout = enroll(cli, server, tmp_path, "Jonas Weber", "jonas-lost")
    other, _ = enroll(cli, server, tmp_path, "Jonas Weber", "jonas-other")
    res = cli.json("report-lost", lout["device_id"], "--note", "left on a train", "--keystore", other)
    assert res["incident_id"] and res["receipt_id"]
    cap = cli.run("whoami", "--keystore", lost, expect=1)
    assert "QG_" in cap.err and "Traceback" not in cap.err

    priya, _ = enroll(cli, server, tmp_path, "Priya Raman", "priya")
    bundle = tmp_path / "bundle.json"
    cli.run("export-bundle", res["incident_id"], "--out", bundle, "--keystore", priya)
    cap = cli.run("verify", bundle)
    assert "not pinned" in cap.err
    assert cli.json("verify", bundle)["ok"] is True

    keys = tmp_path / "keys.json"
    cli.run("server-keys", "--server", server.url, "--out", keys)
    cap = cli.run("verify", bundle, "--keys", keys)
    assert "not pinned" not in cap.err
    assert cli.json("verify", bundle, "--keys", keys)["ok"] is True

    doc = json.loads(bundle.read_text())
    assert doc["entries"]
    receipt = doc["entries"][0]["receipt"]
    key = next(k for k, v in receipt.items() if isinstance(v, str) and len(v) > 2 and k != "leaf_index")
    v = receipt[key]
    receipt[key] = v[:-1] + ("A" if v[-1] != "A" else "B")
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(doc))
    result = cli.json("verify", bad, expect=1)
    assert result["ok"] is False and result["failed_step"] == "entries"
    assert result["first_bad_index"] == doc["entries"][0]["leaf_index"]
    cap = cli.run("verify", bad, expect=1)
    assert "[FAIL]" in cap.out


def test_selftest(cli):
    res = cli.json("selftest")
    assert res["selftest"] == "pass" and len(res["checks"]) >= 6
    assert all(c["ok"] for c in res["checks"])
    cli.run("selftest")
