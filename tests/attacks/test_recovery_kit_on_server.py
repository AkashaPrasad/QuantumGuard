"""Known finding (assigned before this review; one test only): the recovery private key is generated into
the server's keys volume (backend/qg/keys.py, `recovery-kit.json`) next to the seal master key. A copy of the
data volume plus the keys volume opens the recovery slot of every file without any recovery_release change,
so the two-approval control is not a cryptographic control against whoever holds the server volumes."""

from __future__ import annotations

import json
import shutil
import sqlite3

from qg.crypto import aead
from qg.crypto.encoding import b64u_decode
from qg.crypto.xwing import XWingPrivateKey


def test_server_volumes_alone_cannot_open_a_recovery_slot(env, tmp_path):
    aiko = env.device("Aiko Tanaka")
    data = b"restricted handover notes"
    fid = aiko.protect("handover.docx", data, "restricted")["file"]["file_id"]
    assert aiko.open(fid) == data

    copy = tmp_path / "volumes"
    shutil.copytree(env.root / "keys", copy / "keys")
    with env.core.db._lock:  # noqa: SLF001
        dst = sqlite3.connect(copy / "db.sqlite")
        env.core.db._conn.backup(dst)  # noqa: SLF001
        dst.close()
    shutil.copytree(env.root / "data" / "blobs", copy / "blobs")

    recovered = None
    server = json.loads((copy / "keys" / "server-keys.json").read_text())
    kit_path = copy / "keys" / "recovery-kit.json"
    kit = json.loads(kit_path.read_text()) if kit_path.exists() else {}
    if "kem_seed" in kit:
        con = sqlite3.connect(copy / "db.sqlite")
        slot_id, version, sealed, seal_epoch, wrap_epoch = con.execute(
            "SELECT slot_id, version, sealed, seal_epoch, wrap_epoch FROM slots WHERE file_id = ? AND device_id ="
            " 'recovery'", (fid,)).fetchone()
        con.close()
        inner = json.loads(aead.unseal(b64u_decode(server["seal_master"]), seal_epoch,
                                       aead.seal_aad(slot_id, fid, version, "recovery", seal_epoch), sealed))
        kem = XWingPrivateKey.from_seed(b64u_decode(kit["kem_seed"]))
        dek = aead.unwrap_dek(kem, inner, aead.wrap_binding(fid, version, "recovery", wrap_epoch))
        blob = (copy / "blobs" / fid / str(version) / "0").read_bytes()
        recovered = b"".join(aead.decrypt_chunks(dek, fid, version, [blob], 1))

    assert recovered is None, "the data and keys volumes alone decrypted a file through its recovery slot"
    assert env.core.db.one("SELECT COUNT(*) FROM changes")[0] == 0
