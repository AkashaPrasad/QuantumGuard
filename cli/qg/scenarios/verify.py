"""Objective 4, verifiable outcome: verify one decision's receipt offline with only public keys; export the
incident's proof bundle and verify it with `qg verify`; then flip one byte in the server's stored log and
show the verifier reports the first bad leaf index."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from qg.client import QGClient
from qg.clock import fmt
from qg.crypto.encoding import b64u_decode, canon
from qg.crypto.sign import verify_dual
from qg.log import merkle
from qg.scenarios.harness import Server, result


def _qg_verify(bundle: Path, keys: Path, env: dict[str, str]) -> tuple[int, dict]:
    out = subprocess.run([sys.executable, "-m", "qg.client", "verify", str(bundle), "--keys", str(keys), "--json"],
                         capture_output=True, text=True, timeout=60, env=env, check=False)
    return out.returncode, json.loads(out.stdout or "{}")


def run() -> int:
    srv = Server().start()
    work = Path(tempfile.mkdtemp(prefix="qg-verify-"))
    try:
        client = QGClient(srv.url)
        meta = client.meta()
        keys_file = work / "server-keys.json"
        keys_file.write_text(json.dumps(meta["server_keys"]))
        ed, pq = b64u_decode(meta["server_keys"]["ed25519_pk"]), b64u_decode(meta["server_keys"]["mldsa_pk"])

        laptop = client.enroll(srv.code("Aiko Tanaka"), "Aiko's laptop")
        laptop.login()
        phone = client.enroll(laptop.post("/api/v1/invites", {"user_id": laptop.user_id})["code"], "Aiko's phone")
        phone.login()
        priya = client.enroll(srv.code("Priya Raman"), "Priya's workstation")
        priya.login()
        fid = laptop.protect("sequencing-run.fastq", os.urandom(50_000), "restricted", [phone.device_id])["file"][
            "file_id"]

        # 1. one decision, verified offline: receipt -> inclusion proof -> dual-signed checkpoint
        resp = laptop.raw_request("GET", f"/api/v1/files/{fid}/slot")
        request_receipt = resp.headers["QG-Receipt"]
        receipt = laptop.get(f"/api/v1/log/receipts/{request_receipt}")
        proof = laptop.get(f"/api/v1/log/proof/{receipt['leaf_index']}")
        cp = proof["checkpoint"]
        leaf_ok = merkle.leaf_hash(canon(receipt)) == b64u_decode(proof["leaf_hash"])
        incl_ok = merkle.verify_inclusion(receipt["leaf_index"], cp["tree_size"], b64u_decode(proof["leaf_hash"]),
                                          [b64u_decode(p) for p in proof["audit_path"]], b64u_decode(cp["root_hash"]))
        receipt_verified = leaf_ok and incl_ok and verify_dual(cp, "checkpoint", ed, pq)

        # 2. incident proof bundle, verified offline by the qg CLI with pinned keys
        rr = phone.post(f"/api/v1/devices/{laptop.device_id}/report-lost", {"lost_at": fmt(datetime.now(UTC))})
        laptop.raw_request("GET", f"/api/v1/files/{fid}/slot")  # denied attempt
        bundle = priya.get(f"/api/v1/incidents/{rr['incident_id']}/bundle")
        good = work / "bundle.json"
        good.write_text(json.dumps(bundle, indent=2, sort_keys=True))
        env = dict(srv.env)
        rc_good, res_good = _qg_verify(good, keys_file, env)

        # 3. flip one byte of one stored receipt in the server's database, then export again
        db_path = Path(srv.workdir) / "data" / "quantumguard.sqlite"
        target = receipt["leaf_index"]
        db = sqlite3.connect(str(db_path), timeout=30)
        leaf = bytearray(db.execute("SELECT leaf FROM receipts WHERE leaf_index = ?", (target,)).fetchone()[0])
        pos = leaf.index(b'"reason_code":"') + len(b'"reason_code":"')
        leaf[pos] ^= 0x01
        db.execute("UPDATE receipts SET leaf = ? WHERE leaf_index = ?", (bytes(leaf), target))
        db.commit()
        db.close()
        tampered = work / "bundle-after-tamper.json"
        tampered.write_text(json.dumps(priya.get(f"/api/v1/incidents/{rr['incident_id']}/bundle"), indent=2))
        rc_bad, res_bad = _qg_verify(tampered, keys_file, env)

        ok = (receipt_verified and rc_good == 0 and res_good.get("ok") is True and rc_bad == 1
              and res_bad.get("first_bad_index") == target)
        return result("verify", ok, request_receipt_id=request_receipt, receipt_verified=receipt_verified,
                      leaf_index=receipt["leaf_index"], checkpoint_root=cp["root_hash"], tree_size=cp["tree_size"],
                      bundle_entries=len(bundle["entries"]), bundle_verified=rc_good == 0,
                      tampered_index=target, first_bad_index=res_bad.get("first_bad_index"),
                      failed_step=res_bad.get("failed_step"))
    finally:
        srv.close()
