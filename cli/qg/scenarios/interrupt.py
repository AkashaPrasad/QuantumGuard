"""Objective 3, reliability: kill the server in the middle of a re-key and restart it, replay duplicate
revoke requests, send malformed and oversized input, and take the policy engine down. The system recovers,
fails closed while policy is down, and never releases a key to the revoked device."""

from __future__ import annotations

import os
from datetime import UTC, datetime

import httpx

from qg.client import ApiError, QGClient
from qg.clock import fmt
from qg.crypto import aead
from qg.scenarios.harness import Server, result


def _status(fn) -> int:  # noqa: ANN001
    try:
        fn()
        return 200
    except ApiError as e:
        return e.status


def run() -> int:
    srv = Server().start()
    checks: dict[str, object] = {}
    try:
        client = QGClient(srv.url)
        laptop = client.enroll(srv.code("Aiko Tanaka"), "Aiko's laptop")
        laptop.login()
        phone = client.enroll(laptop.post("/api/v1/invites", {"user_id": laptop.user_id})["code"], "Aiko's phone")
        phone.login()
        daniel = client.enroll(srv.code("Daniel Mensah"), "Daniel's laptop")
        daniel.login()
        priya = client.enroll(srv.code("Priya Raman"), "Priya's workstation")
        priya.login()
        datas = {i: os.urandom(200_000 + i) for i in range(3)}
        fids = {i: laptop.protect(f"batch-{i}.dat", d, "confidential", [phone.device_id, daniel.device_id])["file"][
            "file_id"] for i, d in datas.items()}
        for f in fids.values():
            laptop.open(f)
        rr = phone.post(f"/api/v1/devices/{laptop.device_id}/report-lost", {"lost_at": fmt(datetime.now(UTC))})

        # 1. crash in the middle of a re-key: new version created and chunks uploaded, commit never sent
        item = phone.rekey_pending()["rekeys"][0]
        nv = phone.post(f"/api/v1/files/{item['file_id']}/versions",
                        {"reason": "rekey", "size_bytes": 10, "chunk_count": 1})["version"]
        blob = aead.encrypt_file(os.urandom(32), item["file_id"], nv, b"0123456789")[0]
        phone.raw_request("PUT", f"/api/v1/files/{item['file_id']}/versions/{nv}/chunks/0", body=blob,
                          content_type="application/octet-stream")
        srv.kill()
        srv.start()
        checks["restarted"] = True
        for d in (phone, daniel, priya):
            d.login()  # sessions live in memory only; a restart ends them
        pending = phone.rekey_pending()["rekeys"]
        checks["rekey_resumed"] = len(pending) == 3
        phone.rekey_all()
        inc = phone.get(f"/api/v1/incidents/{rr['incident_id']}")
        checks["contained_after_restart"] = inc["status"] == "contained"
        checks["data_intact"] = all(daniel.open(fids[i]) == datas[i] for i in datas)

        # 2. duplicate revoke events: same incident every time
        again = phone.post(f"/api/v1/devices/{laptop.device_id}/report-lost", {"lost_at": fmt(datetime.now(UTC))})
        op = priya.post(f"/api/v1/devices/{laptop.device_id}/revoke",
                        {"compromise_time": inc["compromise_time"], "reason": "duplicate drill"})
        checks["duplicate_revoke_same_incident"] = again["incident_id"] == op["incident_id"] == rr["incident_id"]

        # 3. malformed and oversized input
        raw = httpx.Client(base_url=srv.url, timeout=10)
        bad = [
            raw.post("/api/v1/session/start", content=b"{not json"),
            raw.post("/api/v1/session/start", content=b'{"suite":"QG-1","device_id":1.5}'),
            raw.post("/api/v1/enroll/start", content=b"[" * 5000),
            raw.post("/api/v1/session/start", content=b"x" * (3 * 1024 * 1024)),
            phone.raw_request("POST", "/api/v1/files", body=b'{"name":"x","classification":"secret"}'),
            phone.raw_request("PUT", f"/api/v1/files/{fids[0]}/versions/99/chunks/0", body=b"x" * (2 * 1024 * 1024)),
        ]
        checks["malformed_rejected"] = sum(1 for r in bad if r.status_code == 400)
        checks["healthy_after_malformed"] = raw.get("/healthz").status_code == 200

        # 4. policy engine down: nothing is released (fail closed), then recovery
        srv.admin("policy-down")
        checks["policy_down_status"] = _status(lambda: phone.slot(fids[0]))
        srv.admin("policy-up")
        checks["policy_up_status"] = _status(lambda: phone.slot(fids[0]))

        # 5. zero releases to the revoked device after the revocation
        checks["revoked_slot_status"] = _status(lambda: laptop.slot(fids[1]))
        revoke_receipt = priya.get(f"/api/v1/log/receipts/{rr['receipt_id']}")
        releases = priya.get(f"/api/v1/log/receipts?device_id={laptop.device_id}&action=slot.release&decision=allow"
                             "&limit=200")["items"]
        late = [r for r in releases if r["leaf_index"] > revoke_receipt["leaf_index"]]
        checks["releases_to_revoked_after_revoke"] = len(late)

        ok = (checks["rekey_resumed"] and checks["contained_after_restart"] and checks["data_intact"]
              and checks["duplicate_revoke_same_incident"] and checks["malformed_rejected"] == len(bad)
              and checks["healthy_after_malformed"] and checks["policy_down_status"] == 503
              and checks["policy_up_status"] == 200 and checks["revoked_slot_status"] in (401, 403) and not late)
        return result("interrupt", bool(ok), incident_id=rr["incident_id"], **checks)
    finally:
        srv.close()
