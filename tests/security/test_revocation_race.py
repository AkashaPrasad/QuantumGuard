"""Slot requests from several sessions of a device race its revocation. Ordering is taken from the
transaction-ordered evidence log (receipt leaf index), never from wall-clock request start times."""

from __future__ import annotations

import os
import threading

from fastapi.testclient import TestClient

from qg.client.api import Device
from qgsec import count, q

WORKERS = 6
PER_WORKER = 45  # stays under the per-session burst so rate limiting does not mask the race


def test_revoked_device_gets_no_slot_under_concurrent_release(env):
    laptop = env.device("Aiko Tanaka")
    phone = env.second_device("Aiko Tanaka", "Aiko's phone")
    fid = laptop.protect("race.bin", os.urandom(4096), "confidential", [phone.device_id])["file"]["file_id"]
    assert laptop.open(fid)

    sessions = []
    for _ in range(WORKERS):
        d = Device(TestClient(env.app, base_url="http://testserver"), laptop.state)
        d.login()
        sessions.append(d)

    results: list[dict] = []
    lock = threading.Lock()
    go, revoked = threading.Event(), threading.Event()

    def worker(dev):
        go.wait()
        for _ in range(PER_WORKER):
            after_return = revoked.is_set()  # this request was sent after the revoke response returned
            r = dev.raw_request("GET", f"/api/v1/files/{fid}/slot")
            with lock:
                results.append({"status": r.status_code, "receipt": r.headers.get("QG-Receipt"),
                                "key": r.status_code == 200 and "inner_wrap" in r.text, "after_return": after_return})

    threads = [threading.Thread(target=worker, args=(d,)) for d in sessions]
    for t in threads:
        t.start()
    go.set()
    while True:
        with lock:
            if len(results) >= 25:
                break
    rr = phone.post(f"/api/v1/devices/{laptop.device_id}/report-lost", {"lost_at": env.clock.iso()})
    revoked.set()
    for t in threads:
        t.join(120)

    revoke_index = q(env, "SELECT leaf_index FROM receipts WHERE id = ?", (rr["receipt_id"],))[0][0]
    released = [r for r in results if r["key"]]
    after = [r for r in results if r["after_return"]]
    assert len(results) == WORKERS * PER_WORKER
    assert released, "the race must include releases before the revocation"
    assert after, "the race must include requests sent after the revocation returned"
    for r in released:
        assert q(env, "SELECT leaf_index FROM receipts WHERE id = ?", (r["receipt"],))[0][0] < revoke_index
    for r in after:
        assert r["status"] in (401, 403) and r["key"] is False
    assert count(env, "SELECT COUNT(*) FROM receipts WHERE action = 'slot.release' AND decision = 'allow'"
                      " AND device_id = ? AND leaf_index > ?", (laptop.device_id, revoke_index)) == 0
    assert count(env, "SELECT COUNT(*) FROM sessions WHERE device_id = ?", (laptop.device_id,)) == 0
    assert count(env, "SELECT COUNT(*) FROM slots WHERE device_id = ?", (laptop.device_id,)) == 0
    assert phone.open(fid)
