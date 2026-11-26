"""1,000 concurrent slot requests from a device race its revocation on a real server process.
Claim: no request receives key material after the revoke response returns, and every release that did
happen is ordered before the revocation in the transaction log (receipt leaf index)."""

import os
import sqlite3
import threading
import time
from pathlib import Path

import httpx

from qg.client import QGClient
from qg.clock import fmt
from qg.scenarios.harness import Server

TOTAL = 1000
SESSIONS = 8


def test_revoke_races_1000_slot_requests():
    srv = Server().start()
    try:
        http = httpx.Client(base_url=srv.url, timeout=30)
        client = QGClient(http)
        lost = client.enroll(srv.code("Aiko Tanaka"), "Aiko's laptop")
        lost.login()
        phone = client.enroll(lost.post("/api/v1/invites", {"user_id": lost.user_id})["code"], "phone")
        phone.login()
        fid = lost.protect("race.bin", os.urandom(4096), "confidential", [phone.device_id])["file"]["file_id"]

        sessions = []
        for _ in range(SESSIONS):
            d = client.device(lost.state)
            d.http = httpx.Client(base_url=srv.url, timeout=30)
            d.login()
            sessions.append(d)

        results: list[tuple[float, float, int, str | None, bool]] = []
        lock = threading.Lock()
        go = threading.Event()
        counter = iter(range(TOTAL))

        def worker(dev):
            go.wait()
            while True:
                with lock:
                    try:
                        next(counter)
                    except StopIteration:
                        return
                t0 = time.monotonic()
                r = dev.raw_request("GET", f"/api/v1/files/{fid}/slot")
                t1 = time.monotonic()
                key = r.status_code == 200 and "inner_wrap" in r.text
                with lock:
                    results.append((t0, t1, r.status_code, r.headers.get("QG-Receipt"), key))

        threads = [threading.Thread(target=worker, args=(d,)) for d in sessions]
        for t in threads:
            t.start()
        go.set()
        while len(results) < 150:
            time.sleep(0.005)
        revoke_sent = time.monotonic()
        from datetime import UTC, datetime

        rr = phone.post(f"/api/v1/devices/{lost.device_id}/report-lost", {"lost_at": fmt(datetime.now(UTC))})
        revoke_returned = time.monotonic()
        for t in threads:
            t.join(120)

        assert len(results) == TOTAL
        db = sqlite3.connect(f"file:{Path(srv.workdir) / 'data' / 'quantumguard.sqlite'}?mode=ro", uri=True)
        revoke_index = db.execute("SELECT leaf_index FROM receipts WHERE id = ?", (rr["receipt_id"],)).fetchone()[0]
        released = [r for r in results if r[4]]
        after_return = [r for r in results if r[0] > revoke_returned]
        assert released, "some releases must happen before the revoke"
        assert after_return, "some requests must start after the revoke returned"
        assert not any(r[4] for r in after_return), "key material released after the revoke response"
        for r in released:
            idx = db.execute("SELECT leaf_index FROM receipts WHERE id = ?", (r[3],)).fetchone()[0]
            assert idx < revoke_index, "a release was ordered after the revocation"
        late_releases = db.execute("SELECT COUNT(*) FROM receipts WHERE action = 'slot.release' AND decision = 'allow'"
                                   " AND device_id = ? AND leaf_index > ?", (lost.device_id, revoke_index)).fetchone()[0]
        assert late_releases == 0
        assert {r[2] for r in after_return} <= {401, 403}
        print(f"released={len(released)} after_return={len(after_return)} revoke_ms={rr['time_to_enforce_ms']}"
              f" window_ms={int((revoke_returned - revoke_sent) * 1000)}")
    finally:
        srv.close()
