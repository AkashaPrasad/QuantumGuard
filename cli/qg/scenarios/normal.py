"""Objective 1, normal operation: an admin invites a new person, the person enrols a device, signs in,
protects a file and opens it again; every step is allowed by policy and leaves a receipt."""

from __future__ import annotations

import os

from qg.client import QGClient
from qg.scenarios.harness import Server, result


def run() -> int:
    srv = Server().start()
    try:
        client = QGClient(srv.url)
        admin = client.enroll(srv.code("Mira Okafor"), "Mira's laptop")
        admin.login()
        inv = admin.post("/api/v1/invites", {"name": "Lena Fischer", "roles": ["employee"]})
        lena = client.enroll(inv["code"], "Lena's laptop")
        session = lena.login()
        steps = {"invite": bool(inv["invite_id"]), "enrol": bool(lena.device_id), "session": bool(session["session_id"])}
        receipt_id = None
        try:
            data = os.urandom(150_000)
            committed = lena.protect("assay-results.csv", data, "confidential")
            opened = lena.open(committed["file"]["file_id"])
            steps["protect"] = True
            steps["open"] = opened == data
            receipt_id = committed["receipt_id"]
        except Exception:  # noqa: BLE001 - files arrive in phase 4
            steps["protect"] = False
        if receipt_id is None:
            r = lena.raw_request("POST", "/api/v1/invites", body=b'{"user_id":"' + lena.user_id.encode() + b'"}')
            receipt_id = r.headers.get("QG-Receipt") if r.status_code == 200 else None
            steps["policy_allow"] = receipt_id is not None
        receipt = lena.get(f"/api/v1/log/receipts/{receipt_id}") if steps.get("open") else None
        ok = all(steps.values()) and receipt_id is not None
        return result("normal", ok, steps=steps, receipt_id=receipt_id,
                      decision=(receipt or {}).get("decision", "allow" if receipt_id else None))
    finally:
        srv.close()
