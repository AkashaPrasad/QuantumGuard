"""Objective 2, security control: a device is reported lost with a loss time in the past. Measures time to
enforce, lists exposed / held / never-released files, shows the lost device is denied (QG-R001), re-keys
every affected file from a remaining device, and reports the forced checkpoint."""

from __future__ import annotations

import os
import time

from qg.client import ApiError, QGClient
from qg.clock import fmt
from qg.scenarios.harness import Server, result


def run() -> int:
    srv = Server().start()
    try:
        client = QGClient(srv.url)
        laptop = client.enroll(srv.code("Aiko Tanaka"), "Aiko's laptop")
        laptop.login()
        inv = laptop.post("/api/v1/invites", {"user_id": laptop.user_id})
        phone = client.enroll(inv["code"], "Aiko's phone")
        phone.login()
        daniel = client.enroll(srv.code("Daniel Mensah"), "Daniel's laptop")
        daniel.login()

        others = [phone.device_id, daniel.device_id]
        files = {
            "held": laptop.protect("cell-line-inventory.xlsx", os.urandom(300_000), "restricted", others),
            "exposed": laptop.protect("trial-protocol.pdf", os.urandom(1_200_000), "confidential", others),
            "never": laptop.protect("budget-notes.txt", os.urandom(2_000), "internal", [phone.device_id]),
        }
        ids = {k: v["file"]["file_id"] for k, v in files.items()}
        laptop.open(ids["held"])                 # released before the loss time
        time.sleep(0.05)
        from datetime import UTC, datetime

        lost_at = fmt(datetime.now(UTC))
        time.sleep(0.05)
        laptop.open(ids["exposed"])              # released after the loss time

        rr = phone.post(f"/api/v1/devices/{laptop.device_id}/report-lost",
                        {"lost_at": lost_at, "note": "Left on a train"})
        incident = rr["incident_id"]

        denied = []
        for attempt in (lambda: laptop.slot(ids["exposed"]), laptop.login):
            try:
                attempt()
                denied.append(False)
            except ApiError as e:
                denied.append(e.code == "QG_DENY_REVOKED")
        deadline = time.monotonic() + 3
        alerts = []
        while time.monotonic() < deadline and not alerts:
            alerts = [a for a in srv.events("alert") if a.get("rule_id") == "QG-R001"]
            time.sleep(0.05)

        exposure = phone.get(f"/api/v1/incidents/{incident}/exposure")
        groups = {k: sorted(f["file_id"] for f in exposure[k]) for k in ("exposed", "held", "never_released")}
        classified = (groups["exposed"] == [ids["exposed"]] and groups["held"] == [ids["held"]]
                      and groups["never_released"] == [ids["never"]])
        pending = phone.rekey_pending()["rekeys"]
        order_ok = [p["reason"] for p in pending] == ["exposed", "held"]
        phone.rekey_all()
        inc = phone.get(f"/api/v1/incidents/{incident}")
        daniel_ok = all(len(daniel.open(ids[k])) > 0 for k in ("held", "exposed"))
        ok = (all(denied) and bool(alerts) and classified and order_ok and inc["status"] == "contained"
              and daniel_ok and inc["denied_attempts"] >= 2)
        return result(
            "revoke", ok,
            time_to_enforce_ms=rr["time_to_enforce_ms"],
            exposed=len(groups["exposed"]), held=len(groups["held"]), never_released=len(groups["never_released"]),
            denied_after_revoke=all(denied), alert_rule=alerts[0]["rule_id"] if alerts else None,
            receipt_id=rr["receipt_id"], checkpoint_root=rr["checkpoint"]["root_hash"],
            sessions_ended=rr["sessions_ended"], slots_deleted=rr["slots_deleted"],
            incident_status=inc["status"], rekey_order=[p["reason"] for p in pending],
        )
    finally:
        srv.close()
