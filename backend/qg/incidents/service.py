"""Revocation (one transaction), blast radius, re-key journal and incident views (spec/API.md section 7)."""

from __future__ import annotations

import json
import sqlite3
import time
from typing import TYPE_CHECKING, Any

from qg.clock import parse
from qg.ids import new_id

if TYPE_CHECKING:
    from qg.core import Core


def timeline(core: Core, conn: sqlite3.Connection, incident_id: str, step: str, receipt_id: str | None,
             detail: str) -> None:
    conn.execute("INSERT INTO incident_timeline (incident_id, step, ts, receipt_id, detail) VALUES (?,?,?,?,?)",
                 (incident_id, step, core.clock.iso(), receipt_id, detail))


def queue_rekey(core: Core, conn: sqlite3.Connection, file_id: str, from_version: int, reason: str,
                incident_id: str | None) -> None:
    now = core.clock.iso()
    existing = conn.execute("SELECT reason, status FROM rekey_jobs WHERE file_id = ? AND from_version = ?",
                            (file_id, from_version)).fetchone()
    if existing is None:
        conn.execute("INSERT INTO rekey_jobs (file_id, incident_id, reason, status, from_version, created_at,"
                     " updated_at) VALUES (?,?,?,?,?,?,?)", (file_id, incident_id, reason, "pending", from_version,
                                                             now, now))
    elif existing["status"] != "done":
        rank = {"exposed": 0, "held": 1, "unshare": 2}
        if rank.get(reason, 9) < rank.get(existing["reason"], 9):
            conn.execute("UPDATE rekey_jobs SET reason = ?, incident_id = COALESCE(?, incident_id), updated_at = ?"
                         " WHERE file_id = ? AND from_version = ?", (reason, incident_id, now, file_id, from_version))


def finish_rekey(core: Core, conn: sqlite3.Connection, file_id: str, new_version: int, receipt_id: str) -> None:
    jobs = conn.execute("SELECT * FROM rekey_jobs WHERE file_id = ? AND status != 'done' AND from_version < ?",
                        (file_id, new_version)).fetchall()
    now = core.clock.iso()
    for j in jobs:
        conn.execute("UPDATE rekey_jobs SET status = 'done', new_version = ?, updated_at = ? WHERE file_id = ?"
                     " AND from_version = ?", (new_version, now, file_id, j["from_version"]))
    incidents = {r[0] for r in conn.execute("SELECT incident_id FROM incident_files WHERE file_id = ? AND rekey ="
                                             " 'pending'", (file_id,))}
    for inc in incidents:
        conn.execute("UPDATE incident_files SET rekey = 'done', new_version = ? WHERE incident_id = ? AND file_id = ?",
                     (new_version, inc, file_id))
        name = conn.execute("SELECT name FROM files WHERE file_id = ?", (file_id,)).fetchone()[0]
        timeline(core, conn, inc, "rekey_progress", receipt_id, f"{name} re-keyed to version {new_version}.")
        left = conn.execute("SELECT COUNT(*) FROM incident_files WHERE incident_id = ? AND rekey = 'pending'",
                            (inc,)).fetchone()[0]
        if left == 0:
            timeline(core, conn, inc, "rekey_done", receipt_id, "Every exposed and held file has a new key.")


def classify(core: Core, conn: sqlite3.Connection, incident_id: str, device_id: str, compromise_time: str,
             slot_files: dict[str, int]) -> dict[str, int]:
    """Blast radius from the release log: exposed (released at or after compromise), held (released before),
    never_released (had a slot, never released). Queues re-keys: exposed first, then held."""
    cpt = parse(compromise_time)
    files: dict[str, dict[str, Any]] = {}
    for r in conn.execute("SELECT file_id, version, ts FROM releases WHERE device_id = ? ORDER BY ts", (device_id,)):
        f = files.setdefault(r[0], {"exposed": False, "released": True})
        if parse(r[2]) >= cpt:
            f["exposed"] = True
    for fid in slot_files:
        files.setdefault(fid, {"exposed": False, "released": False})
    counts = {"exposed": 0, "held": 0, "never_released": 0}
    for fid, info in files.items():
        frow = conn.execute("SELECT current_version, deleted FROM files WHERE file_id = ?", (fid,)).fetchone()
        if frow is None:
            continue
        category = "exposed" if info["exposed"] else ("held" if info["released"] else "never_released")
        counts[category] += 1
        prev = conn.execute("SELECT category, rekey FROM incident_files WHERE incident_id = ? AND file_id = ?",
                            (incident_id, fid)).fetchone()
        current = frow["current_version"]
        needs = category in ("exposed", "held") and not frow["deleted"]
        if prev is not None and prev["rekey"] == "done":
            conn.execute("UPDATE incident_files SET category = ? WHERE incident_id = ? AND file_id = ?",
                         (category, incident_id, fid))
            continue
        rekey = "pending" if needs else "not_needed"
        conn.execute("INSERT INTO incident_files (incident_id, file_id, from_version, category, rekey) VALUES"
                     " (?,?,?,?,?) ON CONFLICT(incident_id, file_id) DO UPDATE SET category = excluded.category,"
                     " rekey = excluded.rekey", (incident_id, fid, current, category, rekey))
        if needs:
            queue_rekey(core, conn, fid, current, category, incident_id)
    return counts


def revoke(core: Core, conn: sqlite3.Connection, *, device_id: str, compromise_time: str, reported_by: str,
           note: str, via: str, subject: dict[str, str | None], request_hash: str, started: float) -> dict[str, Any]:
    """The revocation transaction. Caller holds `conn` inside `db.tx()`."""
    dev = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    now = core.clock.iso()
    slot_files = {r[0]: r[1] for r in conn.execute("SELECT file_id, version FROM slots WHERE device_id = ?",
                                                   (device_id,))}
    epoch = core.directory.current_epoch(conn) + 1
    conn.execute("UPDATE devices SET status = 'revoked', revoked_at = ?, revoked_epoch = ?, compromise_time = ?"
                 " WHERE device_id = ?", (now, epoch, compromise_time, device_id))
    slots_deleted = conn.execute("DELETE FROM slots WHERE device_id = ?", (device_id,)).rowcount
    sessions_ended = core.end_sessions(conn, where="device_id = ?", params=(device_id,), reason="revoked")
    conn.execute("UPDATE leases SET cancelled = 1 WHERE device_id = ?", (device_id,))
    directory = core.directory.publish(conn, "revoke", revocation=True)
    incident_id = new_id("inc")
    action = "device.report_lost" if via == "report_lost" else "device.revoke"
    rc = core.receipt(conn, action=action, decision="allow", reason="revoked", subject=subject,
                      request_hash=request_hash, resource=device_id,
                      matched=["P-DEVICE-OWNER" if via == "report_lost" else "P-OPERATOR"])
    checkpoint = core.log.checkpoint(conn, force=True)
    elapsed = int((time.monotonic() - started) * 1000)
    conn.execute(
        "INSERT INTO incidents (id, device_id, user_id, status, reported_at, reported_by, compromise_time, note,"
        " time_to_enforce_ms, directory_epoch, revoke_receipt_id, checkpoint_tree_size) VALUES"
        " (?,?,?,?,?,?,?,?,?,?,?,?)",
        (incident_id, device_id, dev["user_id"], "open", now, reported_by, compromise_time, note, elapsed,
         directory["epoch"], rc["id"], checkpoint["tree_size"]),
    )
    timeline(core, conn, incident_id, "reported", rc["id"],
             "Reported lost by the owner." if via == "report_lost" else "Revoked by an operator.")
    timeline(core, conn, incident_id, "revoked", rc["id"],
             f"Device revoked; {sessions_ended} sessions ended, {slots_deleted} key slots deleted; directory epoch "
             f"{directory['epoch']}.")
    counts = classify(core, conn, incident_id, device_id, compromise_time, slot_files)
    timeline(core, conn, incident_id, "scoped", None,
             f"{counts['exposed']} exposed, {counts['held']} held, {counts['never_released']} never released.")
    core.emit(conn, "device_revoked", subject, [rc["id"]], device_id=device_id, user_id=dev["user_id"],
              incident_id=incident_id)
    return {
        "incident_id": incident_id,
        "device_id": device_id,
        "status": "revoked",
        "directory_epoch": directory["epoch"],
        "time_to_enforce_ms": elapsed,
        "sessions_ended": sessions_ended,
        "slots_deleted": slots_deleted,
        "checkpoint": checkpoint,
        "receipt_id": rc["id"],
    }


def rescope(core: Core, conn: sqlite3.Connection, incident: sqlite3.Row, compromise_time: str,
            receipt_id: str) -> None:
    conn.execute("UPDATE incidents SET compromise_time = ? WHERE id = ?", (compromise_time, incident["id"]))
    conn.execute("UPDATE devices SET compromise_time = ? WHERE device_id = ?", (compromise_time, incident["device_id"]))
    files = {r[0]: r[1] for r in conn.execute("SELECT file_id, from_version FROM incident_files WHERE incident_id = ?",
                                              (incident["id"],))}
    counts = classify(core, conn, incident["id"], incident["device_id"], compromise_time, files)
    timeline(core, conn, incident["id"], "rescoped", receipt_id,
             f"Compromise time set to {compromise_time}: {counts['exposed']} exposed, {counts['held']} held, "
             f"{counts['never_released']} never released.")


def result_for(core: Core, conn: sqlite3.Connection, incident: sqlite3.Row, receipt_id: str) -> dict[str, Any]:
    cp = core.log.checkpoint_at(incident["checkpoint_tree_size"]) or core.log.latest_checkpoint()
    return {
        "incident_id": incident["id"],
        "device_id": incident["device_id"],
        "status": "revoked",
        "directory_epoch": incident["directory_epoch"],
        "time_to_enforce_ms": incident["time_to_enforce_ms"],
        "sessions_ended": 0,
        "slots_deleted": 0,
        "checkpoint": cp,
        "receipt_id": receipt_id,
    }


# ---- views ---------------------------------------------------------------------------------------


def counts(conn: sqlite3.Connection, incident_id: str) -> dict[str, int]:
    out = {"exposed": 0, "held": 0, "never_released": 0, "rekeyed": 0, "pending": 0}
    for r in conn.execute("SELECT category, rekey FROM incident_files WHERE incident_id = ?", (incident_id,)):
        out[r[0]] += 1
        if r[1] == "done":
            out["rekeyed"] += 1
        elif r[1] == "pending":
            out["pending"] += 1
    return out


def status(conn: sqlite3.Connection, inc: sqlite3.Row) -> str:
    if inc["closed_at"]:
        return "closed"
    c = counts(conn, inc["id"])
    if c["pending"] == 0:
        return "contained"
    started = conn.execute("SELECT 1 FROM rekey_jobs WHERE incident_id = ? AND status IN ('in_progress', 'done')"
                           " LIMIT 1", (inc["id"],)).fetchone()
    return "rekeying" if started else "open"


def summary(conn: sqlite3.Connection, inc: sqlite3.Row) -> dict[str, Any]:
    dev = conn.execute("SELECT name FROM devices WHERE device_id = ?", (inc["device_id"],)).fetchone()
    user = conn.execute("SELECT name FROM users WHERE user_id = ?", (inc["user_id"],)).fetchone()
    denied = conn.execute("SELECT COUNT(*) FROM incident_timeline WHERE incident_id = ? AND step = 'denied_attempt'",
                          (inc["id"],)).fetchone()[0]
    return {
        "id": inc["id"],
        "device_id": inc["device_id"],
        "device_name": dev[0] if dev else None,
        "user_id": inc["user_id"],
        "user_name": user[0] if user else None,
        "status": status(conn, inc),
        "reported_at": inc["reported_at"],
        "compromise_time": inc["compromise_time"],
        "counts": counts(conn, inc["id"]),
        "denied_attempts": denied,
    }


def detail(conn: sqlite3.Connection, inc: sqlite3.Row) -> dict[str, Any]:
    out = summary(conn, inc)
    by = conn.execute("SELECT name FROM users WHERE user_id = ?", (inc["reported_by"],)).fetchone()
    out.update({
        "reported_by": {"user_id": inc["reported_by"], "name": by[0] if by else None},
        "note": inc["note"],
        "time_to_enforce_ms": inc["time_to_enforce_ms"],
        "directory_epoch": inc["directory_epoch"],
        "timeline": [{"step": r[0], "ts": r[1], "receipt_id": r[2], "detail": r[3]} for r in conn.execute(
            "SELECT step, ts, receipt_id, detail FROM incident_timeline WHERE incident_id = ? ORDER BY id",
            (inc["id"],))],
        "alert_ids": [r[0] for r in conn.execute(
            "SELECT id FROM alerts WHERE incident_id = ? OR device_id = ? ORDER BY ts", (inc["id"], inc["device_id"]))],
    })
    return out


def exposure(conn: sqlite3.Connection, inc: sqlite3.Row) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = {"exposed": [], "held": [], "never_released": []}
    for r in conn.execute("SELECT i.*, f.name, f.classification FROM incident_files i JOIN files f ON f.file_id ="
                          " i.file_id WHERE i.incident_id = ? ORDER BY f.name", (inc["id"],)):
        releases = [{"ts": x[0], "receipt_id": x[1]} for x in conn.execute(
            "SELECT ts, receipt_id FROM releases WHERE device_id = ? AND file_id = ? ORDER BY ts",
            (inc["device_id"], r["file_id"]))]
        groups[r["category"]].append({"file_id": r["file_id"], "name": r["name"], "classification": r["classification"],
                                      "releases": releases, "rekey": r["rekey"], "new_version": r["new_version"]})
    suspect = [json.loads(x[0]) for x in conn.execute(
        "SELECT leaf FROM receipts WHERE device_id = ? AND ts >= ? ORDER BY leaf_index",
        (inc["device_id"], inc["compromise_time"]))]
    return {"incident_id": inc["id"], "compromise_time": inc["compromise_time"], **groups,
            "suspect_decisions": suspect}
