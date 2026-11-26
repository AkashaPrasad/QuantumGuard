"""Detection quality benchmark: precision, recall, F1, false alerts per 1,000 benign events, time to alert.

    python bench/detection.py --out bench/detection.json [--rounds 5] [--steps 300] [--seed 1]

Each round starts a fresh in-process server (production app, fake clock, temporary storage) with the seeded
organisation. A seeded random workload of benign activity (sign-in, protect, open, share, messages, directory
refresh, an approved two-person role change, occasional mistyped file ids) runs with realistic pauses. Labelled
attacks, one per detection scenario, are injected at random points between benign steps, each from the actor
the rule is meant to catch. The last attack of a round is the log tamper (QG-R013), because its response freezes
all key release.

Every alert is attributed to the step that created it (the alert list is read before and after every step):
  * an alert during a benign step is a false alert;
  * an attack is detected when its expected rule fires during that attack (true positive), otherwise missed;
  * an alert of another rule during an attack is a false alert, unless it is a documented companion
    (QG-R007 draws the privilege path that QG-R005's unsigned role opens).
Benign events are the audited decisions (receipts) benign steps produced. Time to alert is wall-clock time
from the attack's first malicious request to the moment its alert is stored and visible to the API.
No machine learning is involved; the rules are fixed conditions.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import shutil
import statistics
import sys
import tempfile
import time
import warnings
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "backend", ROOT / "cli"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

warnings.filterwarnings("ignore", category=DeprecationWarning)

from qg.client.api import ApiError  # noqa: E402
from qg.crypto.encoding import b64u, canon  # noqa: E402
from qg.crypto.suite import SUITE  # noqa: E402
from qg.testing import TestEnv  # noqa: E402

COMPANIONS = {"QG-R005": {"QG-R007"}}
PEOPLE = ["Mira Okafor", "Tomas Lindqvist", "Priya Raman", "Jonas Weber", "Aiko Tanaka", "Daniel Mensah"]
# (person, label): attacks that need an extra device use these. Loss reports and revocations only ever concern
# Jonas, so they never hold anyone else's enrolment.
EXTRA_DEVICES = [("Aiko Tanaka", "replay laptop"), ("Aiko Tanaka", "stale laptop"), ("Aiko Tanaka", "scanner"),
                 ("Daniel Mensah", "curious laptop"), ("Daniel Mensah", "forger"), ("Jonas Weber", "stolen laptop"),
                 ("Jonas Weber", "lost tablet"), ("Jonas Weber", "spare")]
FILE_OWNERS = {"Aiko Tanaka", "Daniel Mensah", "Mira Okafor"}
BENIGN_ACTORS = ["Aiko Tanaka", "Daniel Mensah", "Mira Okafor", "Priya Raman", "Jonas Weber"]


class World:
    """One round: a fresh server, the seeded people's devices and the files they own."""

    def __init__(self, root: Path, rng: random.Random) -> None:
        self.env = TestEnv(root)
        self.rng = rng
        self.dev = {name: self.env.device(name) for name in PEOPLE}
        self.files: dict[str, list[str]] = {name: [] for name in PEOPLE}
        self.shared: dict[str, list[str]] = {name: [] for name in PEOPLE}
        self.internal: set[str] = set()
        self.share_pairs: set[tuple[str, str]] = set()
        # Devices the attacks will use are enrolled up front, before any loss report could hold enrolment.
        self.pool = {label: self.env.second_device(name, label) for name, label in EXTRA_DEVICES}

    def call(self, name: str, fn: Callable[[Any], Any]) -> Any:
        """Run one benign action; sign in again if the session expired, as the console does."""
        d = self.dev[name]
        try:
            return fn(d)
        except ApiError as e:
            if e.status == 401:
                d.login()
                return fn(d)
            raise

    def extra_device(self, name: str, label: str) -> Any:
        d = self.pool[label]
        assert d.user_id == self.env.user_id(name)
        d.login()
        return d

    def sign_in_everyone(self) -> None:
        for d in self.dev.values():
            d.login()

    def receipts(self) -> int:
        return self.env.core.db.one("SELECT COUNT(*) FROM receipts")[0]

    def alert_ids(self) -> list[str]:
        return [r[0] for r in self.env.core.db.all("SELECT id FROM alerts ORDER BY rowid")]

    def alerts_by_id(self, ids: list[str]) -> list[dict[str, Any]]:
        with self.env.core.db.tx() as conn:
            return [self.env.core.alert_view(conn, i) for i in ids]


# ---- benign workload ---------------------------------------------------------------------------------------

def benign_step(w: World) -> str:
    rng = w.rng
    who = rng.choice(BENIGN_ACTORS)
    other = rng.choice([p for p in BENIGN_ACTORS if p != who])
    roll = rng.random()
    if who in FILE_OWNERS and (roll < 0.16 or not w.files[who]):
        cls = rng.choice(["internal", "internal", "confidential"])
        fid = w.call(who, lambda d: d.protect(f"report-{rng.randrange(10**6)}.pdf", os.urandom(rng.randrange(500, 40_000)),
                                              cls)["file"]["file_id"])
        w.files[who].append(fid)
        if cls == "internal":
            w.internal.add(fid)
        return "protect"
    if who not in FILE_OWNERS or not w.files[who]:
        if w.shared[who] and roll < 0.5:
            fid = rng.choice(w.shared[who])
            w.call(who, lambda d: d.open(fid))
            return "open-shared"
        w.call(who, lambda d: d.refresh_directory())
        return "directory"
    if roll < 0.20 and len(w.files[who]) >= 6:
        # Near the mass-release rule: open a whole folder of own files within about a minute.
        for fid in rng.sample(w.files[who], min(len(w.files[who]), rng.randrange(6, 12))):
            w.env.clock.advance(rng.randrange(2, 8))
            w.call(who, lambda d, f=fid: d.open(f))
        return "open-folder"
    if roll < 0.45:
        fid = rng.choice(w.files[who])
        w.call(who, lambda d: d.open(fid))
        return "open"
    if roll < 0.55:
        # People share internal documents with colleagues; each pair once.
        choices = [f for f in w.files[who] if f in w.internal and (f, other) not in w.share_pairs]
        if not choices:
            w.call(who, lambda d: d.get("/api/v1/files"))
            return "list-files"
        fid = rng.choice(choices)
        target = w.dev[other]
        w.call(who, lambda d: d.share(fid, [target.device_id]))
        w.share_pairs.add((fid, other))
        w.shared[other].append(fid)
        return "share"
    if roll < 0.65 and w.shared[who]:
        fid = rng.choice(w.shared[who])
        w.call(who, lambda d: d.open(fid))
        return "open-shared"
    if roll < 0.73:
        uid = w.dev[other].user_id
        w.call(who, lambda d: d.send_message(uid, f"note {rng.randrange(10**6)}".encode()))
        return "message"
    if roll < 0.78:
        w.call(who, lambda d: d.read_messages())
        return "read-messages"
    if roll < 0.86:
        w.call(who, lambda d: d.refresh_directory())
        return "directory"
    if roll < 0.92:
        w.call(who, lambda d: d.get("/api/v1/files"))
        return "list-files"
    if roll < 0.97:
        w.call("Priya Raman", lambda d: d.get("/api/v1/alerts"))
        return "operator-alerts"
    # Honest mistakes: a few stale or mistyped file ids in a row (below the enumeration threshold of 20 in 60 s).
    for _ in range(rng.randrange(1, 6)):
        try:
            w.call(who, lambda d: d.slot(f"fil_{b64u(os.urandom(16))}"))
        except ApiError:
            pass
    return "mistyped-ids"


def benign_role_change(w: World) -> str:
    """A properly approved change (requested by one admin, approved by the other), then the new auditor reads a
    confidential file: legitimate behaviour that must not raise QG-R005 or QG-R006."""
    mira, tomas = w.dev["Mira Okafor"], w.dev["Tomas Lindqvist"]
    target = w.dev["Daniel Mensah"].user_id
    change = w.call("Mira Okafor", lambda d: d.request_change("role_grant", target, role="auditor", reason="audit week"))
    if change.get("status") != "applied":
        w.call("Tomas Lindqvist", lambda d: d.approve_change(change))
    del mira, tomas
    if w.files["Daniel Mensah"]:
        fid = w.files["Daniel Mensah"][0]
        w.call("Daniel Mensah", lambda d: d.open(fid))
    return "approved-role-change"


# ---- labelled attacks --------------------------------------------------------------------------------------
# Each attack is a generator: it yields after every malicious request so the driver can time the alert.

def atk_replay(w: World) -> Iterator[None]:
    d = w.extra_device("Aiko Tanaka", "replay laptop")
    d.login()
    seq = d.session.seq + 1
    d.raw_request("GET", "/api/v1/devices", seq=seq)
    yield
    d.raw_request("GET", "/api/v1/devices", seq=seq)
    yield


def atk_revoked(w: World) -> Iterator[None]:
    owner = w.dev["Jonas Weber"]
    stolen = w.extra_device("Jonas Weber", "stolen laptop")
    owner.post(f"/api/v1/devices/{stolen.device_id}/report-lost", {"lost_at": w.env.clock.iso()})
    stolen.raw_request("GET", "/api/v1/devices")
    yield


def atk_enrol_during_loss(w: World) -> Iterator[None]:
    owner = w.dev["Jonas Weber"]
    lost = w.extra_device("Jonas Weber", "lost tablet")
    owner.post(f"/api/v1/devices/{lost.device_id}/report-lost", {"lost_at": w.env.clock.iso()})
    code = owner.post("/api/v1/invites", {"user_id": owner.user_id})["code"]
    try:
        w.env.client.enroll(code, "thief's tablet")
    except ApiError:
        pass
    yield


def atk_stale_epoch(w: World) -> Iterator[None]:
    aiko = w.extra_device("Aiko Tanaka", "stale laptop")
    aiko.login()
    fid = aiko.protect("stale.bin", os.urandom(2000), "confidential")["file"]["file_id"]
    slot = aiko.slot(fid)
    dek = aiko.unwrap(slot)
    old_epoch = aiko.refresh_directory()["epoch"]
    spare = w.extra_device("Jonas Weber", "spare")
    w.dev["Priya Raman"].post(f"/api/v1/devices/{spare.device_id}/revoke",
                              {"compromise_time": w.env.clock.iso(), "reason": "drill"})
    recips = sorted([w.dev["Daniel Mensah"].device_id])
    statement = {"directory_epoch": old_epoch, "file_id": fid, "recipients": recips, "suite": SUITE,
                 "version": slot["version"]}
    wraps = aiko._wraps_for(recips, dek, fid, slot["version"], old_epoch)  # noqa: SLF001
    try:
        aiko.post(f"/api/v1/files/{fid}/share", {
            "share": statement, "share_sig": b64u(aiko.state.keys.sig.sign(canon(statement), "share")), "wraps": wraps})
    except ApiError:
        pass
    yield


def atk_decoy(w: World) -> Iterator[None]:
    d = w.extra_device("Daniel Mensah", "curious laptop")
    d.login()
    try:
        d.slot(w.env.decoy_file_id())
    except ApiError:
        pass
    yield


def atk_unsigned_privilege(w: World) -> Iterator[None]:
    now = int(w.env.clock.now().timestamp())
    w.dev["Priya Raman"].post("/api/v1/signals", {
        "iss": "sandbox-idp", "jti": f"jti-{os.urandom(8).hex()}", "iat": now, "aud": "quantumguard",
        "events": {"urn:qg:event-type:privilege-observed": {
            "subject": {"format": "opaque", "id": w.dev["Jonas Weber"].user_id}, "event_timestamp": now,
            "role": "admin"}}})
    yield


def atk_self_grant(w: World) -> Iterator[None]:
    tomas = w.dev["Tomas Lindqvist"]
    fid = tomas.protect("board.bin", os.urandom(2000), "confidential")["file"]["file_id"]
    statement = {"directory_epoch": tomas.refresh_directory()["epoch"], "file_id": None, "reason": "need it",
                 "role": "auditor", "suite": SUITE, "target_user_id": tomas.user_id, "type": "role_grant"}
    tomas.post("/api/v1/changes", {"change": statement,
                                   "signature": b64u(tomas.state.keys.sig.sign(canon(statement), "change"))})
    yield
    try:
        tomas.slot(fid)
    except ApiError:
        pass
    yield


def atk_burst(w: World) -> Iterator[None]:
    """Mass key release far above the person's own baseline (built from their benign opens)."""
    d = w.dev["Aiko Tanaka"]
    if not w.files["Aiko Tanaka"]:
        w.files["Aiko Tanaka"].append(d.protect("b.bin", os.urandom(2000), "internal")["file"]["file_id"])
    fid = w.files["Aiko Tanaka"][0]
    for _ in range(40):
        w.env.clock.advance(1)
        r = d.raw_request("GET", f"/api/v1/files/{fid}/slot")
        yield
        if r.status_code != 200:
            return


def atk_enumeration(w: World) -> Iterator[None]:
    d = w.extra_device("Aiko Tanaka", "scanner")
    d.login()
    for _ in range(25):
        d.raw_request("GET", f"/api/v1/files/fil_{b64u(os.urandom(16))}/slot")
        w.env.clock.advance(1)
        yield


def atk_retired_key(w: World) -> Iterator[None]:
    mira = w.dev["Mira Okafor"]
    svc = mira.post("/api/v1/services", {"name": f"build-signer-{w.rng.randrange(10**6)}"})
    old_key = svc["keys"][0]["key_id"]
    mira.post(f"/api/v1/services/{svc['service_id']}/rotate", {"reason": "leaked", "emergency": True})
    mira.raw_request("GET", "/api/v1/services", headers={"QG-Service-Key": old_key})
    yield


def atk_bad_mac(w: World) -> Iterator[None]:
    d = w.extra_device("Daniel Mensah", "forger")
    d.login()
    d.session.k_mac = bytes(48)
    for _ in range(8):
        d.raw_request("GET", "/api/v1/devices")
        yield


def atk_bad_suite(w: World) -> Iterator[None]:
    w.env.http.post("/api/v1/enroll/start", json={"suite": "QG-0", "code": "AAAA-AAAA-AAAA-AAAA",
                                                  "device_name": "downgrade", "kem_pk": "AAAA", "sig_pk": "AAAA"})
    yield


def atk_replay_older(w: World) -> Iterator[None]:
    """Variant: replay an older sequence number, not the last one."""
    d = w.extra_device("Aiko Tanaka", "replay laptop")
    base = d.session.seq
    for k in (3, 4, 5):
        d.raw_request("GET", "/api/v1/devices", seq=base + k)
    yield
    d.raw_request("GET", "/api/v1/files", seq=base + 2)
    yield


def atk_mixed_enumeration(w: World) -> Iterator[None]:
    """Variant: probe other people's real files (denied) mixed with invented ids (not found)."""
    d = w.extra_device("Aiko Tanaka", "scanner")
    others = [f for name in ("Daniel Mensah", "Mira Okafor") for f in w.files[name] if f not in w.internal]
    if not others:
        others = [w.dev["Mira Okafor"].protect("m.bin", os.urandom(1500), "confidential")["file"]["file_id"]]
    for i in range(25):
        fid = others[i % len(others)] if i % 2 else f"fil_{b64u(os.urandom(16))}"
        d.raw_request("GET", f"/api/v1/files/{fid}/slot")
        w.env.clock.advance(1)
        yield


def atk_handshake_forgery(w: World) -> Iterator[None]:
    """Variant: guess session proofs for someone else's device instead of forging request MACs."""
    target = w.extra_device("Daniel Mensah", "forger")
    for _ in range(6):
        s = w.env.http.post("/api/v1/session/start", json={"suite": SUITE, "device_id": target.device_id}).json()
        if "start_id" in s:
            w.env.http.post("/api/v1/session/finish", json={
                "start_id": s["start_id"], "signature": b64u(os.urandom(3309)), "key_confirm": b64u(os.urandom(48))})
        yield


def atk_log_tamper(w: World) -> Iterator[None]:
    idx, leaf = w.env.core.db.one("SELECT leaf_index, leaf FROM receipts ORDER BY leaf_index LIMIT 1")
    flipped = (leaf[:-1] + ("A" if leaf[-1] != "A" else "B")) if isinstance(leaf, str) else \
        leaf[:-1] + bytes([leaf[-1] ^ 1])
    with w.env.core.db.tx() as conn:
        conn.execute("UPDATE receipts SET leaf = ? WHERE leaf_index = ?", (flipped, idx))
    w.env.core.self_audit()
    yield


ATTACKS: list[tuple[str, str, Callable[[World], Iterator[None]]]] = [
    ("revoked device keeps using its session", "QG-R001", atk_revoked),
    ("replayed request", "QG-R002", atk_replay),
    ("share built on a directory epoch from before a revocation", "QG-R003", atk_stale_epoch),
    ("decoy file opened", "QG-R004", atk_decoy),
    ("role appears in the identity source with no signed change", "QG-R005", atk_unsigned_privilege),
    ("admin grants themselves a role, then opens a confidential file", "QG-R006", atk_self_grant),
    ("mass key release far above the person's baseline", "QG-R008", atk_burst),
    ("file id enumeration", "QG-R009", atk_enumeration),
    ("retired service key presented", "QG-R010", atk_retired_key),
    ("new device enrolled while a loss report is open", "QG-R011", atk_enrol_during_loss),
    ("forged request MACs", "QG-R012", atk_bad_mac),
    ("downgrade to an unknown suite", "QG-R014", atk_bad_suite),
    ("variant: replay of an older sequence number", "QG-R002", atk_replay_older),
    ("variant: enumeration mixing denied and not-found ids", "QG-R009", atk_mixed_enumeration),
    ("variant: forged session handshake proofs", "QG-R012", atk_handshake_forgery),
    ("evidence log tampered in storage", "QG-R013", atk_log_tamper),  # last: freezes all key release
]


# ---- driver ------------------------------------------------------------------------------------------------

def run_round(root: Path, rng: random.Random, steps: int) -> dict[str, Any]:
    w = World(root, rng)
    attacks = ATTACKS[:-1][:]
    rng.shuffle(attacks)
    slots = sorted(rng.sample(range(steps // 5, steps), len(attacks)))
    plan: dict[int, tuple[str, str, Callable[[World], Iterator[None]]]] = dict(zip(slots, attacks, strict=True))
    benign_events = 0
    benign_steps = 0
    benign_errors = 0
    errors: list[str] = []
    false_alerts: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    role_change_at = rng.randrange(steps // 4, steps // 2)

    def attribute(before: list[str]) -> list[dict[str, Any]]:
        after = w.alert_ids()
        new = [i for i in after if i not in set(before)]
        return w.alerts_by_id(new)

    def run_attack(name: str, rule: str, fn: Callable[[World], Iterator[None]]) -> None:
        w.sign_in_everyone()  # attackers start from a live session, as a real one would
        before = w.alert_ids()
        t0 = time.perf_counter()
        tta = None
        error = None
        try:
            for _ in fn(w):
                if tta is None and any(a["rule_id"] == rule for a in attribute(before)):
                    tta = (time.perf_counter() - t0) * 1000
        except ApiError as e:
            error = f"{e.status} {e.code} {e.reason}"
        new = attribute(before)
        hit = [a for a in new if a["rule_id"] == rule]
        if hit and tta is None:
            tta = (time.perf_counter() - t0) * 1000
        allowed = {rule} | COMPANIONS.get(rule, set())
        for a in new:
            if a["rule_id"] not in allowed:
                false_alerts.append({"during": f"attack {rule}", "rule_id": a["rule_id"], "summary": a["summary"]})
        results.append({"attack": name, "expected_rule": rule, "detected": bool(hit),
                        "time_to_alert_ms": round(tta, 3) if tta is not None else None, "setup_error": error,
                        "alert_names": ({"identity": hit[0]["identity"], "service": hit[0]["service"],
                                         "event": hit[0]["event"]["kind"]} if hit else None)})

    for step in range(steps):
        w.env.clock.advance(rng.randrange(5, 45))
        if step in plan:
            run_attack(*plan[step])
            continue
        before_alerts = w.alert_ids()
        before_receipts = w.receipts()
        try:
            benign_role_change(w) if step == role_change_at else benign_step(w)
        except ApiError as e:
            benign_errors += 1
            errors.append(f"{e.status} {e.code} {e.reason}")
        benign_steps += 1
        benign_events += w.receipts() - before_receipts
        for a in attribute(before_alerts):
            false_alerts.append({"during": "benign", "rule_id": a["rule_id"], "summary": a["summary"]})
    run_attack(*ATTACKS[-1])
    w.env.close()
    return {"benign_steps": benign_steps, "benign_events": benign_events, "benign_errors": benign_errors,
            "false_alerts": false_alerts, "attacks": results, "errors": errors}


def pct(values: list[float], q: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, round(q * (len(s) - 1)))]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", type=Path, default=ROOT / "bench" / "detection.json")
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--steps", type=int, default=300)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args(argv)

    rounds = []
    tmp = Path(tempfile.mkdtemp(prefix="qg-detect-"))
    try:
        for i in range(args.rounds):
            rng = random.Random(args.seed * 1000 + i)  # noqa: S311 - reproducible workload, not cryptography
            rounds.append(run_round(tmp / f"r{i}", rng, args.steps))
            r = rounds[-1]
            hits = sum(a["detected"] for a in r["attacks"])
            print(f"round {i + 1}/{args.rounds}: {hits}/{len(r['attacks'])} attacks detected, "
                  f"{len(r['false_alerts'])} false alerts, {r['benign_events']} benign events", file=sys.stderr)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    attacks = [a for r in rounds for a in r["attacks"]]
    false_alerts = [f for r in rounds for f in r["false_alerts"]]
    tp = sum(a["detected"] for a in attacks)
    fn = len(attacks) - tp
    fp = len(false_alerts)
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    benign_events = sum(r["benign_events"] for r in rounds)
    ttas = [a["time_to_alert_ms"] for a in attacks if a["time_to_alert_ms"] is not None]
    per_rule: dict[str, dict[str, Any]] = {}
    for a in attacks:
        e = per_rule.setdefault(a["attack"], {"rule": a["expected_rule"], "runs": 0, "detected": 0, "tta_ms": []})
        e["runs"] += 1
        e["detected"] += a["detected"]
        if a["time_to_alert_ms"] is not None:
            e["tta_ms"].append(a["time_to_alert_ms"])
    for e in per_rule.values():
        t = e.pop("tta_ms")
        e["median_time_to_alert_ms"] = round(statistics.median(t), 2) if t else None
    out = {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "method": "bench/detection.py: seeded benign workload with labelled attacks injected at random points; "
                  "every alert attributed to the step that created it. In-process server, fake clock.",
        "parameters": {"rounds": args.rounds, "steps_per_round": args.steps, "seed": args.seed},
        "host": {"machine": platform.machine(), "python": platform.python_version(), "system": platform.system()},
        "attacks_injected": len(attacks),
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "benign_steps": sum(r["benign_steps"] for r in rounds),
        "benign_events": benign_events,
        "benign_step_errors": sum(r["benign_errors"] for r in rounds),
        "false_alerts_per_1000_benign_events": round(1000 * sum(1 for f in false_alerts if f["during"] == "benign")
                                                     / benign_events, 3) if benign_events else None,
        "time_to_alert_ms": {"median": round(statistics.median(ttas), 2), "p95": round(pct(ttas, 0.95), 2),
                             "min": round(min(ttas), 2), "max": round(max(ttas), 2), "n": len(ttas)} if ttas else None,
        "per_attack": dict(sorted(per_rule.items(), key=lambda kv: (kv[1]["rule"], kv[0]))),
        "false_alerts": false_alerts,
        "missed": [{"attack": a["attack"], "rule": a["expected_rule"], "setup_error": a["setup_error"]}
                   for a in attacks if not a["detected"]],
        "benign_error_kinds": sorted({e for r in rounds for e in r["errors"]}),
    }
    args.out.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: out[k] for k in ("precision", "recall", "f1", "false_alerts_per_1000_benign_events",
                                          "time_to_alert_ms", "benign_events", "attacks_injected")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
