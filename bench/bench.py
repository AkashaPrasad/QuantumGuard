"""QG-1 performance benchmark (build plan section 13.5).

    python bench/bench.py --out bench/latest.json [--quick]

Starts one real server process (temp data) and measures crypto, request latency, report-lost enforcement,
file throughput, checkpoint signing and cold start. Writes JSON (indent 2, sorted keys) and a summary to stderr.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for _p in (ROOT / "backend", ROOT / "cli"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from qg.client import api as client_api
from qg.client.api import QGClient
from qg.crypto import xwing
from qg.crypto.sign import DualSigner, Ed25519Key, MLDSAKey, mldsa_verify
from qg.scenarios.harness import Server

TARGETS = {
    "policy_decision_p95_ms": 5,
    "slot_release_p95_ms": 20,
    "added_latency_p95_ms": 3,
    "time_to_enforce_ms": 100,
    "cold_start_s": 10,
    "image_size_mb": 250,
}
MIB = 1024 * 1024


class BenchFailure(RuntimeError):
    pass


def r3(x: float) -> float:
    return round(float(x), 3)


def stats(samples: list[float]) -> dict[str, Any]:
    s = sorted(samples)
    p95 = s[min(len(s) - 1, max(0, round(0.95 * len(s) + 0.5) - 1))]
    return {"median": r3(statistics.median(s)), "p95": r3(p95), "n": len(s)}


def timed(fn: Any, n: int, warmup: int = 3) -> list[float]:
    for _ in range(warmup):
        fn()
    out = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t) * 1000)
    return out


def ok(resp: Any) -> Any:
    if not 200 <= resp.status_code < 300:
        raise BenchFailure(f"non-2xx in timed loop: {resp.status_code} {resp.text[:200]}")
    return resp


def login(dev: Any) -> None:
    """Untimed login that waits out the per-address public rate limit (start and finish each take a token:
    0.5 tokens/s, burst 20, so a sustained rate of one login per 4 s after the first 10)."""
    for _ in range(40):
        try:
            dev.login()
            return
        except client_api.ApiError as exc:
            if exc.status != 429:
                raise
            time.sleep(5)
    raise BenchFailure("login stayed rate limited")


def enroll_device(c: QGClient, code: str, name: str) -> Any:
    """Enrol, waiting out the per-address public rate limit (start and finish each take a token)."""
    for _ in range(40):
        try:
            return c.enroll(code, name)
        except client_api.ApiError as exc:
            if exc.status != 429:
                raise
            time.sleep(5)
    raise BenchFailure("enrol stayed rate limited")


def session_loop(fn: Any, n: int, burst: int = 50, warmup: int = 3) -> list[float]:
    """Time fn() n times in back-to-back bursts of `burst` requests (the first `warmup` of each burst are dropped
    so a cold CPU after the pause does not count), pausing between bursts so the per-session token bucket
    (20/s, burst 60) refills. Pacing with a sleep between every request would measure idle wake-up instead."""
    out: list[float] = []
    while len(out) < n:
        for i in range(burst):
            t = time.perf_counter()
            fn()
            dt = (time.perf_counter() - t) * 1000
            if i >= warmup and len(out) < n:
                out.append(dt)
        time.sleep(burst / 20.0)
    return out


def bench_crypto(n: int) -> dict[str, Any]:
    kem = xwing.XWingPrivateKey.generate()
    pk = kem.public_key
    _ss, ct = xwing.encapsulate(pk)
    pq = MLDSAKey.generate()
    ed = Ed25519Key.generate()
    msg = os.urandom(256)
    sig = pq.sign(msg, "manifest")
    dual = DualSigner(ed, pq)
    ckpt = {"checkpoint": {"size": 1000, "root": "A" * 64, "prev": "B" * 64}, "time": "2026-01-01T00:00:00Z"}
    return {
        "xwing_keygen": stats(timed(xwing.XWingPrivateKey.generate, n)),
        "xwing_encaps": stats(timed(lambda: xwing.encapsulate(pk), n)),
        "xwing_decaps": stats(timed(lambda: kem.decapsulate(ct), n)),
        "mldsa_sign": stats(timed(lambda: pq.sign(msg, "manifest"), n)),
        "mldsa_verify": stats(timed(lambda: mldsa_verify(pq.public_key, sig, msg, "manifest"), n)),
        "ed25519_sign": stats(timed(lambda: ed.sign(msg, "manifest"), n)),
        "dual_sign_checkpoint": stats(timed(lambda: dual.sign_object(ckpt, "checkpoint"), n)),
    }


def bench_checkpoint(reps: int, receipts: int) -> dict[str, Any]:
    dual = DualSigner(Ed25519Key.generate(), MLDSAKey.generate())
    ckpt = {"checkpoint": {"size": receipts, "root": "A" * 64, "prev": "B" * 64}}
    dual.sign_object(ckpt, "checkpoint")
    batched = []
    for _ in range(reps):
        t = time.perf_counter()
        dual.sign_object(ckpt, "checkpoint")
        batched.append((time.perf_counter() - t) * 1000)
    t = time.perf_counter()
    for i in range(receipts):
        dual.sign_object({"receipt": {"seq": i, "root": "A" * 64}}, "checkpoint")
    per_receipt = (time.perf_counter() - t) * 1000
    return {"batched": r3(statistics.median(batched)), "per_receipt_equivalent": r3(per_receipt),
            "receipts_per_checkpoint": receipts}


def bench_policy(n: int) -> dict[str, Any]:
    from qg.testing import TestEnv

    with tempfile.TemporaryDirectory(prefix="qg-bench-env-") as d:
        env = TestEnv(Path(d))
        try:
            facts = {"user_active": True, "device_active": True}
            return stats(timed(lambda: env.core.policy.decide(["employee"], "file.create", facts), n, warmup=20))
        finally:
            env.close()


def enroll(server: Server, name: str) -> tuple[QGClient, Any]:
    c = QGClient(server.url)
    dev = enroll_device(c, server.code(name), "bench-" + name.split()[0].lower())
    login(dev)
    return c, dev


def bench_latency(server: Server, dev: Any, n: int) -> dict[str, Any]:
    file_id = dev.protect("slot.bin", b"x" * 1024)["file"]["file_id"]
    handshake = timed(dev.login, 4 if n < 50 else 8, warmup=0)
    baseline = session_loop(lambda: ok(dev.http.get("/healthz")), n)
    auth = session_loop(lambda: ok(dev.raw_request("GET", "/api/v1/policy")), n)
    slot = session_loop(lambda: ok(dev.raw_request("GET", f"/api/v1/files/{file_id}/slot")), n)
    b, a = stats(baseline), stats(auth)
    return {
        "session_handshake_ms": stats(handshake),
        "baseline_ms": b,
        "authenticated_ms": a,
        "slot_release_ms": stats(slot),
        "added_latency_ms": {"median": r3(a["median"] - b["median"]), "p95": r3(a["p95"] - b["p95"]),
                             "n": min(a["n"], b["n"])},
    }


def bench_enforce(server: Server, admin: Any, runs: int) -> dict[str, Any]:
    """Each run: the admin invites a new person, who enrols two devices; the second reports the first lost."""
    samples: list[float] = []
    c = QGClient(server.url)
    for i in range(runs):
        inv = admin.post("/api/v1/invites", {"name": f"Bench Person {i}", "roles": ["employee"]})
        victim = enroll_device(c, inv["code"], f"enf-{i}-a")
        login(victim)
        inv2 = victim.post("/api/v1/invites", {"user_id": victim.user_id})
        reporter = enroll_device(c, inv2["code"], f"enf-{i}-b")
        login(reporter)
        res = reporter.post(f"/api/v1/devices/{victim.device_id}/report-lost",
                            {"lost_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")})
        samples.append(float(res["time_to_enforce_ms"]))
    return stats(samples)


def bench_throughput(dev: Any, mib: int) -> dict[str, Any]:
    data = os.urandom(mib * MIB)
    login(dev)
    t = time.perf_counter()
    res = dev.protect("big.bin", data)
    t_protect = time.perf_counter() - t
    file_id = res["file"]["file_id"]
    t = time.perf_counter()
    back = dev.open(file_id)
    t_open = time.perf_counter() - t
    if back != data:
        raise BenchFailure("round trip mismatch")
    slot = dev.slot(file_id)
    chunks = slot["manifest"]["chunk_count"]
    ct_total = 0
    for i in range(chunks):
        ct_total += len(ok(dev.raw_request("GET", f"/api/v1/files/{file_id}/chunks/{i}",
                                           headers={"QG-Lease": slot["lease"]["lease_id"]})).content)
    sess = dev.session
    mac = client_api.request_mac(sess.k_mac, "GET", "/api/v1/policy", 1, b"")
    hdr = sum(len(k) + len(v) + 4 for k, v in (("QG-Session", sess.session_id), ("QG-Seq", "1"), ("QG-MAC", mac)))
    return {"protect": r3(mib / t_protect), "open": r3(mib / t_open), "size_mib": mib,
            "size_overhead": {"per_chunk_bytes": 28, "per_file_bytes": ct_total - len(data),
                              "per_request_header_bytes": hdr, "chunk_count": chunks}}


def _size_mb(text: str) -> float | None:
    m = re.match(r"^([0-9.]+)\s*([KMG]?B)$", text.strip())
    if not m:
        return None
    return r3(float(m.group(1)) * {"B": 1e-6, "KB": 1e-3, "MB": 1.0, "GB": 1e3}[m.group(2)])


def docker_metrics() -> tuple[dict[str, Any], dict[str, Any]]:
    """Image size as `docker image ls` reports it (unpacked, MB) and the compressed content size (MiB)."""
    reason = {"value": None, "reason": "measured by the container build"}
    if shutil.which("docker") is None:
        return dict(reason), dict(reason)
    try:
        compressed = subprocess.run(["docker", "image", "inspect", "quantumguard:local", "--format", "{{.Size}}"],
                                    capture_output=True, text=True, timeout=30, check=True).stdout.strip()
        listed = subprocess.run(["docker", "image", "ls", "quantumguard:local", "--format", "{{.Size}}"],
                                capture_output=True, text=True, timeout=30, check=True).stdout.strip().splitlines()
    except (subprocess.SubprocessError, ValueError, OSError):
        return dict(reason), dict(reason)
    unpacked = _size_mb(listed[0]) if listed else None
    size = {"value": unpacked, "unit": "MB (docker image ls, unpacked)",
            "compressed_mib": r3(int(compressed) / MIB) if compressed.isdigit() else None, "reason": None}
    return size, {"value": None, "reason": "image present, idle memory not sampled by this bench"}


def commit() -> str:
    if os.environ.get("QG_COMMIT"):
        return os.environ["QG_COMMIT"]
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True,
                              text=True, timeout=10, check=True).stdout.strip() or "unknown"
    except (subprocess.SubprocessError, OSError):
        return "unknown"


def run(quick: bool = False) -> dict[str, Any]:
    n = 12 if quick else 200
    out: dict[str, Any] = {
        "commit": commit(),
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "machine": {"platform": platform.platform(), "python": platform.python_version(),
                    "cpu_count": os.cpu_count()},
        "suite": "QG-1",
    }
    out["crypto_ms"] = bench_crypto(n)
    out["checkpoint_signing_ms_per_1000_receipts"] = bench_checkpoint(3 if quick else 10, 50 if quick else 1000)
    out["policy_decision_ms"] = bench_policy(n * 5)
    server = Server()
    try:
        t0 = time.perf_counter()
        server.start()
        cold = time.perf_counter() - t0
        out["cold_start_s"] = r3(cold)
        _, dev = enroll(server, "Aiko Tanaka")
        out.update(bench_latency(server, dev, n))
        base = enroll(server, "Mira Okafor")[1]
        out["time_to_enforce_ms"] = bench_enforce(server, base, 2 if quick else 5)
        out["throughput_mb_s"] = bench_throughput(dev, 2 if quick else 16)
    finally:
        server.close()
    size, mem = docker_metrics()
    out["image_size_mb"], out["idle_memory_mb"] = size, mem
    out["targets"] = dict(TARGETS)
    out["met"] = {
        "policy_decision_p95_ms": out["policy_decision_ms"]["p95"] <= TARGETS["policy_decision_p95_ms"],
        "slot_release_p95_ms": out["slot_release_ms"]["p95"] <= TARGETS["slot_release_p95_ms"],
        "added_latency_p95_ms": out["added_latency_ms"]["p95"] <= TARGETS["added_latency_p95_ms"],
        "time_to_enforce_ms": out["time_to_enforce_ms"]["p95"] <= TARGETS["time_to_enforce_ms"],
        "cold_start_s": out["cold_start_s"] <= TARGETS["cold_start_s"],
        # null when the image was not built on this machine
        "image_size_mb": (out["image_size_mb"]["value"] <= TARGETS["image_size_mb"]
                          if out["image_size_mb"].get("value") is not None else None),
    }
    return out


def summary(res: dict[str, Any]) -> str:
    return "\n".join([
        f"QG-1 bench @ {res['commit']}",
        f"  policy decision   p95 {res['policy_decision_ms']['p95']} ms (target 5)",
        f"  slot release      p95 {res['slot_release_ms']['p95']} ms (target 20)",
        f"  added latency     p95 {res['added_latency_ms']['p95']} ms (target 3)",
        "  time to enforce   median {} ms, p95 {} ms (target 100)".format(
            res["time_to_enforce_ms"]["median"], res["time_to_enforce_ms"]["p95"]),
        f"  cold start        {res['cold_start_s']} s (target 10)",
        f"  throughput        protect {res['throughput_mb_s']['protect']} MB/s, open {res['throughput_mb_s']['open']} MB/s",
        "  targets met: " + ", ".join(f"{k}={v}" for k, v in res["met"].items()),
    ])


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "bench" / "latest.json"))
    ap.add_argument("--quick", action="store_true", help="tiny sample sizes (smoke test)")
    args = ap.parse_args()
    res = run(args.quick)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(res, indent=2, sort_keys=True) + "\n")
    print(summary(res), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
