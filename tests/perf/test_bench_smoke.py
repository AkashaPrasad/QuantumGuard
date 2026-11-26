import importlib.util
import json
from pathlib import Path

BENCH = Path(__file__).resolve().parents[2] / "bench" / "bench.py"


def _load():
    spec = importlib.util.spec_from_file_location("qg_bench", BENCH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _numbers(x):
    if isinstance(x, bool):
        return
    if isinstance(x, (int, float)):
        yield x
    elif isinstance(x, dict):
        for k, v in x.items():
            if k != "machine":
                yield from _numbers(v)


def test_quick_bench_has_all_keys_and_sane_numbers(tmp_path):
    bench = _load()
    res = bench.run(quick=True)
    json.dumps(res)
    for key in ("commit", "generated_at", "machine", "suite", "crypto_ms", "session_handshake_ms",
                "policy_decision_ms", "slot_release_ms", "baseline_ms", "authenticated_ms", "added_latency_ms",
                "time_to_enforce_ms", "throughput_mb_s", "checkpoint_signing_ms_per_1000_receipts",
                "cold_start_s", "image_size_mb", "idle_memory_mb", "targets", "met"):
        assert key in res, key
    assert res["suite"] == "QG-1"
    for name in ("xwing_keygen", "xwing_encaps", "xwing_decaps", "mldsa_sign", "mldsa_verify", "ed25519_sign",
                 "dual_sign_checkpoint"):
        assert set(res["crypto_ms"][name]) == {"median", "p95", "n"}
    assert set(res["throughput_mb_s"]) >= {"protect", "open", "size_overhead"}
    assert set(res["checkpoint_signing_ms_per_1000_receipts"]) >= {"batched", "per_receipt_equivalent"}
    assert set(res["targets"]) == set(res["met"]) == {"policy_decision_p95_ms", "slot_release_p95_ms",
                                                      "added_latency_p95_ms", "time_to_enforce_ms",
                                                      "cold_start_s", "image_size_mb"}
    assert all(n >= 0 for n in _numbers({k: v for k, v in res.items() if k != "added_latency_ms"}))
