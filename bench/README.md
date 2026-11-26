# QG-1 benchmark

`make bench` runs `bench/bench.py --out bench/latest.json` against a real `python -m qg.server` process with
temporary data, and prints a short summary to stderr. `--quick` uses tiny sample sizes (used by `tests/perf`).

Notes on method:

- Request latency is measured in back-to-back bursts of 50 with a pause between bursts, so the 20 requests/s
  per-session limit is never hit and idle wake-up is not counted as latency. Any non-2xx fails the run.
- The public endpoints (enrol, session start and finish) are limited per address (burst 20 tokens, 0.5 per
  second, and a login uses two), so the session handshake is sampled 8 times only.
- Time to enforce comes from `time_to_enforce_ms` in the report-lost response; each run uses a new person.
- `image_size_mb` and `idle_memory_mb` are null with a reason unless Docker and `quantumguard:local` exist.
