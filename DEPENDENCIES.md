# Dependencies

Exact versions are pinned in `backend/pyproject.toml` and locked in `backend/uv.lock`
(`backend/requirements.txt` is exported from the lock for readers who do not use `uv`). No release
newer than 14 days before the build started is used (`exclude-newer = 2026-11-12`). Web dependencies
are listed in `web/package.json` and `web/pnpm-lock.yaml`.

## Python runtime (server and `qg` client)

| Package | Version | Why |
|---|---|---|
| `cryptography` | 50.0.2 | ML-KEM-768 and ML-DSA-65 (with context strings), X25519, Ed25519, AES-256-GCM, HKDF, SHA-2/SHA-3. Bundles OpenSSL 4.0.3. The only source of cryptographic primitives; QuantumGuard composes them (X-Wing per draft-connolly-cfrg-xwing-kem-11) and passes the official vectors |
| `argon2-cffi` | 25.1.0 | Argon2id for the passphrase-protected device keystore |
| `fastapi` | 0.162.5 | HTTP API, request validation, OpenAPI export |
| `pydantic` | 2.14.3 | Strict request and response models (unknown fields rejected) |
| `uvicorn[standard]` | 0.54.0 | ASGI server |
| `httpx` | 0.28.1 | HTTP client used by the `qg` CLI, scenarios and tests |
| `typer` | 0.29.1 | `qg` command-line interface (pulls in `rich` for terminal output) |
| `structlog` | 26.1.0 | Structured JSON logs with no secrets |
| `pyyaml` | 6.0.3 | Reads the signed policy bundle `rules.yaml` (safe loader only) |

Transitive packages are listed in `backend/requirements.txt`.

## Python development only

| Package | Version | Why |
|---|---|---|
| `pytest` | 9.2.0 | Test runner |
| `pytest-xdist` | 3.8.0 | Parallel test runs |
| `hypothesis` | 6.170.15 | Property tests (bit flips, reordering, Merkle proofs, canonical JSON) |
| `schemathesis` | 4.33.2 | Fuzzing from the OpenAPI document (`make fuzz`) |
| `ruff` | 0.17.4 | Lint |
| `mypy` | 2.4.1 | Type checks |
| `bandit` | 1.9.4 | Security lint |
| `pip-audit` | 2.10.1 | Known-vulnerability audit of the lockfile |

## Standard library only

`sqlite3` (state, WAL mode, parameterised queries), `hashlib` (SHAKE-256 for X-Wing key expansion,
SHA3-256 for the X-Wing combiner, SHA-256), `hmac` (HMAC-SHA-384, `compare_digest`).

## Test vectors (data, not code)

| File | Source |
|---|---|
| `spec/vectors/xwing.json` | draft-connolly-cfrg-xwing-kem-11, Appendix C |
| `spec/vectors/mlkem768.json` | NIST ACVP-Server `ML-KEM-keyGen-FIPS203`; C2SP Wycheproof `mlkem_768_test.json` |
| `spec/vectors/mldsa65.json` | NIST ACVP-Server `ML-DSA-keyGen-FIPS204`, `ML-DSA-sigVer-FIPS204` |

No AI or machine-learning package is a dependency (`scripts/check_banned_deps.sh` enforces this).
