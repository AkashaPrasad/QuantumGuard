# Security claims and core integration

Run `uv run --project backend python -m pytest tests/security -ra` from the repository root.
Pass 1 intentionally skips claims whose backend or client adapter does not exist yet.
CI adds `--security-strict`, which turns every missing fixture into a failure. A skipped
test is pending evidence, never a verified claim. Every run writes `claims.json` with test
IDs and outcomes only. The test names map to all 30 negative claims in build-plan 13.2;
parameterized cases additionally cover both signature algorithms, both proofs and each
object access path.

The harness lives in `backend/qg/testing.py` and the real client in `cli/qg`; the assertions live here.
The following is the proposed adapter interface, pending integration with core:

- `create_test_app(*, data_dir: Path, keys_dir: Path, clock: Callable[[], datetime]) -> FastAPI`.
  Each call must isolate storage and keys, initialize the production app and disable external
  adapters. Generate every secret at run time. Lifespan startup runs inside `TestClient`.
- `gateway_dependency`: the actual callable installed in every private route dependency tree.
- `security_case(*, name, data_dir, keys_dir, clock) -> Case`. Set up fresh synthetic identities,
  invitations, distinct actor sessions, encrypted multi-chunk files and signed artifacts using
  production crypto and the public HTTP API. A clock returns a timezone-aware UTC datetime;
  the tests advance it without sleeping. No private HTTP endpoints are permitted for setup.
- `Case.act(operation_name)` performs the named operation in the tests and returns a real
  HTTP response or a real CLI result with `returncode` and `plaintext_written`. Mutations
  (slot moves, incorrect AAD, reordered/truncated/bit-flipped ciphertext, signature damage)
  must change actual artifact bytes before the production client/verifier consumes them.
- `Case.observe(name)` reads actual test instrumentation, storage or captured logs. Names are
  explicit in the tests. Never synthesize outcomes, alert IDs or counts for an assertion.
- `Case.close()` releases all clients, database handles and resources, including failed tests.
- `Case.race_release_and_revoke(workers=8)` uses independent authenticated sessions so it
  races revocation rather than invalid sequence ordering. Include scheduled operations before,
  during and after the revoke transaction. Return `revoke_committed`, `revoke_commit_index`
  and `releases`. Each release has the gateway's transaction-ordered `decision_index`,
  `status_code`, and `contains_key_material`. Do not infer ordering from wall-clock times.

Scenario names and operations are declared directly in `test_negative_claims.py` and
`test_revocation_race.py`. Operations that intentionally bypass normal setup are limited to
test-owned fault injection: unsigned privilege at the identity source, policy outage,
artifact corruption, database copies and controlled clocks. No live external identity source
is contacted. In-process ASGI clients and this project's localhost containers are the only
test targets.

For `database_copy`, copy the SQLite database including committed WAL state into a separate
temporary attacker workspace; include public metadata and ciphertext, exclude `keys/` and
all client private material. Actually try to recover the sealed slots and decrypt a file.
Check the legitimate client can decrypt first. This demonstrates the limited database-copy
claim, not security after compromise of the running server or its key volume.

`secret_logging` must exercise enroll, login, upload, open, share, revoke, rekey, recovery,
errors and signal processing. Scan every application's stdout/stderr and security-event log,
including base64url and hex encodings of generated keys, MAC keys, invitation codes,
passphrases and KEM secrets. Include server startup: API section 10 forbids codes in server
output. The operator's explicit `python -m qg.admin invite` command returns codes only to the
caller's terminal; never merge that command's output into captured server logs. The test must
not silently exempt startup logs.

Do not monkeypatch policy decisions, cryptographic verification or access checks to expected
values. Every denial must run through production enforcement. A test exposing a product flaw
stays failing and becomes a finding under `tests/attacks/`; product owners fix their code.
