# QuantumGuard

QuantumGuard protects sensitive files with post-quantum cryptography and checks identity on every
request. Files are encrypted on the device, and each file key is wrapped for one device and then
sealed again by the server, so neither side can open a file alone. When a device is reported lost,
one transaction removes its access, the affected files are listed and re-keyed, and every decision is
recorded in a log that anyone can verify offline.

**The testable claim.** After a device is reported lost, no request from that device receives key
material, every file whose key that device received is listed and queued for new keys, and every
decision is recorded in a log that verifies offline with public keys only. Reading a protected file
from recorded traffic requires breaking both X25519 and ML-KEM-768.

This is a research prototype. It has not been audited, it stores keys in software, and it is meant
for synthetic data only. The limits are listed in [THREAT_MODEL.md](THREAT_MODEL.md).

## 1. Quick start

You need Docker (with Compose v2), Git, Bash and Make. Nothing else is installed on the host.

```bash
git clone https://github.com/AkashaPrasad/QuantumGuard.git quantumguard
cd quantumguard
```

Then, from the repository root:

<!-- qg:quickstart -->
```bash
docker compose up --build -d --wait
make demo
make test
```
<!-- /qg:quickstart -->

| Command | What it does | What it prints |
|---|---|---|
| `docker compose up --build -d --wait` | Builds the image and starts one container on `127.0.0.1:8080`. On first start the server generates its own keys and creates a synthetic organisation. No key or code is shipped in the repository. (`make up` runs the same command without `--wait`.) | Docker build output, then the container reported as healthy. The first build downloads base images and packages and takes several minutes |
| `make demo` | Issues a demo recovery kit inside the container, enrols every seeded person through the public API and protects two sample files, then runs the lost-device flow against the running server, so the incident, its timeline, the QG-R001 alert and the receipts stay visible in the console | A line saying where the demo recovery kit was written, one JSON line listing the enrolled people and file ids, then the `revoke` result line shown in section 3 |
| `make test` | Builds a test image and runs, with no network: the tooling tests, every Python suite, the security suite in strict mode (a skipped test counts as a failure), then six scenarios | pytest progress and summaries, then one JSON result line per scenario. It exits 0 only when everything passes |

`docker compose down` stops the stack. `docker compose down -v` also deletes its data and keys.

### Open the console

The server never prints or logs an enrolment code. Codes for the six seeded people come from a local
command that needs access to the server's data, which is the same trust as owning the server:

```bash
docker compose exec quantumguard python -m qg.admin invite --all --json
```

It prints `{"invites":[{"user_id":…,"name":…,"roles":[…],"code":…,"expires_at":…}]}` to your
terminal. A code is 16 Crockford base32 characters in four groups, for example `K7QM-2XVD-9RTA-HB4N`;
case, spaces and hyphens do not matter. Each code works once and lasts 24 hours; running the command
again cancels the previous codes. For one person only, use `--user-id usr_…`. `make demo` uses codes
itself, so run this command after it.

Open `http://localhost:8080`, choose **Launch console**, and enter a code on the **Enrol** screen
(`/app/enrol`) with a device name and a passphrase. The seeded organisation is Kestrel Biolabs, and
every name in it is invented:

| Person | Role | Lands on |
|---|---|---|
| Mira Okafor | admin | Overview |
| Tomas Lindqvist | admin | Overview |
| Priya Raman | operator | Overview |
| Jonas Weber | auditor | Overview |
| Aiko Tanaka | employee | Files |
| Daniel Mensah | employee | Files |

A person can add a second device from **Devices** (`/app/devices`), which shows a one-time code to
enter on the other device. Use a second browser profile for it. From the second device, **Report
lost** on the first one starts the incident that an operator follows under **Incidents**
(`/app/ops/incidents`). Only the owner's devices give a file a new key afterwards, so the owner signs
in on a remaining device to finish re-keying.

## 2. Running tests

| Command | Runs | Needs |
|---|---|---|
| `make test` | Everything in the Python test tree and six scenarios, inside a Docker test image | Docker |
| `make scenario-<name>` | One scenario inside the running container | Docker, running stack |
| `make readme-test` | Runs this README's quick-start block in a clean, isolated Docker daemon with no credential files, then checks `/healthz` | Docker |
| `make setup` | Installs the Python and web dependencies from the lockfiles | `uv`, `pnpm` |
| `make test-crypto` | Known-answer, vector and property tests: 353 in Python, plus the browser code's tests in `web/src/crypto` | host after `make setup` |
| `make test-api` | 41 endpoint tests (fuzzing excluded; `make fuzz` runs it) | host after `make setup` |
| `make test-security` | 172 negative security tests and regression tests from the review (`tests/security`, `tests/attacks`) | host after `make setup` |
| `make test-detect` | 18 tests, at least one per detection rule | host after `make setup` |
| `make test-reliability`, `make test-unit` | The 1,000-request revocation race; 6 command-line client tests plus the browser client's unit tests | host after `make setup` |
| `make test-e2e`, `make test-a11y` | 184 browser interaction tests and 77 accessibility checks against the console with a mock client (`pnpm --dir web run test:e2e`, `test:a11y`) | host after `make setup`, Playwright browsers |
| `pnpm --dir web run test:e2e:live` | The browser client against a real server; it starts its own API on port 8091 and web server on port 5181 | host after `make setup`, Playwright browsers |
| `make dev-scenario-<name>` | One scenario on the host against a throwaway server | host after `make setup` |

The Python counts were confirmed by running each target on 26 November 2026; the browser counts are
from `playwright test --list`. [THREAT_MODEL.md](THREAT_MODEL.md) lists each claim with its test, the
command that runs it and its status. `make test-security` also writes `claims.json` with the outcome
of every test id in `tests/security`.

## 3. Scenarios

Each scenario starts its own throwaway server (inside the container for `make scenario-<name>`),
prints exactly one JSON line on standard output, and exits 0 on pass and 1 on failure. The lines below
were copied from real runs; ids, hashes and timings differ on every run. `make demo` runs the `revoke`
flow against the main server instead, so its result appears in the console.

| Objective | Command | Result line |
|---|---|---|
| Normal operation: an admin invites a person, who enrols, signs in, protects a file and opens it | `make scenario-normal` | `{"scenario":"normal","pass":true,"steps":{"invite":true,"enrol":true,"session":true,"protect":true,"open":true},"receipt_id":"rcp_…","decision":"allow"}` |
| Security control: a device is reported lost with a loss time in the past; it is denied, the files are scoped and re-keyed | `make scenario-revoke` | `{"scenario":"revoke","pass":true,"time_to_enforce_ms":2,"exposed":1,"held":1,"never_released":1,"denied_after_revoke":true,"alert_rule":"QG-R001","receipt_id":"rcp_…","checkpoint_root":"…","sessions_ended":1,"slots_deleted":3,"incident_status":"contained","rekey_order":["exposed","held"]}` |
| Reliability: the server is killed during a re-key and restarted; duplicate revokes, malformed input and a policy outage | `make scenario-interrupt` | `{"scenario":"interrupt","pass":true,"incident_id":"inc_…","restarted":true,"rekey_resumed":true,"contained_after_restart":true,"data_intact":true,"duplicate_revoke_same_incident":true,"malformed_rejected":6,"healthy_after_malformed":true,"policy_down_status":503,"policy_up_status":200,"revoked_slot_status":401,"releases_to_revoked_after_revoke":0}` |
| Verifiable outcome: a receipt and a proof bundle verify offline; a changed stored receipt is caught at its index | `make scenario-verify` | `{"scenario":"verify","pass":true,"request_receipt_id":"rcp_…","receipt_verified":true,"leaf_index":9,"checkpoint_root":"…","tree_size":10,"bundle_entries":4,"bundle_verified":true,"tampered_index":9,"first_bad_index":9,"failed_step":"entries"}` |

Three supporting workflows reuse the same engine:

| Workflow | Command | Result line |
|---|---|---|
| Service key rotation: routine rotation keeps the old key working until it retires; an operator's emergency rotation retires it at once; a retired key is refused | `make scenario-rotate` | `{"scenario":"rotate","pass":true,"service_id":"svc_…","keyset_epoch_before":1,"keyset_epoch_after":4,"keyset_verified":true,"retiring_key_accepted":true,"operator_needs_emergency":true,"retired_key_denied":true,"alert_rule":"QG-R010","receipt_id":"rcp_…"}` |
| Unexpected privilege change: the identity source reports a role with no signed change; the person is quarantined for sensitive files only; self-approval is refused; the proper two-person change applies | `make scenario-privilege` | `{"scenario":"privilege","pass":true,"alert_rule":"QG-R005","response":"quarantine_identity","path_rule":"QG-R007","path_edges":5,"sensitive_denied":"QG_QUARANTINED/identity_quarantined","internal_still_open":true,"other_people_unaffected":true,"self_approval_blocked":true,"approved_change":"applied","open_after_lift":true,"receipt_id":"rcp_…"}` |
| Messaging device revocation: after one recipient device is revoked, messages reach only the remaining device | `make scenario-messaging` | `{"scenario":"messaging","pass":true,"delivered_to_both":true,"after_revoke_delivered_to_remaining":true,"revoked_device_denied":true,"revoked_device_addressable":false,"incident_id":"inc_…","time_to_enforce_ms":1}` |

## 4. Recovery kit

Each file can carry a recovery wrap, so it can still be opened when every device that held it is
gone. The recovery kit is an X-Wing private key that the server never holds. Whoever operates the
server issues it once:

```bash
make recovery-kit
```

This runs `python -m qg.admin recovery-kit init` in the container and prints the kit (format
`qg-recovery-kit/1`) to your terminal; store it offline. To write it straight to a file, run
`docker compose exec -T quantumguard python -m qg.admin recovery-kit init > recovery-kit.json`. The
server keeps only the public half and publishes it in a new directory epoch. A second run is refused.

- Until a kit exists, files carry no recovery slot. Files committed before the kit was issued stay
  without one.
- `make demo` issues a demo kit inside the container at `/tmp/qg-demo/recovery-kit.json`, a
  memory-backed directory that is lost when the container restarts. Copy it out with
  `docker compose cp quantumguard:/tmp/qg-demo/recovery-kit.json .` if you want it. After `make demo`,
  `make recovery-kit` is refused because a kit already exists.
- Releasing a file takes a `recovery_release` change approved by two admins or operators other than
  the requester (console: **Settings**, then **Changes**). The kit holder, an admin, then opens the
  file with the command-line client on a trusted machine (Python 3.12 and `uv`, after `make setup`),
  using a keystore enrolled with `qg enroll`:

  ```bash
  PYTHONPATH=backend:cli uv run --project backend python -m qg.client recover fil_… --change chg_… --kit recovery-kit.json --out recovered.bin --keystore admin.qgkeystore
  ```

  The passphrase comes from `QG_PASSPHRASE` or a prompt. Each approved change releases one file once.

## 5. Verifying evidence offline

Every decision produces a receipt. Receipts are leaves of a SHA-256 Merkle tree (RFC 6962 hashing),
and signed checkpoints carry both an Ed25519 and an ML-DSA-65 signature; both must verify. An
incident's proof bundle holds the receipts of the incident with their inclusion paths, the revocation
checkpoint, a consistency proof to the latest checkpoint, the exposure report and the signed
directory, and is itself dual-signed.

Three ways to check one:

1. **Automatically.** `make scenario-verify` (section 3).
2. **In the browser.** As the operator or auditor, open the incident and choose **Export proof
   bundle**. Then open **Verify** (`/app/evidence/verify`) and load the file. Verification runs in the
   page and makes no network request; a changed receipt fails and the page shows its index.
3. **With the command-line client** on a machine with Python 3.12 and `uv` (after `make setup`):

   ```bash
   PYTHONPATH=backend:cli uv run --project backend python -m qg.client server-keys --server http://localhost:8080 --out server-keys.json
   PYTHONPATH=backend:cli uv run --project backend python -m qg.client verify bundle.json --keys server-keys.json
   ```

   The first command fetches the server's public keys once, to pin them. The second runs with no
   network access and prints one `[ok]` or `[FAIL]` line per step, then `bundle verified`; it exits 1
   on any failure and prints `first bad index: <n>` for a changed receipt. Add `--json` for one JSON
   object. Without `--keys` it still verifies but warns that the keys came from the bundle itself.

## 6. Architecture

```
  DEVICE (holds private keys)        EDGE (untrusted)             BACKEND (decides; cannot read files)
 +---------------------------+    +---------------------+    +--------------------------------------+
 | browser console / qg CLI  |    | static site         |    | gateway: session, MAC, sequence      |
 |  encrypt and decrypt      |--->| same-origin /api    |--->| policy engine: signed rules, deny    |
 |  wrap file keys (X-Wing)  |    | forwarding          |    |   by default                         |
 |  sign (ML-DSA-65)         |    +---------------------+    | directory: dual-signed, epochs       |
 |  keystore (Argon2id)      |                               | key release: sealed slots, 60 s lease|
 |  offline verifier         |<--- receipts, proofs, signed  | evidence log: Merkle tree, checkpoint|
 +---------------------------+     checkpoints ------------- | detection: 14 rules, incidents       |
                                                             | SQLite and blob store: ciphertext    |
                                                             +--------------------------------------+
```

In the local build one container serves the static console and the API on one origin; there is no
separate edge process.

| Component | Code | Job |
|---|---|---|
| Client crypto | `web/src/crypto/`, `cli/qg/client/` | Encrypts files in 1 MiB chunks, wraps file keys, signs manifests, opens files |
| Device keystore | `web/src/crypto/keystore.ts`, `backend/qg/crypto/keystore.py` | Device key seeds under AES-256-GCM with an Argon2id key from the passphrase |
| Gateway | `backend/qg/gateway/http.py` | Session, request MAC, sequence number, device status, service key, active responses, rate limit, policy availability |
| Policy engine | `backend/qg/policy/` | Default deny; rules in `rules.yaml`, dual-signed by the server; unavailable means deny |
| Directory | `backend/qg/directory/` | Signed list of people, devices and public keys; the epoch only increases |
| Key release | `backend/qg/api/files.py` | Stores sealed slots; unseals one only after an allow decision, with a 60-second lease bound to the session and checked on every chunk. Only the owner's devices make a new version |
| Incidents | `backend/qg/incidents/` | Revocation transaction, exposure (exposed, held, never released), re-key queue, proof bundle |
| Evidence log | `backend/qg/log/` | Receipts, Merkle tree, checkpoints, inclusion and consistency proofs, verifier |
| Detection | `backend/qg/detect/` | Fourteen rules with scoped, liftable responses (QG-R013's is global and ends on acknowledgement) |
| Storage | `backend/qg/storage/` | SQLite in WAL mode and a blob store holding ciphertext |
| Local admin | `backend/qg/admin.py` | Enrolment codes for seeded people, the recovery kit, a policy switch for drills, decoy ids |

The API contract is `spec/API.md`; every byte two implementations must agree on is in `spec/SUITE.md`.

## 7. Cryptography (suite QG-1)

There is one fixed suite and no negotiation. Any other suite name, at any depth of a request, is
refused with `QG_BAD_SUITE`.

| Use | Algorithm | Python library | Browser library |
|---|---|---|---|
| Key exchange (file key wraps, recovery wraps, enrolment, sessions, messages) | X-Wing: X25519 with ML-KEM-768, draft-connolly-cfrg-xwing-kem-11 | `cryptography` 50.0.2 (OpenSSL 4.0.3), combiner from `hashlib` | `@noble/post-quantum` 0.7.1 |
| Device and server signatures | ML-DSA-65 (FIPS 204), hedged, with a context string per purpose | `cryptography` 50.0.2 | `@noble/post-quantum` 0.7.1 |
| Long-lived trust records (directory, checkpoints, certificates, policy, bundles) | Ed25519 and ML-DSA-65, both required | `cryptography` 50.0.2 | `@noble/curves` 2.4.0, `@noble/post-quantum` 0.7.1 |
| File contents and slot sealing | AES-256-GCM | `cryptography` 50.0.2 | Web Crypto, or `@noble/ciphers` 2.4.0 outside a secure context |
| Key derivation and request codes | HKDF-SHA-384, HMAC-SHA-384 | `cryptography` 50.0.2, `hmac` | Web Crypto, or `@noble/hashes` 2.4.0 |
| Evidence log | SHA-256 Merkle tree, RFC 6962 domain separation | `hashlib` | Web Crypto, or `@noble/hashes` 2.4.0 |
| Passphrase to keystore key | Argon2id (19 MiB, 2 passes, 1 lane) | `argon2-cffi` 25.1.0 | `@noble/hashes` 2.4.0 |

QuantumGuard composes these primitives and implements none. Python passes the official X-Wing,
ML-KEM-768 (NIST ACVP, Wycheproof) and ML-DSA-65 (NIST ACVP) vectors; the browser code passes the same
X-Wing vectors and the project's own vectors for every encoding, transcript and envelope. SLH-DSA is
not enabled because the Python library does not provide it.

## 8. Detection rules

Rules, counters and a privilege graph only; no machine learning. All fourteen rules are implemented
in `backend/qg/detect/rules/`. Each alert names its rule and the receipts that matched. Alerts appear
at `GET /api/v1/alerts`, as JSON lines with `"event":"alert"` in `docker compose logs quantumguard`,
and in `SECURITY_EVENTS.jsonl` in the data volume. An operator can lift a response, but never one that
contains themselves; an admin may lift one that contains an operator.

| Rule | Trigger | Automatic response |
|---|---|---|
| QG-R001 | Request or session attempt from a revoked device | Deny; attach to the incident |
| QG-R002 | Sequence number not greater than the last accepted (replay) | End that session |
| QG-R003 | Object built on a directory epoch past the 60 s grace or from before a revocation | Deny; require a fresh session proof |
| QG-R004 | Decoy file or decoy service key touched | Quarantine the device until an operator lifts it |
| QG-R005 | Role in the identity source with no signed change | Quarantine the person for confidential and restricted files; cancel leases |
| QG-R006 | Self-granted role followed within 10 minutes by access to a sensitive file | Quarantine the person for sensitive files |
| QG-R007 | Unapproved role opens a path to the recovery key and restricted files | Alert with the path; no automatic response |
| QG-R008 | Key releases per minute above the person's EWMA mean plus three standard deviations | Require a fresh session proof |
| QG-R009 | 20 or more not-found or denied answers in 60 s on one session | Throttle the session for 5 minutes |
| QG-R010 | Retired service key presented on any route | Deny the key |
| QG-R011 | Enrolment while a loss report is open for the same person | Hold enrolment until an operator lifts it |
| QG-R012 | 5 or more failed key proofs or bad MACs in 60 s from one address naming one device or person; or 5 signature failures on one session | Refuse further failed proofs from that address for that claim for 5 minutes (a correct proof is always accepted); or throttle that session |
| QG-R013 | The stored log fails its own consistency check | Freeze all key release until an operator acknowledges the alert. This is the one deliberately global response |
| QG-R014 | Suite other than `QG-1` requested | Deny |

Each rule has a test in `tests/detect/` (`make test-detect`); see [THREAT_MODEL.md](THREAT_MODEL.md),
section 7.

## 9. Performance

From `bench/latest.json`, written by `make bench` at commit `2684af0` on a 12-core arm64 macOS
machine with Python 3.12, server and client on the same host over loopback. The benchmark measures
the Python client only; browser timings and idle memory are not yet measured.

| Measure | Median | p95 | Target (p95) |
|---|---|---|---|
| Time to enforce a revocation (measured in the server from the start of the report handler to the end of the revocation work, 5 runs) | 3 ms | 7 ms | under 100 ms |
| Slot release, measured from the client | 1.26 ms | 2.77 ms | under 20 ms |
| Added latency: authenticated request minus the unauthenticated `/healthz` request | 0.53 ms | 1.26 ms | under 3 ms |
| Policy decision | 0.003 ms | 0.003 ms | under 5 ms |
| Session handshake (8 samples) | 2.15 ms | 2.73 ms | |
| Cold start | 0.32 s | | under 10 s |
| Runtime image size (unpacked, `docker image ls`) | 169 MB | | under 250 MB |

Protect and open throughput on a 16 MiB file: 173.2 and 590.6 MB/s. The compressed image is
36.7 MiB. Size overhead: 28 bytes per 1 MiB chunk and 125 bytes of headers per request. Signing a
checkpoint once per 1,000 receipts costs 0.44 ms, against about 421 ms if each receipt were signed.
Run `make bench` (host, after `make setup`) to measure on your machine.

## 10. Limits

QuantumGuard does not protect what a device decrypted before it was revoked, an authorised device
that is unlocked and running malware, weak passphrases, keys in hardware, metadata, availability
under a flood, or side channels in the libraries. Only the owner's devices re-key a file, so a file
whose owner has no unlocked device stays "new key pending"; devices enrolled with a code a thief used
before the report are not revoked by it. The full list is in [THREAT_MODEL.md](THREAT_MODEL.md),
section 4, and the weaknesses found by the internal review, all fixed, are in section 6.

## 11. Dependencies, notices and licence

- [DEPENDENCIES.md](DEPENDENCIES.md): Python packages and versions, and why each is used.
- [web/DEPENDENCIES.md](web/DEPENDENCIES.md): web packages.
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md): licences and sources of third-party code, fonts,
  components and test vectors.
- [SECURITY.md](SECURITY.md): reporting a vulnerability and running the scanners (`make scan`).
- [LICENSE](LICENSE): MIT.

## 12. Troubleshooting

| Problem | What to do |
|---|---|
| Port 8080 is already in use | Stop the other service, or change the left-hand side of `127.0.0.1:8080:8080` in `docker-compose.yml`. The port is bound to the loopback address only, so other machines cannot reach it |
| `make demo`, `make recovery-kit` or `make scenario-*` says the service is not running | Start the stack first with `docker compose up --build -d --wait`; these targets run inside the container |
| The console says the browser is not a secure context | Open `http://localhost:8080`, which browsers treat as secure. For HTTPS, start the TLS profile with `bash scripts/compose.sh --profile tls up -d --wait` and open `https://localhost:8443`; Caddy issues the certificate from its own local authority, so the browser warns until you trust that root. The profile is for local testing only |
| Behind the TLS profile or any reverse proxy, everyone shares one rate limit | The server takes the client address from `X-Forwarded-For` only when the proxy's address is listed in `QG_TRUSTED_PROXIES` (default `127.0.0.1`). Add `QG_TRUSTED_PROXIES` with the proxy's address (for Caddy, find it with `docker inspect`) to the `quantumguard` environment in `docker-compose.yml`. The Caddy profile overwrites `X-Forwarded-For`, so a client cannot choose its own address |
| `QG_RATE_LIMITED` while enrolling or signing in repeatedly | Enrolment and sign-in are rate-limited per address, and after 5 failed proofs naming one device, further failed proofs from that address for that device are refused for 5 minutes. A correct proof is always accepted. Wait and try again, or an operator lifts the response under **Alerts** (`/app/ops/alerts`) |
| An enrolment code does not work | Codes are single use and last 24 hours, running the invite command again cancels earlier codes, and reporting a device lost cancels the person's pending codes. Run the command again and use the newest code |
| Enrolment is on hold | A loss report is open for that person (rule QG-R011). The hold applies while the incident is open or re-keying, and after a held attempt until an operator lifts the response under **Alerts** |
| A file stays "new key pending" after a loss report | Only the owner's devices give a file a new key. The owner unlocks one of their remaining devices in the console, which re-keys pending files |
| Start again with new keys and a new organisation | `docker compose down -v` deletes the data and keys volumes; the next start generates fresh server keys and the seeded people again, with no recovery kit until one is issued. Clear the site data for `localhost:8080` in the browser, because devices enrolled earlier no longer exist |
