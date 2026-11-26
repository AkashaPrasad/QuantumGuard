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
make scenario-verify
```
<!-- /qg:quickstart -->

| Command | What it does | What it prints |
|---|---|---|
| `docker compose up --build -d --wait` | Builds the image and starts one container on `127.0.0.1:8080`. On first start the server generates its own keys and creates a synthetic organisation. No key or code is shipped in the repository | Docker build output, then the container reported as healthy. The first build downloads base images and packages and takes several minutes |
| `make demo` | Enrols every seeded person through the public API from inside the container and protects two sample files, then runs the lost-device flow against the running server, so the incident, its timeline, the QG-R001 alert and the receipts stay visible in the console | One JSON line listing the enrolled people and file ids, then the `revoke` result line shown in section 3 |
| `make scenario-verify` | Verifies one receipt offline, verifies an incident proof bundle with pinned keys, changes one byte of a stored receipt and verifies again | One JSON line ending in `"first_bad_index":<n>,"failed_step":"entries"`, with `"pass":true` and exit code 0 |

`docker compose down` stops the stack. `docker compose down -v` also deletes its data and keys.

### Open the console

The server never prints or logs an enrolment code. Codes for the six seeded people come from a local
command that needs access to the server's data, which is the same trust as owning the server:

```bash
docker compose exec quantumguard python -m qg.admin invite --all --json
```

It prints `{"invites":[{"user_id":…,"name":…,"roles":[…],"code":"XXXX-XXXX-XXXX-XXXX","expires_at":…}]}`
to your terminal. Each code works once and lasts 24 hours; running the command again cancels the
previous codes. For one person only, use `--user-id usr_…`. `make demo` uses codes itself, so run
this command after it.

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
(`/app/ops/incidents`).

## 2. Running tests

| Command | Runs | Needs |
|---|---|---|
| `make test` | Every Python suite inside a test image, with the security suite in strict mode, then six scenarios (all but `messaging`) | Docker |
| `make scenario-<name>` | One scenario inside the running container | Docker, running stack |
| `make setup` | Installs the Python and web dependencies from the lockfiles | `uv`, `pnpm` |
| `make test-crypto` | Known-answer, vector and property tests in Python and in the browser code | host after `make setup` |
| `make test-api`, `make test-security`, `make test-detect`, `make test-reliability`, `make test-unit` | Endpoint, negative security, one test per detection rule, reliability, and command-line and browser client tests | host after `make setup` |
| `make dev-scenario-<name>` | One scenario on the host against a throwaway server | host after `make setup` |

[THREAT_MODEL.md](THREAT_MODEL.md) lists each claim with its test, the command that runs it and its
status. `make test-security` also writes `claims.json` with the outcome of every test id.

## 3. Scenarios

Each scenario starts its own throwaway server (inside the container for `make scenario-<name>`),
prints exactly one JSON line on standard output, and exits 0 on pass and 1 on failure. The lines below
were copied from real runs; ids, hashes and timings differ on every run. `make demo` runs the `revoke`
flow against the main server instead, so its result appears in the console.

| Objective | Command | Result line |
|---|---|---|
| Normal operation: an admin invites a person, who enrols, signs in, protects a file and opens it | `make scenario-normal` | `{"scenario":"normal","pass":true,"steps":{"invite":true,"enrol":true,"session":true,"protect":true,"open":true},"receipt_id":"rcp_…","decision":"allow"}` |
| Security control: a device is reported lost with a loss time in the past; it is denied, the files are scoped and re-keyed | `make scenario-revoke` | `{"scenario":"revoke","pass":true,"time_to_enforce_ms":2,"exposed":1,"held":1,"never_released":1,"denied_after_revoke":true,"alert_rule":"QG-R001","receipt_id":"rcp_…","checkpoint_root":"…","sessions_ended":1,"slots_deleted":3,"incident_status":"contained","rekey_order":["exposed","held"]}` |
| Reliability: the server is killed during a re-key and restarted; duplicate revokes, malformed input and a policy outage | `make scenario-interrupt` | `{"scenario":"interrupt","pass":true,"incident_id":"inc_…","restarted":true,"rekey_resumed":true,"contained_after_restart":true,"data_intact":true,"duplicate_revoke_same_incident":true,"malformed_rejected":6,"healthy_after_malformed":true,"policy_down_status":503,"policy_up_status":200,"revoked_slot_status":403,"releases_to_revoked_after_revoke":0}` |
| Verifiable outcome: a receipt and a proof bundle verify offline; a changed stored receipt is caught at its index | `make scenario-verify` | `{"scenario":"verify","pass":true,"request_receipt_id":"rcp_…","receipt_verified":true,"leaf_index":9,"checkpoint_root":"…","tree_size":10,"bundle_entries":4,"bundle_verified":true,"tampered_index":9,"first_bad_index":9,"failed_step":"entries"}` |

Three supporting workflows reuse the same engine:

| Workflow | Command | Result line |
|---|---|---|
| Service key rotation: routine rotation keeps the old key working until it retires; an operator's emergency rotation retires it at once; a retired key is refused | `make scenario-rotate` | `{"scenario":"rotate","pass":true,"service_id":"svc_…","keyset_epoch_before":1,"keyset_epoch_after":4,"keyset_verified":true,"retiring_key_accepted":true,"operator_needs_emergency":true,"retired_key_denied":true,"alert_rule":"QG-R010","receipt_id":"rcp_…"}` |
| Unexpected privilege change: the identity source reports a role with no signed change; the person is quarantined for sensitive files only; self-approval is refused; the proper two-person change applies | `make scenario-privilege` | `{"scenario":"privilege","pass":true,"alert_rule":"QG-R005","response":"quarantine_identity","path_rule":"QG-R007","path_edges":5,"sensitive_denied":"QG_QUARANTINED/identity_quarantined","internal_still_open":true,"other_people_unaffected":true,"self_approval_blocked":true,"approved_change":"applied","open_after_lift":true,"receipt_id":"rcp_…"}` |
| Messaging device revocation: after one recipient device is revoked, messages reach only the remaining device | `make scenario-messaging` | `{"scenario":"messaging","pass":true,"delivered_to_both":true,"after_revoke_delivered_to_remaining":true,"revoked_device_denied":true,"revoked_device_addressable":false,"incident_id":"inc_…","time_to_enforce_ms":2}` |

## 4. Verifying evidence offline

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

## 5. Architecture

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
| Gateway | `backend/qg/gateway/http.py` | Session, request MAC, sequence number, device status, active responses, rate limit, policy availability |
| Policy engine | `backend/qg/policy/` | Default deny; rules in `rules.yaml`, dual-signed at first start; unavailable means deny |
| Directory | `backend/qg/directory/` | Signed list of people, devices and public keys; the epoch only increases |
| Key release | `backend/qg/api/files.py` | Stores sealed slots; unseals one only after an allow decision, with a 60-second lease checked on every chunk |
| Incidents | `backend/qg/incidents/` | Revocation transaction, exposure (exposed, held, never released), re-key queue, proof bundle |
| Evidence log | `backend/qg/log/` | Receipts, Merkle tree, checkpoints, inclusion and consistency proofs, verifier |
| Detection | `backend/qg/detect/` | Fourteen rules with scoped, time-boxed, liftable responses |
| Storage | `backend/qg/storage/` | SQLite in WAL mode and a blob store holding ciphertext |
| Local admin | `backend/qg/admin.py` | Enrolment codes for seeded people, policy switch for drills, decoy ids |

The API contract is `spec/API.md`; every byte two implementations must agree on is in `spec/SUITE.md`.

## 6. Cryptography (suite QG-1)

There is one fixed suite and no negotiation. Any other suite name is refused with `QG_BAD_SUITE`.

| Use | Algorithm | Python library | Browser library |
|---|---|---|---|
| Key exchange (file key wraps, enrolment, sessions) | X-Wing: X25519 with ML-KEM-768, draft-connolly-cfrg-xwing-kem-11 | `cryptography` 50.0.2 (OpenSSL 4.0.3), combiner from `hashlib` | `@noble/post-quantum` 0.7.1 |
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

## 7. Detection rules

Rules, counters and a privilege graph only; no machine learning. Each alert names its rule and the
receipts that matched. Alerts appear at `GET /api/v1/alerts`, as JSON lines with `"event":"alert"` in
`docker compose logs quantumguard`, and in `SECURITY_EVENTS.jsonl` in the data volume.

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
| QG-R010 | Retired service key presented | Deny the key |
| QG-R011 | Enrolment while a loss report is open for the same person | Hold enrolment until an operator lifts it |
| QG-R012 | 5 or more MAC or signature failures in 60 s | Throttle the session or device for 5 minutes |
| QG-R013 | Stored log no longer matches its hashes or checkpoint | Freeze key release until an operator acknowledges |
| QG-R014 | Suite other than `QG-1` requested | Deny |

Each rule has one test in `tests/detect/` (`make test-detect`); see [THREAT_MODEL.md](THREAT_MODEL.md),
section 6.

## 8. Performance

From `bench/latest.json`, written by `make bench` at commit `aa8504e` on a 12-core arm64 macOS
machine with Python 3.12, server and client on the same host over loopback. The benchmark measures
the Python client only; browser timings and idle memory are not yet measured.

| Measure | Median | p95 | Target (p95) |
|---|---|---|---|
| Time to enforce a revocation (measured in the server from the start of the report handler to the end of the revocation work, 5 runs) | 3 ms | 6 ms | under 100 ms |
| Slot release, measured from the client | 1.64 ms | 7.29 ms | under 20 ms |
| Added latency: authenticated request minus the unauthenticated `/healthz` request | 0.48 ms | 1.31 ms | under 3 ms |
| Policy decision | 0.003 ms | 0.004 ms | under 5 ms |
| Session handshake (8 samples) | 3.35 ms | 4.41 ms | |
| Cold start | 0.27 s | | under 10 s |
| Runtime image size (unpacked, `docker image ls`) | 272 MB | | under 250 MB: not met |

Protect and open throughput on a 16 MiB file: 117.2 and 312.3 MB/s. The compressed image is
56.6 MiB. Size overhead: 28 bytes per 1 MiB chunk and 125 bytes of headers per request. Signing a
checkpoint once per 1,000 receipts costs 0.42 ms, against about 430 ms if each receipt were signed. Run `make bench` (host, after `make setup`)
to measure on your machine.

## 9. Limits

QuantumGuard does not protect what a device decrypted before it was revoked, an authorised device
that is unlocked and running malware, weak passphrases, keys in hardware, metadata, availability
under a flood, or side channels in the libraries. The full list, including the recovery kit that
stays on the server until it is moved offline, is in [THREAT_MODEL.md](THREAT_MODEL.md), section 4.

## 10. Dependencies, notices and licence

- [DEPENDENCIES.md](DEPENDENCIES.md): Python packages and versions, and why each is used.
- [web/DEPENDENCIES.md](web/DEPENDENCIES.md): web packages.
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md): licences and sources of third-party code, fonts,
  components and test vectors.
- [SECURITY.md](SECURITY.md): reporting a vulnerability and running the scanners (`make scan`).
- [LICENSE](LICENSE): MIT.

## 11. Troubleshooting

| Problem | What to do |
|---|---|
| Port 8080 is already in use | Stop the other service, or change the left-hand side of `127.0.0.1:8080:8080` in `docker-compose.yml`. The port is bound to the loopback address only, so other machines cannot reach it |
| `make demo` or `make scenario-*` says the service is not running | Start the stack first with `docker compose up --build -d --wait`; these targets run inside the container |
| The console says the browser is not a secure context | Open `http://localhost:8080`, which browsers treat as secure. For HTTPS, start the TLS profile with `bash scripts/compose.sh --profile tls up -d --wait` and open `https://localhost:8443`; Caddy issues the certificate from its own local authority, so the browser warns until you trust that root. The profile is for local testing only |
| An enrolment code does not work | Codes are single use and last 24 hours, and running the invite command again cancels earlier codes. Run it again and use the newest code |
| Enrolment is on hold | A loss report is open for that person (rule QG-R011). An operator lifts the response under **Alerts** (`/app/ops/alerts`) |
| `QG_RATE_LIMITED` while enrolling or signing in repeatedly | Enrolment and sign-in are rate-limited per address. Wait a few seconds and try again |
| Start again with new keys and a new organisation | `docker compose down -v` deletes the data and keys volumes; the next start generates fresh keys, a fresh recovery kit and the seeded people again. Clear the site data for `localhost:8080` in the browser, because devices enrolled earlier no longer exist |
