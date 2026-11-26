<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
  <img alt="QuantumGuard" src="docs/assets/logo-light.svg" width="460">
</picture>

**Post-quantum file protection with per-request identity checks, scoped device revocation<br>and an evidence log anyone can verify offline.**

[![CI](https://github.com/AkashaPrasad/QuantumGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/AkashaPrasad/QuantumGuard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-2438C7.svg)](LICENSE)
![Python 3.12](https://img.shields.io/badge/python-3.12-2438C7.svg)
![Suite QG-1](https://img.shields.io/badge/suite-X--Wing%20%C2%B7%20ML--DSA--65-2438C7.svg)
![Status](https://img.shields.io/badge/status-research%20prototype-5A607A.svg)

[Quick start](#quick-start) ·
[Evaluation guide](#evaluation-guide) ·
[Architecture](#architecture) ·
[Cryptography](#cryptography-suite-qg-1) ·
[Threat model](THREAT_MODEL.md) ·
[API](spec/API.md) ·
[Security](SECURITY.md)

</div>

---

## Overview

QuantumGuard encrypts sensitive files on the device and checks identity on every request. Each file
key is wrapped for one device and then sealed again by the server, so **neither side can open a file
alone**. When a device is reported lost, a single transaction removes its access, lists and re-keys
the affected files, and records every decision in a Merkle log that verifies offline with public
keys only.

> **The testable claim.** After a device is reported lost, no request from that device receives key
> material, every file whose key that device received is listed and queued for new keys, and every
> decision is recorded in a log that verifies offline. Reading a protected file from recorded traffic
> requires breaking both X25519 and ML-KEM-768.

> [!WARNING]
> QuantumGuard is a research prototype. It has not been audited, it stores keys in software, and it
> is meant for synthetic data only. See the limits in [THREAT_MODEL.md](THREAT_MODEL.md).

**Submission:** Team Underdawgs, Track 4, *Trust, but verify*. Two-page brief (USP, architecture, one-page
threat model): [PDF](brief/QuantumGuard-Brief-Team-Underdawgs.pdf) · [Word](brief/QuantumGuard-Brief-Team-Underdawgs.docx).
Demo video (5 minutes): [Google Drive](https://drive.google.com/file/d/1dvVt6pceQgQA0AMLYYeipy75qnwlVrb3/view?usp=sharing). Live instance: <https://quantum.spacesdrive.cc>.
Evaluators: start with the [Quick start](#quick-start), then follow the [Evaluation guide](#evaluation-guide).

### Highlights

- **Two locks, two holders.** File keys are wrapped with X-Wing (X25519 + ML-KEM-768) for one device,
  then sealed by the server. Release needs an allow decision and a 60-second lease bound to the session.
- **Scoped revocation with a compromise time.** Files are classified as *exposed*, *held* or *never
  released* relative to the moment the device was last safe, and re-keyed in that order.
- **Evidence that verifies without the operator.** Every allow and deny is a receipt in an RFC 6962
  Merkle tree with checkpoints signed by both Ed25519 and ML-DSA-65. Proof bundles verify in the
  browser or the CLI with no network access.
- **Explainable detection.** Fourteen deterministic rules, counters and a privilege graph, with no
  machine learning. Every alert names the identity, the service and the event, its rule and receipts;
  responses are scoped and liftable. Measured F1 0.98 with 1.2 false alerts per 1,000 benign events.
- **One container, Docker only.** The console, API and all tests run with Docker and Make on the host.

## Contents

- [Quick start](#quick-start)
- [Evaluation guide](#evaluation-guide)
- [Testing](#testing)
- [Scenarios](#scenarios)
- [Recovery kit](#recovery-kit)
- [Verifying evidence offline](#verifying-evidence-offline)
- [Architecture](#architecture)
- [Cryptography (suite QG-1)](#cryptography-suite-qg-1)
- [Detection rules](#detection-rules)
- [Performance](#performance)
- [Limitations](#limitations)
- [Repository layout](#repository-layout)
- [Troubleshooting](#troubleshooting)
- [Contributing, security and licence](#contributing-security-and-licence)

## Quick start

**Requirements:** Docker with Compose v2, Git, Bash and Make. Nothing else is installed on the host.

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

| Command | What it does |
|---|---|
| `docker compose up --build -d --wait` | Builds the image and starts one container on `127.0.0.1:8080`. On first start the server generates its own keys and a synthetic organisation; no key is shipped in the repository. The first build takes several minutes |
| `make demo` | Issues a demo recovery kit, enrols every seeded person through the public API, protects two sample files and runs the lost-device flow, so the incident, its timeline, the QG-R001 alert and the receipts are visible in the console |
| `make test` | Builds a test image and runs, with no network: the tooling tests, every Python suite, the security suite in strict mode, then the scenarios. Exits 0 only when everything passes |

`docker compose down` stops the stack; `docker compose down -v` also deletes its data and keys.

### Open the console

The server never prints or logs an enrolment code. Codes for the seeded people come from a local
command that needs access to the server's data, the same trust as owning the server:

```bash
docker compose exec quantumguard python -m qg.admin invite --all --json
```

Each code is 16 Crockford base32 characters in four groups (for example `K7QM-2XVD-9RTA-HB4N`), works
once and lasts 24 hours; running the command again cancels earlier codes. Use `--user-id usr_…` for one
person. `make demo` consumes codes itself, so run this command after it.

Open <http://localhost:8080>, choose **Launch console**, and enter a code on the **Enrol** screen with
a device name and a passphrase. The seeded organisation, Kestrel Biolabs, is entirely fictional:

| Person | Role | Lands on |
|---|---|---|
| Mira Okafor | admin | Overview |
| Tomas Lindqvist | admin | Overview |
| Priya Raman | operator | Overview |
| Jonas Weber | auditor | Overview |
| Aiko Tanaka | employee | Files |
| Daniel Mensah | employee | Files |

Add a second device from **Devices** (use a second browser profile). From the second device, **Report
lost** on the first one opens the incident an operator follows under **Incidents**. Only the owner's
devices re-key a file, so the owner signs in on a remaining device to finish re-keying.

## Evaluation guide

This section is written so that a reviewer or an automated pipeline can run every check from this
README alone. Every command runs from the repository root, needs only Docker (with Compose v2), Bash,
Make and Git, exits 0 on success and non-zero on failure, and prints machine-readable JSON where noted.

### Step by step

| # | Command | Pass criterion | Time (first run) |
|---|---|---|---|
| 1 | `docker compose up --build -d --wait` | exits 0; `docker compose ps` shows `quantumguard` as `healthy` | 3–8 min (image build) |
| 2 | `curl -fsS http://127.0.0.1:8080/healthz` | exits 0 and prints a JSON object | < 1 s |
| 3 | `make demo` | exits 0; the last line is JSON with `"scenario":"revoke","pass":true` | ~30 s |
| 4 | `make test` | exits 0 (tooling tests, every Python suite, strict security suite, scenarios) | 5–10 min |
| 5 | `make scenarios` | exits 0; six JSON lines, each with `"pass":true` | ~1 min |
| 6 | `make scenario-messaging` | exits 0; one JSON line with `"pass":true` | ~10 s |
| 7 | `docker compose exec -T quantumguard python -m qg.admin invite --all --json` | prints `{"invites":[…]}` with one single-use code per seeded person | < 2 s |
| 8 | Open <http://localhost:8080> and enrol with a code from step 7 | the console opens on Overview or Files | manual |
| 9 | `docker compose logs quantumguard \| grep '"event":"alert"'` | one JSON line per alert raised so far | < 1 s |
| 10 | `docker compose down -v` | removes the stack, its data and its keys | < 10 s |

Each scenario starts its own throwaway server inside the container, so steps 5 and 6 do not depend on
what earlier steps did. `make demo` deliberately leaves its incident in the main server so it can be
inspected in the console (**Incidents**, **Alerts**, **Evidence**).

### Driving the system from a script

The command-line client is installed in the container, so a pipeline can create test identities, act
as them and read alerts without a browser. The keystore passphrase comes from `QG_PASSPHRASE`; keystores
under `/tmp` live in the container's memory and disappear when it stops. The runtime image is hardened
and has no shell, so every step is a single `python` command.

```bash
# 1. single-use enrolment codes for the six seeded people (Priya Raman is the operator)
docker compose exec -T quantumguard python -m qg.admin invite --all --json

# 2. enrol an operator device and an employee device (replace the codes with ones printed above)
docker compose exec -T -e QG_PASSPHRASE=eval-passphrase quantumguard python -m qg.client enroll \
  --server http://127.0.0.1:8080 --code PRIYA-CODE --device-name eval-operator --keystore /tmp/priya.qgkeystore --json
docker compose exec -T -e QG_PASSPHRASE=eval-passphrase quantumguard python -m qg.client enroll \
  --server http://127.0.0.1:8080 --code AIKO-CODE --device-name eval-laptop --keystore /tmp/aiko.qgkeystore --json

# 3. act as the employee: protect a file and list devices
docker compose exec -T quantumguard python -c "import os; open('/tmp/sample.bin', 'wb').write(os.urandom(4096))"
docker compose exec -T -e QG_PASSPHRASE=eval-passphrase quantumguard python -m qg.client protect /tmp/sample.bin \
  --name sample.bin --classification confidential --keystore /tmp/aiko.qgkeystore --json
docker compose exec -T -e QG_PASSPHRASE=eval-passphrase quantumguard python -m qg.client devices --keystore /tmp/aiko.qgkeystore --json

# 4. revoke the employee's device as the operator (time is RFC 3339, UTC), then show the device is refused
docker compose exec -T -e QG_PASSPHRASE=eval-passphrase quantumguard python -m qg.client revoke DEVICE-ID \
  --compromise-time 2026-01-01T00:00:00Z --reason "evaluation" --keystore /tmp/priya.qgkeystore --json
docker compose exec -T -e QG_PASSPHRASE=eval-passphrase quantumguard python -m qg.client devices --keystore /tmp/aiko.qgkeystore
#    -> exits 1 with QG_DENY_REVOKED

# 5. read the alerts: each names the identity, the service and the event
docker compose exec -T -e QG_PASSPHRASE=eval-passphrase quantumguard python -m qg.client alerts --keystore /tmp/priya.qgkeystore --json

# 6. send an identity-provider signal (CAEP session-revoked, credential-change or device-compliance-change)
docker compose exec -T -e QG_PASSPHRASE=eval-passphrase quantumguard python -m qg.client signal \
  --type session-revoked --subject USER-ID --keystore /tmp/priya.qgkeystore --json
```

Integration points for mock services, synthetic logs and test identities:

| Need | How |
|---|---|
| Test identities | `python -m qg.admin invite --all --json` for the seeded people; admins invite new people in the console (**People**) or with `POST /api/v1/invites` |
| Identity-provider events | `POST /api/v1/signals` with a Security Event Token shaped body (`qg signal`): CAEP `session-revoked`, `credential-change`, `device-compliance-change`, and `urn:qg:event-type:privilege-observed` for roles seen in the identity source |
| Service credentials | `POST /api/v1/services` creates a service with a key; `POST /api/v1/services/{id}/rotate` rotates it (routine or emergency); requests present it in `QG-Service-Key` |
| Security event stream | JSON lines with `"event":"alert"` on the container's standard output, `SECURITY_EVENTS.jsonl` in the data volume, `GET /api/v1/alerts` and `qg alerts` |
| Full API | [spec/API.md](spec/API.md) and [spec/openapi.json](spec/openapi.json); every byte format in [spec/SUITE.md](spec/SUITE.md) |

### Checklist answers

Every number below comes from a command in this repository; rerun it to reproduce.

| Item | Value | Source |
|---|---|---|
| Grace period | Objects may name the previous directory epoch for **60 s**, never one from before a revocation (QG-R003). Key-release lease **60 s**; session idle timeout **600 s**, hard cap **3,600 s**; a routinely rotated service key keeps working for **600 s** | `backend/qg/crypto/suite.py`, `backend/qg/api/services.py` |
| Revocation time (server) | median **11.5 ms**, p95 **16 ms**, range **2–17 ms** over 30 runs, from the start of the report handler to the committed revocation | `make bench` → `bench/latest.json` `time_to_enforce_ms` |
| Revocation time (client) | median **16.4 ms**, p95 **20.9 ms**, range **5.1–21.5 ms**, from sending the loss report to the lost device's next request being refused | `make bench` → `report_to_denied_ms` |
| Timing range of alerts | **0.92–75.5 ms** from an attack's first malicious request to its stored alert | `make bench-detect` → `bench/detection.json` |
| F1 | **0.982** (precision 0.964, recall 1.000) over 160 injected attacks, including three variants the rules were not written against | `make bench-detect` |
| Median time to alert | **16.33 ms** (p95 44.09 ms) | `make bench-detect` |
| False alerts per 1,000 benign events | **1.164** (6 false alerts over 5,156 audited benign decisions; all QG-R008 when a person opened a folder of 10+ files within a minute) | `make bench-detect` |
| Rejected on every node and after a crash or restart | One API node with one SQLite database (`synchronous=FULL`); the revocation commits before the report returns. `make scenario-interrupt` kills the server mid re-key, restarts it and shows the revoked device still refused and no key released to it. Several API nodes are not supported | `make scenario-interrupt`, `tests/reliability/` |
| Every alert names the identity, service and event | `identity` (person and name, device, session; source address and claimed id before a key is proven), `service`, `event` (kind, time, details) on every alert, in the API, the logs and `SECURITY_EVENTS.jsonl` | `tests/detect/conftest.py::check_names`, `make test-detect` |
| No hard-coded secrets | Server keys are generated on first start into the `keys` volume; enrolment codes come only from a local command; gitleaks scans the tree and the whole history in CI | `make scan-secrets` |
| No AI/ML components | Fourteen fixed rules, counters and a privilege graph; `scripts/check_banned_deps.py` fails the build on any ML or LLM package | `make preflight`, `make scan` |
| Vetted PQC library | ML-KEM-768 and ML-DSA-65 from `cryptography` 50.0.2 (OpenSSL 4.0.3) in Python and `@noble/post-quantum` 0.7.1 in the browser; official NIST ACVP, Wycheproof and X-Wing vectors pass | `make test-crypto` |

### Where each scoring area is evidenced

| Area | Evidence |
|---|---|
| Security correctness | `make test-crypto` (official vectors, properties), `make test-security` (172 negative and regression tests), [THREAT_MODEL.md](THREAT_MODEL.md) section 5 (each claim with its test) |
| Live security assessment | Fourteen detection rules with scoped, liftable responses ([Detection rules](#detection-rules)); alerts in the console, the API, the logs and `qg alerts`; measured detection quality above |
| Functionality and reliability | `make scenario-normal`, `scenario-revoke`, `scenario-interrupt` (crash and restart), `scenario-verify` (offline evidence); `make test-reliability` (1,000 concurrent requests racing a revocation) |
| Threat model and honesty | [THREAT_MODEL.md](THREAT_MODEL.md): assets, attackers, assumptions, 24 stated limits, claims with tests, review findings |
| Performance and overhead | [Performance](#performance), `make bench`, `make bench-detect` |
| Usability and documentation | The console at <http://localhost:8080> with a guided tour; this README; [spec/](spec/) |

## Testing

| Command | Runs | Needs |
|---|---|---|
| `make test` | Every Python suite and the scenarios inside a Docker test image | Docker |
| `make scenario-<name>` | One scenario inside the running container | Docker, running stack |
| `make readme-test` | This README's quick-start block in a clean, isolated Docker daemon | Docker |
| `make setup` | Python and web dependencies from the lockfiles | `uv`, `pnpm` |
| `make test-crypto` | Known-answer, vector and property tests (353 in Python) plus the browser crypto tests | host, after `make setup` |
| `make test-api` | 41 endpoint tests (`make fuzz` runs Schemathesis fuzzing) | host, after `make setup` |
| `make test-security` | 172 negative security and regression tests | host, after `make setup` |
| `make test-detect` | 18 tests, at least one per detection rule | host, after `make setup` |
| `make test-reliability`, `make test-unit` | The 1,000-request revocation race; CLI and browser client unit tests | host, after `make setup` |
| `make test-e2e`, `make test-a11y` | 184 browser interaction tests and 77 accessibility checks | host, Playwright browsers |
| `pnpm --dir web run test:e2e:live` | The browser client against a real server (API on 8091, web on 5181) | host, Playwright browsers |
| `make verify` | Preflight, spec lint, lint, types, all host tests and scenarios, secret scan | host, after `make setup` |
| `make scan` | gitleaks, semgrep, bandit, pip-audit, pnpm audit, trivy, hadolint, ZAP | Docker |

[THREAT_MODEL.md](THREAT_MODEL.md) maps each security claim to its test, the command that runs it and
its status. `make test-security` also writes `claims.json` with the outcome of every test id.

## Scenarios

Each scenario starts its own throwaway server, prints exactly one JSON line and exits 0 on pass and 1
on failure. Ids, hashes and timings differ on every run.

| Objective | Command |
|---|---|
| **Normal operation:** an admin invites a person, who enrols, signs in, protects a file and opens it | `make scenario-normal` |
| **Security control:** a device is reported lost with a past loss time; it is denied and its files are scoped and re-keyed | `make scenario-revoke` |
| **Reliability:** the server is killed mid re-key and restarted; duplicate revokes, malformed input, a policy outage | `make scenario-interrupt` |
| **Verifiable outcome:** a receipt and a proof bundle verify offline; a changed stored receipt is caught at its index | `make scenario-verify` |
| **Service key rotation:** routine and emergency rotation; a retired key is refused | `make scenario-rotate` |
| **Unexpected privilege change:** an unsigned role is quarantined; self-approval is refused; a two-person change applies | `make scenario-privilege` |
| **Messaging revocation:** after one recipient device is revoked, messages reach only the remaining device | `make scenario-messaging` |

<details>
<summary>Example result line (<code>make scenario-revoke</code>)</summary>

```json
{"scenario":"revoke","pass":true,"time_to_enforce_ms":2,"exposed":1,"held":1,"never_released":1,"denied_after_revoke":true,"alert_rule":"QG-R001","receipt_id":"rcp_…","checkpoint_root":"…","sessions_ended":1,"slots_deleted":3,"incident_status":"contained","rekey_order":["exposed","held"]}
```

</details>

## Recovery kit

Each file can carry a recovery wrap, so it can still be opened when every device that held it is gone.
The recovery kit is an X-Wing private key the server never holds. The operator issues it once:

```bash
make recovery-kit
```

This prints the kit (format `qg-recovery-kit/1`) to your terminal; store it offline. The server keeps
only the public half and publishes it in a new directory epoch. A second run is refused.

- Until a kit exists, files carry no recovery slot; files committed earlier stay without one.
- `make demo` issues a demo kit inside the container at `/tmp/qg-demo/recovery-kit.json` (memory-backed,
  lost on restart). Copy it out with `docker compose cp quantumguard:/tmp/qg-demo/recovery-kit.json .`
- Releasing a file takes a `recovery_release` change approved by two admins or operators other than the
  requester. The kit holder then opens the file with the CLI on a trusted machine:

  ```bash
  PYTHONPATH=backend:cli uv run --project backend python -m qg.client recover fil_… \
    --change chg_… --kit recovery-kit.json --out recovered.bin --keystore admin.qgkeystore
  ```

## Verifying evidence offline

Receipts are leaves of a SHA-256 Merkle tree (RFC 6962 hashing). Checkpoints carry both an Ed25519 and
an ML-DSA-65 signature, and both must verify. An incident's proof bundle holds its receipts with
inclusion paths, the revocation checkpoint, a consistency proof to the latest checkpoint, the exposure
report and the signed directory, and is itself dual-signed.

1. **Automatically:** `make scenario-verify`.
2. **In the browser:** as operator or auditor, open the incident, choose **Export proof bundle**, then
   load it on **Verify** (`/app/evidence/verify`). Verification makes no network request.
3. **With the CLI:**

   ```bash
   PYTHONPATH=backend:cli uv run --project backend python -m qg.client server-keys --server http://localhost:8080 --out server-keys.json
   PYTHONPATH=backend:cli uv run --project backend python -m qg.client verify bundle.json --keys server-keys.json
   ```

   The first command pins the server's public keys. The second runs offline, prints one `[ok]` or
   `[FAIL]` line per step and exits 1 on any failure, reporting `first bad index: <n>` for a changed
   receipt. Add `--json` for machine-readable output.

## Architecture

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

Locally, one container serves the static console and the API on one origin.

| Component | Code | Responsibility |
|---|---|---|
| Client crypto | `web/src/crypto/`, `cli/qg/client/` | Encrypts files in 1 MiB chunks, wraps file keys, signs manifests, opens files |
| Device keystore | `web/src/crypto/keystore.ts`, `backend/qg/crypto/keystore.py` | Key seeds under AES-256-GCM with an Argon2id key from the passphrase |
| Gateway | `backend/qg/gateway/http.py` | Session, request MAC, sequence number, device status, rate limits, active responses |
| Policy engine | `backend/qg/policy/` | Default deny; rules in `rules.yaml`, dual-signed; unavailable means deny |
| Directory | `backend/qg/directory/` | Signed list of people, devices and public keys; the epoch only increases |
| Key release | `backend/qg/api/files.py` | Sealed slots, unsealed only after an allow decision, with a 60-second session-bound lease |
| Incidents | `backend/qg/incidents/` | Revocation transaction, exposure classification, re-key queue, proof bundle |
| Evidence log | `backend/qg/log/` | Receipts, Merkle tree, checkpoints, inclusion and consistency proofs, verifier |
| Detection | `backend/qg/detect/` | Fourteen rules with scoped, liftable responses |
| Storage | `backend/qg/storage/` | SQLite in WAL mode and a ciphertext blob store |
| Local admin | `backend/qg/admin.py` | Enrolment codes, the recovery kit, policy drills, decoy ids |

The API contract is [spec/API.md](spec/API.md); every byte two implementations must agree on is in
[spec/SUITE.md](spec/SUITE.md). An optional hosted setup (API on AWS, console on Cloudflare) is
described in [deploy/README.md](deploy/README.md).

## Cryptography (suite QG-1)

One fixed suite, no negotiation. Any other suite name, at any depth of a request, is refused with
`QG_BAD_SUITE`.

| Use | Algorithm | Python | Browser |
|---|---|---|---|
| Key exchange (file wraps, recovery, enrolment, sessions, messages) | X-Wing: X25519 + ML-KEM-768 (draft-connolly-cfrg-xwing-kem-11) | `cryptography` 50.0.2 | `@noble/post-quantum` 0.7.1 |
| Device and server signatures | ML-DSA-65 (FIPS 204), hedged, per-purpose context | `cryptography` 50.0.2 | `@noble/post-quantum` 0.7.1 |
| Long-lived trust records | Ed25519 **and** ML-DSA-65, both required | `cryptography` 50.0.2 | `@noble/curves` 2.4.0, `@noble/post-quantum` 0.7.1 |
| File contents and slot sealing | AES-256-GCM | `cryptography` 50.0.2 | Web Crypto / `@noble/ciphers` 2.4.0 |
| Key derivation and request codes | HKDF-SHA-384, HMAC-SHA-384 | `cryptography`, `hmac` | Web Crypto / `@noble/hashes` 2.4.0 |
| Evidence log | SHA-256 Merkle tree, RFC 6962 | `hashlib` | Web Crypto / `@noble/hashes` 2.4.0 |
| Passphrase to keystore key | Argon2id (19 MiB, 2 passes, 1 lane) | `argon2-cffi` 25.1.0 | `@noble/hashes` 2.4.0 |

QuantumGuard composes these primitives and implements none. Python passes the official X-Wing,
ML-KEM-768 (NIST ACVP, Wycheproof) and ML-DSA-65 (NIST ACVP) vectors; the browser passes the same X-Wing
vectors and the project's own vectors for every encoding, transcript and envelope.

## Detection rules

Deterministic rules in `backend/qg/detect/rules/`. Alerts appear at `GET /api/v1/alerts`, as JSON log
lines with `"event":"alert"`, and in `SECURITY_EVENTS.jsonl` in the data volume. An operator can lift a
response, but never one that contains themselves.

| Rule | Trigger | Automatic response |
|---|---|---|
| QG-R001 | Request or session attempt from a revoked device | Deny; attach to the incident |
| QG-R002 | Sequence number not greater than the last accepted (replay) | End that session |
| QG-R003 | Object built on a stale directory epoch or from before a revocation | Deny; require a fresh session proof |
| QG-R004 | Decoy file or decoy service key touched | Quarantine the device until lifted |
| QG-R005 | Role in the identity source with no signed change | Quarantine the person for sensitive files; cancel leases |
| QG-R006 | Self-granted role followed within 10 minutes by sensitive access | Quarantine the person for sensitive files |
| QG-R007 | Unapproved role opens a path to the recovery key and restricted files | Alert with the path |
| QG-R008 | Key releases per minute above EWMA mean + 3σ | Require a fresh session proof |
| QG-R009 | 20+ not-found or denied answers in 60 s on one session | Throttle the session for 5 minutes |
| QG-R010 | Retired service key presented | Deny the key |
| QG-R011 | Enrolment while a loss report is open for the same person | Hold enrolment until lifted |
| QG-R012 | Repeated failed key proofs, bad MACs or signature failures | Refuse failed proofs from that source for 5 minutes, or throttle the session |
| QG-R013 | The stored log fails its own consistency check | Freeze all key release until acknowledged (the one global response) |
| QG-R014 | Suite other than `QG-1` requested | Deny |

## Performance

From [bench/latest.json](bench/latest.json) and [bench/detection.json](bench/detection.json), measured on
a 12-core arm64 machine with Python 3.12, server and client on one host over loopback. Run `make bench`
and `make bench-detect` to measure on your machine. Browser timings and idle memory are not measured.

| Measure | Median | p95 | Range | Target (p95) |
|---|---|---|---|---|
| Time to enforce a revocation (server, 30 runs) | 11.5 ms | 16 ms | 2–17 ms | < 100 ms |
| Loss report sent to lost device refused (client, 30 runs) | 16.4 ms | 20.9 ms | 5.1–21.5 ms | |
| Time to alert (160 attacks) | 16.33 ms | 44.09 ms | 0.92–75.5 ms | |
| Slot release (client-measured) | 1.192 ms | 2.806 ms | | < 20 ms |
| Added latency of an authenticated request | 0.6 ms | 1.459 ms | | < 3 ms |
| Policy decision | 0.003 ms | 0.004 ms | | < 5 ms |
| Session handshake | 3.0 ms | 4.064 ms | | |
| Cold start | 0.319 s | | | < 10 s |
| Runtime image (unpacked) | 169 MB | | | < 250 MB |

Protect and open throughput on a 16 MiB file: 206.0 and 553.3 MB/s. The compressed
image is 36.7 MiB. Size overhead: 28 bytes per 1 MiB chunk and
125 bytes of headers per request. Batched checkpoint signing costs 0.29 ms per 1,000 receipts,
against about 416 ms if each receipt were signed.

## Limitations

QuantumGuard does not protect what a device decrypted before it was revoked, an unlocked authorised
device running malware, weak passphrases, hardware-held keys, metadata, availability under a flood, or
side channels in the libraries. Only the owner's devices re-key a file, so a file whose owner has no
unlocked device stays "new key pending". The full list is in [THREAT_MODEL.md](THREAT_MODEL.md),
section 4; findings from the internal security review, all fixed, are in section 6.

## Repository layout

```
backend/        Python API server (qg): crypto, gateway, policy, directory, incidents, log, detection
cli/            qg command-line client and the scenario harness
web/            React console, browser crypto client, Playwright suites
spec/           API contract, byte-level suite spec, OpenAPI, JSON schemas, test vectors
tests/          api, crypto, detect, security, attacks, reliability, perf and unit suites
scenarios/      Source-checkout entry point for the scenarios
bench/          Benchmark harness and the latest results
deploy/         Optional hosted deployment (Terraform for AWS, Cloudflare Worker)
scripts/        Container build, scanners, git hooks and test gates
docs/assets/    Logo and brand assets
```

## Troubleshooting

<details>
<summary>Common problems and fixes</summary>

| Problem | What to do |
|---|---|
| Port 8080 is already in use | Stop the other service, or change the left-hand side of `127.0.0.1:8080:8080` in `docker-compose.yml` |
| `make demo` or `make scenario-*` says the service is not running | Start the stack with `docker compose up --build -d --wait`; these targets run inside the container |
| The console says the browser is not a secure context | Use `http://localhost:8080`. For HTTPS run `bash scripts/compose.sh --profile tls up -d --wait` and open `https://localhost:8443` (local CA; trust its root to silence the warning) |
| Everyone shares one rate limit behind a reverse proxy | Add the proxy's address to `QG_TRUSTED_PROXIES` (default `127.0.0.1`) in `docker-compose.yml` |
| `QG_RATE_LIMITED` while enrolling or signing in | Enrolment and sign-in are rate-limited per address. Wait, or an operator lifts the response under **Alerts** |
| An enrolment code does not work | Codes are single use, last 24 hours and are cancelled by a newer invite or a loss report. Issue a new one |
| Enrolment is on hold | A loss report is open for that person (QG-R011); an operator lifts it under **Alerts** |
| A file stays "new key pending" | The owner unlocks one of their remaining devices, which re-keys pending files |
| Start again from scratch | `docker compose down -v`, then clear site data for `localhost:8080` in the browser |

</details>

## Contributing, security and licence

- [CONTRIBUTING.md](CONTRIBUTING.md): development setup, checks and commit conventions.
- [SECURITY.md](SECURITY.md): reporting a vulnerability privately and running the scanners.
- [THREAT_MODEL.md](THREAT_MODEL.md): assets, adversaries, claims and their tests, limits.
- [DEPENDENCIES.md](DEPENDENCIES.md) and [web/DEPENDENCIES.md](web/DEPENDENCIES.md): pinned packages and why each is used.
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md): licences of third-party code, fonts and test vectors.

Released under the [MIT License](LICENSE).
