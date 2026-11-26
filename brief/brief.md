# QuantumGuard

**After a device is reported lost, no request from it receives key material, every file whose key it received is listed and queued for new keys, and every decision is recorded in a log that verifies offline with public keys only.**

Track 4: Trust, but verify. Repository: https://github.com/AkashaPrasad/QuantumGuard. Demo video (5 minutes): https://drive.google.com/file/d/1dvVt6pceQgQA0AMLYYeipy75qnwlVrb3/view?usp=sharing.

## The problem

A lost laptop keeps working until its session or token expires, and removing the person's permission does nothing to keys the device already holds. After the incident, the only account of what the device could read is a log that its own operator could have edited, and files wrapped with classical key exchange can be read later by anyone who recorded the traffic.

## What is different

- **Two locks, two holders.** Each file key is wrapped for one device with X-Wing (X25519 with ML-KEM-768), then sealed again by the server. The device cannot open a file unless the server releases the slot at that moment; the server cannot open it without the device's private key.
- **Scoped revocation with a compromise time.** One database transaction revokes the device, deletes its key slots, ends its sessions and publishes a new dual-signed device list. The reporter gives the time the device was last safe; files are classified as exposed (released after that time), held (released before) or never released, and re-keyed in that order.
- **Evidence that verifies without us.** Every allow and deny is a receipt in a SHA-256 Merkle tree with checkpoints signed by Ed25519 and ML-DSA-65. A proof bundle verifies offline in the browser or with the command-line client, and a changed receipt is reported by its index.
- **Explainable detection.** Fourteen fixed rules, counters and a privilege graph; no machine learning. Each alert names the identity, the service and the event, its rule and the receipts behind it. Every automatic response but one is scoped to a session, device, identity, credential or source and can be lifted by an operator other than the person it contains; the exception, QG-R013, freezes all key release when the log fails its own check.

## Architecture

```
 DEVICE: holds private keys         EDGE: untrusted           BACKEND: decides, cannot read files
 browser console or qg CLI   --->   static site and     --->  gateway (session, MAC, sequence)
 encrypts files, wraps keys,        same-origin /api          policy engine (signed, deny by default)
 signs, verifies proofs                                       directory (dual-signed, epochs)
 keystore: Argon2id          <---   receipts, proofs,  <---  key release (sealed slots, 60 s lease)
                                    signed checkpoints        evidence log, detection, incidents
```

## Suite QG-1 (no negotiation)

| Use | Algorithm |
|---|---|
| Key exchange | X-Wing: X25519 with ML-KEM-768 (draft-connolly-cfrg-xwing-kem-11) |
| Device and server signatures | ML-DSA-65 with a context string per purpose |
| Trust records (directory, checkpoints) | Ed25519 and ML-DSA-65, both must verify |
| File contents and slot sealing | AES-256-GCM, 1 MiB chunks, every chunk bound to file, version and position |
| Derivation, request codes, log, keystore | HKDF and HMAC with SHA-384; SHA-256 Merkle tree (RFC 6962); Argon2id |

Primitives come from `cryptography` 50.0.2 (Python) and `@noble/post-quantum` 0.7.1 with Web Crypto (browser). Our code composes them and implements none.

## Measured

| Measure | Result |
|---|---|
| Time to enforce a revocation (server) | 11.5 ms median, 16 ms p95, range 2–17 ms (30 runs) |
| Loss report to lost device refused (client) | 16.4 ms median, range 5.1–21.5 ms |
| Detection: F1, false alerts, time to alert | F1 0.98 over 160 attacks; 1.164 false alerts per 1,000 benign events; 16.33 ms median to alert |
| Added latency per authenticated request | 1.459 ms p95 |
| Key slot release | 2.806 ms p95 |
| Protect / open throughput (16 MiB file) | 206 / 553 MB/s |

`make bench` and `make bench-detect` on one 12-core arm64 machine; runtime image 169 MB. Grace period: 60 s for the previous directory epoch, never across a revocation. Browser timings are not measured.

<div style="page-break-after: always"></div>

# Threat model

**Assets.** File contents; file keys (wrapped per device, sealed by the server); device private keys (passphrase-protected keystore); server signing and seal keys (`keys/` volume); the recovery kit (private half issued once to the operator and kept offline); the signed device directory; the signed policy; the evidence log.

**Attackers and what stops them.**

| Attacker | Stopped by |
|---|---|
| Finder or thief of an enrolled device | Report lost: one transaction revokes it, deletes its slots and sessions; later requests denied and alerted (QG-R001); new enrolments held (QG-R011) |
| Network attacker, including record now, decrypt later | Encryption on the device; X-Wing wraps; per-request HMAC with an increasing sequence number (QG-R002) |
| Thief of the data and keys volumes | File keys wrapped for device keys inside the server's seal; recovery wraps open only with the offline kit |
| Insider with an ordinary or admin account | Default-deny policy; only the owner re-keys a file; second admin approves role grants; no self-lift; unsigned privilege raises QG-R005 and QG-R007 |
| Keyless caller | Failed proofs answered per source address and claimed device; correct proofs always accepted |
| Untrusted edge | Sees only ciphertext and MAC-protected requests; signed objects checked against keys pinned at enrolment |

**Assumptions.** The standard algorithms and vetted libraries are sound. The live backend process is not taken over. Behind a proxy, `QG_TRUSTED_PROXIES` names it. The honest device's operating system and browser are not compromised. The server keys seen at first enrolment are genuine. The browser runs the code in this repository unmodified. Only server time is used for decisions.

**Limits: what we do not protect.** Anything a device decrypted before revocation. A person tricked into opening a file, or malware on an authorised, unlocked device. A weak passphrase beyond the cost of Argon2id. Hardware key protection: keys are software bytes, not hardware-backed or non-extractable. Metadata: names, sizes, recipients and every decision are visible to the server. Availability under a flood. Side channels in the libraries. Also: SLH-DSA is not enabled; pinned server keys and the highest epoch sit unauthenticated in browser storage; an opened file is held whole in memory; only the owner's devices re-key a file (the server cannot check re-encrypted contents), so a file whose owner has no unlocked device stays "new key pending"; devices enrolled with a code a thief used before the report are not revoked by it; files carry no recovery slot until a kit is issued; QG-R013 freezes all key release until acknowledged; QG-R008 asks someone opening ten or more files in a minute to sign in again (all measured false alerts); one API node only; the prototype is unaudited and for synthetic data only. An internal review found 12 weaknesses (2 High, 7 Medium, 3 Low) before submission; all are fixed, each with a regression test.

**Claims and tests** (full table with commands in `THREAT_MODEL.md`).

| Claim | Test | Status |
|---|---|---|
| Revoked device denied on every route, recorded, one QG-R001 alert | `tests/api/test_incidents.py::test_denied_attempt_recorded_on_any_route` | passes |
| No key release after revocation, 1,000 concurrent requests | `tests/reliability/test_revocation_race.py::test_revoke_races_1000_slot_requests` | passes |
| Exposed, held, never released; re-key order; contained | `make scenario-revoke` | passes |
| Official X-Wing, ML-KEM-768, ML-DSA-65 vectors; bit flip, reorder, truncation, wrong binding fail; both checkpoint signatures required | `tests/crypto/` (`make test-crypto`) | passes |
| Enrolment proves both keys; invites single use, 15 min | `tests/api/test_auth.py::test_enrol_requires_both_proofs` | passes |
| Replay ends the session; bad MAC refused; policy engine down means deny | `tests/api/test_auth.py` | passes |
| Crash mid re-key recovers; malformed input refused | `make scenario-interrupt` | passes |
| Tampered stored receipt caught at its index offline | `make scenario-verify` | passes |
| Data and keys volumes cannot open a recovery slot | `tests/api/test_recovery.py::test_data_and_keys_volumes_together_cannot_open_a_recovery_slot` | passes |
| Only the owner re-keys; a recipient cannot replace contents | `tests/attacks/test_r2_rekey_content.py` | passes |
| Self-approval refused; unsigned privilege quarantined (QG-R005) | `make scenario-privilege` | passes |
| 172 negative and review regression tests | `make test-security` | passes |
| Each of the fourteen rules fires with its response | `tests/detect/` (`make test-detect`) | passes |
| Every alert names the identity, the service and the event | `tests/detect/conftest.py::check_names` | passes |
