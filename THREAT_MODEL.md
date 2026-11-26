# QuantumGuard threat model

QuantumGuard protects a sensitive file so that, when a device is reported lost, no request from that
device receives key material, every file whose key that device received is listed and queued for new
keys, and every decision is recorded in a log that verifies offline with public keys only.

This document states what is protected, from whom, under which assumptions, and where the protection
ends. Every claim in it is linked to a test in this repository. It describes a prototype that has not
been audited and that is run with synthetic data only.

## 1. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| File contents | Encrypted on the device in 1 MiB AES-256-GCM chunks; the server stores ciphertext only | The thing being protected |
| File keys (one random 32-byte key per file version) | Wrapped per recipient device with X-Wing (inner wrap), then sealed by the server (outer seal) as a key slot | Whoever holds a file key reads that version |
| Device private keys (X-Wing seed, ML-DSA-65 seed) | In a passphrase-protected keystore: a `*.qgkeystore` file for the command-line client, IndexedDB in the browser | They open inner wraps and prove the device in every session |
| Server keys (Ed25519 and ML-DSA-65 signing seeds, seal master key) | `keys/` volume, never in the database | They sign the directory and checkpoints and seal key slots |
| Recovery kit (an X-Wing private key) | Written once to `keys/recovery-kit.json` at first start | It opens the recovery wrap that every file carries |
| Device directory | Dual-signed object with an epoch that only increases | Decides which devices and public keys are current |
| Policy bundle | `backend/qg/policy/rules.yaml`, dual-signed at first start | Decides every allow or deny |
| Evidence log | SHA-256 Merkle tree of receipts with dual-signed checkpoints | The record an operator, auditor or reviewer checks afterwards |

## 2. Attackers

| Attacker | Capability | What stops them | Claims |
|---|---|---|---|
| Someone who finds or steals an enrolled device | Holds the device, its keystore and anything it saved; may have an unlocked session | Report lost (from another device) or operator revoke runs one transaction: device revoked, its key slots deleted, its sessions ended, its leases cancelled, a new signed directory published, a checkpoint forced. Later requests are refused with `QG_DENY_REVOKED`, recorded, and raise QG-R001. New enrolments for that person are held while the report is open (QG-R011). The keystore needs the passphrase (Argon2id) | C1 to C8 |
| A network attacker, including one who records traffic now for a future quantum computer | Reads, records, replays and alters traffic | File contents are encrypted on the device. File keys are wrapped with X-Wing, so both X25519 and ML-KEM-768 must be broken. Sessions start with proof of both device keys; each request carries an HMAC-SHA-384 code over method, path, sequence number and body hash; a sequence number that does not increase ends the session (QG-R002) | C9 to C20, C24 to C28 |
| Someone who copies the server database and blob store | Reads every row and every ciphertext, but not the `keys/` volume | Key slots are sealed with a key derived from the seal master key, which lives in `keys/`; inside each seal the file key is wrapped for a device's X-Wing public key. Neither layer opens without a key the copy does not contain | C39 |
| A curious or malicious insider with an ordinary or administrative account | Signs in normally and calls any route | Default-deny policy on every route; files are visible only to their owner and to devices holding a slot; other people's objects answer `QG_NOT_FOUND`; granting `admin` or `operator` needs approval from a different admin; recovery release needs two approvals from other admins or operators; a privilege that appears with no signed change raises QG-R005 and QG-R007; decoy objects raise QG-R004 | C36 to C41 |
| An untrusted edge or content delivery network between the person and the backend | Sees and can alter every request and response | Contents and file keys cross only as ciphertext and wrapped keys; requests carry a per-session MAC; directories, checkpoints and certificates are dual-signed and checked against server keys pinned at enrolment; an older directory is refused. The edge serves the web application itself, which is a limit (section 4, item 15) | C17, C22, C43 |

## 3. Assumptions

1. The standardised algorithms and the libraries that implement them (section 8) are sound.
2. The backend process and its `keys/` volume are not taken over while the server runs. A copy of the
   database is covered; an attacker who runs code inside the live backend, or who holds both the
   database and the `keys/` volume, is not.
3. The operating system and browser on an honest device are not already compromised.
4. The server public keys a device receives at enrolment are the real ones. They are pinned then and
   a different key later is refused; the first contact itself is trusted.
5. The web application the browser loads is the code in this repository, served unmodified.
6. Server time is the only time used for decisions; a client clock is never trusted.
7. Security signals (`POST /api/v1/signals`) come from an operator or a service identity with a valid
   session; their content is believed.

## 4. Limits: what we do not protect

The first seven items are the list shown on the public page.

1. Anything a device already decrypted before it was revoked. We list it; we cannot recall it.
2. A person who is tricked into opening a file for an attacker, or malware on a device that is
   currently authorised and unlocked.
3. A weak passphrase on a stolen device, beyond the cost that slow key derivation imposes and the time
   it buys to revoke. The keystore uses Argon2id with 19 MiB of memory, 2 passes and 1 lane.
4. Hardware-level key protection. The prototype stores keys in software; a production version would
   use a secure element or hardware module.
5. Metadata. The backend knows who opened which file and when; that is what makes the exposure report
   possible.
6. Availability against a determined flood. We rate-limit and fail closed, which protects data, not
   uptime.
7. Side-channel attacks on the cryptographic libraries, which we rely on the library authors to
   address.
8. Browser device keys are passphrase-wrapped bytes in IndexedDB, created with a JavaScript library.
   They are not hardware-backed and not held as non-extractable Web Crypto keys. While the console is
   unlocked the key seeds are in page memory; they are zeroed on lock.
9. SLH-DSA is not enabled. The Python `cryptography` package used here does not ship it, so there is
   no hash-based signature in the suite.
10. In the browser, the pinned server keys and the highest directory epoch seen are stored in IndexedDB
    next to the keystore, outside the passphrase-protected part. Anyone who can write to that browser
    profile's storage can replace them.
11. An opened file is held whole in memory (a `Blob` in the browser, a byte string in the command-line
    client) before it is saved. The largest file accepted is 100 MiB.
12. File names, sizes, classifications and recipient lists are visible to the server.
13. The recovery kit is written to the server's `keys/` volume at first start and stays there until an
    operator moves it offline. Until then, a copy of the database together with the `keys/` volume
    opens every file through its recovery wrap. The two-approval rule for recovery release is enforced
    by the server's policy, not by cryptography.
14. QG-R013 (evidence log mismatch) freezes every key release until an operator acknowledges the
    alert. It is the one automatic response that is not scoped to a session, device, identity or
    credential.
15. The browser runs whatever code the origin serves. A malicious server or edge that changes the web
    application can read passphrases and keys in the browser. The command-line client does not have
    this exposure.
16. Sessions are kept in server memory. A server restart ends every session, and devices sign in
    again.
17. The local Docker stack serves plain HTTP on `127.0.0.1:8080`. Transport encryption is not part of
    any claim; the optional TLS profile is for local testing only.
18. The prototype is unaudited, was built in a short time, and is meant for synthetic data only.

## 5. Claims and tests

The status column is the result of running each command on the host on 26 November 2026 at commit
`a7e941e`. The `make test-*` and `make dev-scenario-*` targets need `uv` (and `pnpm` for the `web/`
tests) after `make setup`; `make scenario-<name>` runs the same scenario inside the running container.
`make test` runs every Python suite and six scenarios inside a Docker test image, with the security
suite in strict mode, where a skipped test counts as a failure. `make test-security` writes
`claims.json` with the outcome of every test id.

### Revocation and lost devices

| Id | Claim | Test | Command | Status |
|---|---|---|---|---|
| C1 | A revoked device cannot start a session | `tests/security/test_negative_claims.py::test_revoked_device_cannot_start_session`; `tests/api/test_incidents.py::test_denied_session_attempts_counted_and_one_alert` | `make test-security`, `make test-api` | passes |
| C2 | A request from a revoked device on any route is refused with `QG_DENY_REVOKED`, gets a receipt, appears on the incident timeline and raises one QG-R001 alert | `tests/api/test_incidents.py::test_denied_attempt_recorded_on_any_route`; `tests/detect/test_qg_r001.py::test_revoked_device_attempt_denied_and_alerted` | `make test-api`, `make test-detect` | passes |
| C3 | A revoked device's existing session dies in the same transaction that deletes its key slots; repeating the revoke returns the same incident; a corrected compromise time re-scopes it | `tests/security/test_negative_claims.py::test_revoked_devices_existing_session_dies_in_same_transaction`; `tests/api/test_incidents.py::test_revoke_result_and_idempotence` | `make test-security`, `make test-api` | passes |
| C4 | No key material reaches a device after its revocation while slot requests race the revoke (1,000 requests in the reliability test) | `tests/reliability/test_revocation_race.py::test_revoke_races_1000_slot_requests`; `tests/security/test_revocation_race.py::test_revoked_device_gets_no_slot_under_concurrent_release` | `make test-reliability`, `make test-security` | passes |
| C5 | After a loss report, files are classified as exposed, held or never released against the loss time, re-keyed exposed first, and stay readable by the remaining devices | `cli/qg/scenarios/revoke.py::run` | `make scenario-revoke` | passes |
| C6 | An incident cannot be closed while files still wait for new keys | `tests/api/test_incidents.py::test_close_requires_rekey` | `make test-api` | passes |
| C7 | Enrolment for a person with an open loss report is held (QG-R011) until an operator lifts the response | `tests/api/test_incidents.py::test_enrolment_held_while_loss_open`; `tests/detect/test_qg_r011.py::test_enrolment_held_during_open_loss_report` | `make test-api`, `make test-detect` | passes |
| C8 | An expired lease stops a download in the middle of a file | `tests/security/test_negative_claims.py::test_expired_lease_stops_download_mid_file` | `make test-security` | passes |

### Cryptography and binding

| Id | Claim | Test | Command | Status |
|---|---|---|---|---|
| C9 | X-Wing matches the three Appendix C vectors of draft-connolly-cfrg-xwing-kem-11 (Python and browser) | `tests/crypto/test_official_kats.py::test_xwing_draft11`; `web/src/crypto/primitives.test.ts::draft-11 Appendix C vector` | `make test-crypto` | passes |
| C10 | ML-KEM-768 matches NIST ACVP key generation and C2SP Wycheproof decapsulation vectors | `tests/crypto/test_official_kats.py::test_mlkem768_keygen`; `tests/crypto/test_official_kats.py::test_mlkem768_decaps_wycheproof` | `make test-crypto` | passes |
| C11 | ML-DSA-65 matches NIST ACVP key generation and signature verification with context vectors | `tests/crypto/test_official_kats.py::test_mldsa65_keygen`; `tests/crypto/test_official_kats.py::test_mldsa65_sigver_with_context` | `make test-crypto` | passes |
| C12 | A single bit flip anywhere in a protected file fails decryption | `tests/crypto/test_properties.py::test_any_single_bit_flip_fails`; `tests/security/test_negative_claims.py::test_ciphertext_bit_flip_fails`; `web/src/crypto/envelope.test.ts::a single bit flip anywhere fails` | `make test-crypto`, `make test-security` | passes |
| C13 | Reordered or truncated chunks and a wrong AAD fail; a chunk from another file fails | `tests/crypto/test_properties.py::test_reorder_truncate_and_wrong_aad_fail`; `tests/crypto/test_properties.py::test_chunk_from_other_file_with_same_key_fails`; `tests/security/test_negative_claims.py::test_chunk_reordered_or_truncated_fails`; `tests/security/test_negative_claims.py::test_wrong_aad_fails` | `make test-crypto`, `make test-security` | passes |
| C14 | A chunk nonce never repeats within a file version | `tests/crypto/test_properties.py::test_nonce_never_repeats_within_file` | `make test-crypto` | passes |
| C15 | An inner wrap opens only for its device, file, version and directory epoch; a key slot moved to another file or another device fails | `tests/crypto/test_properties.py::test_wrap_bound_to_device_file_version_epoch`; `tests/security/test_negative_claims.py::test_slot_moved_to_another_context_fails`; `web/src/crypto/envelope.test.ts::a wrap bound to another file, version, device or epoch fails; wrong device key fails` | `make test-crypto`, `make test-security` | passes |
| C16 | An outer seal opens only for its slot | `tests/crypto/test_properties.py::test_seal_bound_to_slot` | `make test-crypto` | passes |
| C17 | A checkpoint is accepted only when both the Ed25519 and the ML-DSA-65 signature verify under the right keys and purpose | `tests/crypto/test_qg_vectors.py::test_checkpoint_vectors`; `tests/security/test_negative_claims.py::test_checkpoint_with_one_bad_signature_rejected`; `web/src/crypto/merkle.test.ts::checkpoint verifies under the dual-signature rule` | `make test-crypto`, `make test-security` | passes |
| C18 | The Python and browser clients produce the same bytes for canonical JSON, request MACs, transcripts, file envelopes and keystores | `tests/crypto/test_qg_vectors.py` (all tests); `web/src/crypto/encoding.test.ts`, `web/src/crypto/protocol.test.ts`, `web/src/crypto/envelope.test.ts`, `web/src/crypto/keystore.test.ts` (vector tests) | `make test-crypto` | passes |
| C19 | A keystore opened with a wrong passphrase or a modified header fails | `tests/crypto/test_qg_vectors.py::test_keystore_must_fail` | `make test-crypto` | passes |
| C20 | The evidence log hashes and proofs follow RFC 6962 | `tests/crypto/test_merkle_rfc6962.py::test_reference_roots`; `tests/crypto/test_merkle_rfc6962.py::test_proofs_verify_for_random_sizes` | `make test-crypto` | passes |

### Directory and uploads

| Id | Claim | Test | Command | Status |
|---|---|---|---|---|
| C21 | The server refuses an object built on an older directory | `tests/security/test_negative_claims.py::test_older_directory_rejected_by_server`; `tests/detect/test_qg_r003.py::test_stale_epoch_share_requires_fresh_session` | `make test-security`, `make test-detect` | passes |
| C22 | The client refuses a directory older than the highest it has seen | `tests/security/test_negative_claims.py::test_older_directory_rejected_by_client` | `make test-security` | passes |
| C23 | A manifest naming a recipient that policy does not allow is refused | `tests/security/test_negative_claims.py::test_manifest_naming_unauthorized_recipient_rejected` | `make test-security` | passes |

### Enrolment, sessions and the gateway

| Id | Claim | Test | Command | Status |
|---|---|---|---|---|
| C24 | Enrolment without proof of the signing key, or without proof of the KEM key, is refused and publishes nothing | `tests/api/test_auth.py::test_enrol_requires_both_proofs`; `tests/security/test_negative_claims.py::test_enrollment_without_key_possession_proof_rejected` | `make test-api`, `make test-security` | passes |
| C25 | An invite is single use and expires after 15 minutes | `tests/api/test_auth.py::test_invite_single_use_and_expiry`; `tests/security/test_negative_claims.py::test_expired_invite_rejected`; `tests/security/test_negative_claims.py::test_invite_reused_rejected` | `make test-api`, `make test-security` | passes |
| C26 | A replayed sequence number is refused, ends the session and raises QG-R002; a gap is accepted; a bad MAC is refused without advancing the sequence | `tests/api/test_auth.py::test_replay_gap_and_bad_mac`; `tests/security/test_negative_claims.py::test_replayed_request_rejected_and_session_ended`; `tests/security/test_negative_claims.py::test_sequence_gap_tolerated_but_regression_rejected`; `tests/detect/test_qg_r002.py::test_replay_ends_the_session` | `make test-api`, `make test-security`, `make test-detect` | passes |
| C27 | The request MAC covers the query string and the body | `tests/api/test_auth.py::test_mac_covers_query_and_body` | `make test-api` | passes |
| C28 | Sessions end after 600 s idle and after 3,600 s in total | `tests/api/test_auth.py::test_session_idle_expiry`; `tests/api/test_auth.py::test_session_hard_cap` | `make test-api` | passes |
| C29 | Every non-public contract route answers 401 without a session | `tests/security/test_route_inventory.py::test_every_non_public_contract_route_without_session_returns_401`; `tests/api/test_auth.py::test_private_routes_need_session` | `make test-security`, `make test-api` | passes |
| C30 | Every non-public route in the application carries the gateway dependency | `tests/security/test_route_inventory.py::test_every_non_public_route_has_gateway_dependency` | `make test-security` | passes |
| C31 | A suite other than `QG-1` is refused with `QG_BAD_SUITE` and raises QG-R014 | `tests/security/test_negative_claims.py::test_unknown_suite_rejected`; `tests/detect/test_qg_r014.py::test_unknown_suite_is_refused_and_alerted` | `make test-security`, `make test-detect` | passes |
| C32 | Unknown fields and floating-point numbers in a request are refused | `tests/api/test_auth.py::test_unknown_fields_rejected` | `make test-api` | passes |
| C33 | Oversized and deeply nested bodies are refused | `tests/api/test_auth.py::test_body_limits` | `make test-api` | passes |
| C34 | An unknown device and a known one get the same response shape from session start | `tests/api/test_auth.py::test_unknown_device_session_start_same_shape` | `make test-api` | passes |
| C35 | When the policy engine is unavailable, requests are refused with `QG_UNAVAILABLE_FAIL_CLOSED` and no key is released | `tests/api/test_auth.py::test_policy_down_fails_closed`; `tests/security/test_negative_claims.py::test_policy_engine_down_means_deny_without_key_release`; `cli/qg/scenarios/interrupt.py::run` | `make test-api`, `make test-security`, `make scenario-interrupt` | passes |

### Insiders and server data

| Id | Claim | Test | Command | Status |
|---|---|---|---|---|
| C36 | Another person's object ids answer `QG_NOT_FOUND` on every file route | `tests/security/test_negative_claims.py::test_other_users_object_ids_return_not_found_without_existence_leak` | `make test-security` | passes |
| C37 | Approving your own sensitive change, or one that targets you, is refused | `tests/security/test_negative_claims.py::test_self_approval_of_sensitive_change_rejected`; `cli/qg/scenarios/privilege.py::run` | `make test-security`, `make scenario-privilege` | passes |
| C38 | A recovery slot cannot be used without two independent approvals | `tests/security/test_negative_claims.py::test_recovery_slot_unusable_without_two_independent_approvals` | `make test-security` | passes |
| C39 | A copy of the server database, without the `keys/` volume, cannot decrypt a file | `tests/security/test_negative_claims.py::test_server_database_copy_alone_cannot_decrypt_file` | `make test-security` | passes |
| C40 | A role that appears with no signed change raises QG-R005 and quarantines that person for sensitive files only; QG-R007 reports the new path | `tests/security/test_negative_claims.py::test_privilege_without_signed_record_raises_qg_r005`; `tests/detect/test_qg_r005.py::test_unsigned_privilege_quarantines_the_identity`; `tests/detect/test_qg_r007.py::test_new_path_alert_has_the_path_and_no_response`; `cli/qg/scenarios/privilege.py::run` | `make test-security`, `make test-detect`, `make scenario-privilege` | passes |
| C41 | Touching a decoy file or decoy service key raises QG-R004 and quarantines the device | `tests/security/test_negative_claims.py::test_decoy_touch_raises_qg_r004_and_quarantines_device`; `tests/detect/test_qg_r004.py::test_decoy_file_quarantines_the_device`; `tests/detect/test_qg_r004.py::test_decoy_service_key_quarantines_the_device` | `make test-security`, `make test-detect` | passes |
| C42 | No generated secret appears in any server log line, and the server never prints an enrolment code | `tests/security/test_negative_claims.py::test_no_generated_secret_appears_in_any_log_line`; `tests/api/test_auth.py::test_server_never_prints_codes` | `make test-security`, `make test-api` | passes |
| C43 | The browser client refuses a server that presents keys other than those pinned at enrolment | `web/src/client/real/client.test.ts::refuses a server that swaps its keys, and locks on QG_NO_SESSION` | `make test-unit` | passes |

### Evidence

| Id | Claim | Test | Command | Status |
|---|---|---|---|---|
| C44 | One decision's receipt verifies offline against a dual-signed checkpoint; an incident proof bundle verifies with pinned keys; after one byte of a stored receipt is changed, the verifier names the first bad leaf index | `cli/qg/scenarios/verify.py::run` | `make scenario-verify` | passes |
| C45 | A byte changed in the log is detected by the offline verifier | `tests/security/test_negative_claims.py::test_log_byte_flip_detected_by_offline_verifier` | `make test-security` | passes |
| C46 | `qg verify` warns when keys are not pinned and reports a tampered receipt with its leaf index | `tests/unit/test_cli.py::test_report_lost_bundle_verify_selftest` | `make test-unit` | passes |
| C47 | The browser verifier names the index of a tampered receipt and refuses foreign server keys | `web/src/crypto/merkle.test.ts::a tampered receipt reports its leaf index (report re-signed so only the leaf is wrong)`; `web/src/crypto/merkle.test.ts::foreign server keys are refused when keys are pinned` | `make test-crypto` | passes |
| C48 | Receipts are covered by a signed checkpoint | `tests/api/test_auth.py::test_receipts_chain_into_checkpoint` | `make test-api` | passes |
| C49 | A stored receipt changed on the server raises QG-R013 and freezes key release until acknowledged | `tests/detect/test_qg_r013.py::test_tampered_receipt_freezes_key_release` | `make test-detect` | passes |
| C50 | One alert reaches the API, the server log and `SECURITY_EVENTS.jsonl` with the same id | `tests/detect/test_alert_channels.py::test_alert_appears_on_every_channel` | `make test-detect` | passes |

### Reliability and supporting workflows

| Id | Claim | Test | Command | Status |
|---|---|---|---|---|
| C51 | A server killed in the middle of a re-key restarts and finishes it; duplicate revokes return one incident; malformed input is refused; the revoked device receives no key release after the revocation | `cli/qg/scenarios/interrupt.py::run` | `make scenario-interrupt` | passes |
| C52 | A rotated service key keeps working until retired; a retired key is refused and raises QG-R010; the signed key set verifies at every epoch | `cli/qg/scenarios/rotate.py::run`; `tests/detect/test_qg_r010.py::test_retired_key_is_denied_and_alerted` | `make scenario-rotate`, `make test-detect` | passes |
| C53 | After one of a person's devices is revoked, messages reach only the remaining device and the revoked one cannot be addressed | `cli/qg/scenarios/messaging.py::run` | `make scenario-messaging` | passes |

## 6. Detection coverage

Each rule is one file in `backend/qg/detect/rules/`. An alert names its rule, the condition in words
and the receipts that matched (QG-R013 names the failing leaf index instead). Alerts are available at
`GET /api/v1/alerts`, as JSON lines with `"event":"alert"` on the server's standard output, and in
`SECURITY_EVENTS.jsonl` in the data directory (C50). Every response except QG-R013's is scoped to one
session, device, identity or credential, and an operator can lift it. All fourteen rules are
implemented; each test below runs with `make test-detect`.

| Attack | Rule | Severity | Automatic response | Test |
|---|---|---|---|---|
| A revoked device sends a request or starts a session | QG-R001 | Critical | Deny the device; attach the alert to the incident | `tests/detect/test_qg_r001.py::test_revoked_device_attempt_denied_and_alerted` |
| A captured request is replayed (sequence number not increasing) | QG-R002 | High | End that session | `tests/detect/test_qg_r002.py::test_replay_ends_the_session` |
| An object is built on a directory epoch past the 60 s grace or from before a revocation | QG-R003 | High | Deny with `QG_STALE_EPOCH`; require a fresh session proof (10 minutes) | `tests/detect/test_qg_r003.py::test_stale_epoch_share_requires_fresh_session` |
| A decoy file or decoy service key is touched | QG-R004 | Critical | Quarantine the device and end its sessions until an operator lifts it; for a decoy key with no device, deny the key | `tests/detect/test_qg_r004.py::test_decoy_file_quarantines_the_device`; `tests/detect/test_qg_r004.py::test_decoy_service_key_quarantines_the_device` |
| A role appears in the identity source with no signed change | QG-R005 | Critical | Quarantine the person for confidential and restricted files; cancel their leases | `tests/detect/test_qg_r005.py::test_unsigned_privilege_quarantines_the_identity` |
| A self-granted role is followed within 10 minutes by access to a sensitive file | QG-R006 | High | Quarantine the person for confidential and restricted files | `tests/detect/test_qg_r006.py::test_self_granted_role_then_sensitive_access` |
| An unapproved role opens a path to the recovery key and restricted files | QG-R007 | High | Alert with the path drawn; no automatic response | `tests/detect/test_qg_r007.py::test_new_path_alert_has_the_path_and_no_response` |
| Key releases per minute exceed the person's own EWMA mean plus three standard deviations | QG-R008 | Medium | Require a fresh session proof (10 minutes) | `tests/detect/test_qg_r008.py::test_burst_above_baseline_requires_a_fresh_session` |
| 20 or more not-found or policy-denied answers in 60 s on one session | QG-R009 | Medium | Throttle that session for 5 minutes | `tests/detect/test_qg_r009.py::test_enumeration_throttles_the_session` |
| A retired service key is presented | QG-R010 | High | Deny that key | `tests/detect/test_qg_r010.py::test_retired_key_is_denied_and_alerted` |
| A new device is enrolled while a loss report is open for the same person | QG-R011 | High | Hold enrolment for that person until an operator lifts it | `tests/detect/test_qg_r011.py::test_enrolment_held_during_open_loss_report` |
| 5 or more MAC or signature failures in 60 s | QG-R012 | Medium | Throttle the session or device for 5 minutes | `tests/detect/test_qg_r012.py::test_bad_mac_burst_throttles_the_session` |
| A stored receipt, leaf hash or checkpoint no longer matches the log (self-audit every 15 s and before every bundle export) | QG-R013 | Critical | Freeze all key release until an operator acknowledges the alert (not scoped; see limit 14) | `tests/detect/test_qg_r013.py::test_tampered_receipt_freezes_key_release` |
| A suite other than `QG-1` is requested | QG-R014 | Medium | The request is refused with `QG_BAD_SUITE`; no further response | `tests/detect/test_qg_r014.py::test_unknown_suite_is_refused_and_alerted` |

Specified, not yet implemented: none.

## 7. Server roles in a decision

The gateway checks, in order: the session exists, the request MAC, the sequence number, the device is
still active, any active automatic response, the rate limit, and that the policy engine is available.
The route then asks the policy engine for a decision, which allows only when an allow rule matches and
no deny rule matches. Detection runs on events after enforcement; if detection fails, nothing is
granted.

## 8. Library provenance

Our code composes primitives from the libraries below and implements none of them. The X-Wing
combiner (`SHA3-256(ss_M || ss_X || ct_X || pk_X || label)`) and the key expansion with SHAKE-256 are
protocol code written from draft-connolly-cfrg-xwing-kem-11 and checked against its three Appendix C
test vectors. Versions are from `backend/uv.lock` and `web/pnpm-lock.yaml`.

| Primitive | Server and `qg` client (Python 3.12) | Browser console |
|---|---|---|
| ML-KEM-768 (inside X-Wing) | `cryptography` 50.0.2 (bundles OpenSSL 4.0.3) | `@noble/post-quantum` 0.7.1 (`ml_kem768_x25519`) |
| X25519 (inside X-Wing) | `cryptography` 50.0.2 | `@noble/post-quantum` 0.7.1 |
| SHA3-256 and SHAKE-256 (X-Wing combiner and key expansion) | Python standard library `hashlib` | `@noble/post-quantum` 0.7.1 |
| ML-DSA-65 | `cryptography` 50.0.2 | `@noble/post-quantum` 0.7.1 |
| Ed25519 | `cryptography` 50.0.2 | `@noble/curves` 2.4.0 |
| AES-256-GCM | `cryptography` 50.0.2 | Web Crypto in a secure context, otherwise `@noble/ciphers` 2.4.0 |
| HKDF-SHA-384 | `cryptography` 50.0.2 | Web Crypto in a secure context, otherwise `@noble/hashes` 2.4.0 |
| HMAC-SHA-384 | Python standard library `hmac` | Web Crypto in a secure context, otherwise `@noble/hashes` 2.4.0 |
| SHA-256 (data hashes, Merkle tree) | Python standard library `hashlib` | Web Crypto in a secure context, otherwise `@noble/hashes` 2.4.0 |
| Argon2id | `argon2-cffi` 25.1.0 (`argon2-cffi-bindings` 26.1.0) | `@noble/hashes` 2.4.0 |

X-Wing reference: draft-connolly-cfrg-xwing-kem-11, as recorded in `spec/SUITE.md`. Every other
algorithm is used as specified in `spec/SUITE.md`, with no negotiation: every signed or stored object
carries `"suite": "QG-1"`.
