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
| Recovery kit (an X-Wing private key) | Issued once by `python -m qg.admin recovery-kit init` to whoever operates the server, kept offline. The server stores only the public half | It opens the recovery wrap of every file committed after the kit was issued |
| Device directory | Dual-signed object with an epoch that only increases | Decides which devices and public keys are current |
| Policy bundle | `backend/qg/policy/rules.yaml`, dual-signed by the server | Decides every allow or deny |
| Evidence log | SHA-256 Merkle tree of receipts with dual-signed checkpoints | The record an operator, auditor or reviewer checks afterwards |

## 2. Attackers

| Attacker | Capability | What stops them | Claims |
|---|---|---|---|
| Someone who finds or steals an enrolled device | Holds the device, its keystore and anything it saved; may have an unlocked session | Report lost (from another device) or operator revoke runs one transaction: device revoked, its key slots deleted, its sessions ended, its leases cancelled, pending enrolment codes for the person and codes created by the person or the device cancelled, a new signed directory published, a checkpoint forced. Later requests are refused with `QG_DENY_REVOKED`, recorded, and raise QG-R001. New enrolments for the person are held (QG-R011). The keystore needs the passphrase (Argon2id) | C1 to C10 |
| A network attacker, including one who records traffic now for a future quantum computer | Reads, records, replays and alters traffic | File contents are encrypted on the device. File keys are wrapped with X-Wing, so both X25519 and ML-KEM-768 must be broken. Sessions start with proof of both device keys; each request carries an HMAC-SHA-384 code over method, path, sequence number and body hash; a sequence number that does not increase ends the session (QG-R002) | C11 to C22, C26 to C31 |
| Someone who copies the server's data and keys volumes | Reads every row, every ciphertext and the server keys | Each file key is wrapped for a device's X-Wing public key inside the server's seal; the recovery wrap is wrapped for the recovery kit, whose private half is in neither volume. A database copy alone cannot even remove the outer seal | C42, C43 |
| A curious or malicious insider with an ordinary or administrative account | Signs in normally and calls any route | Default-deny policy on every route; files are visible only to their owner and to devices holding a slot; other people's objects answer `QG_NOT_FOUND`; only the owner's devices make a new version of a file; granting `admin` or `operator` needs approval from a different admin; recovery release needs two approvals from other admins or operators; nobody lifts an automatic response that contains them; a privilege that appears with no signed change raises QG-R005 and QG-R007; decoy objects raise QG-R004 | C38 to C47 |
| An untrusted edge or content delivery network between the person and the backend | Sees and can alter every request and response | Contents and file keys cross only as ciphertext and wrapped keys; requests carry a per-session MAC; directories, checkpoints and certificates are dual-signed and checked against server keys pinned at enrolment; an older directory is refused. The edge serves the web application itself, which is a limit (section 4, item 15) | C19, C24, C48 |
| Anyone who can reach the public endpoints, with no key | Sends handshakes, forged MACs and malformed input, and can name any device id from the public directory | Failures that prove no key are counted per source address and claimed device; the response (QG-R012) refuses only further failed proofs from that address for that claim, for 5 minutes, and a correct proof is always accepted. A session id without a valid MAC writes no evidence. Inputs are bounded and schema-checked | C32 to C37 |

## 3. Assumptions

1. The standardised algorithms and the libraries that implement them (section 9) are sound.
2. The backend process is not taken over while the server runs. A copy of the data and keys volumes is
   covered as stated in section 2; an attacker who runs code inside the live backend is not.
3. The operating system and browser on an honest device are not already compromised.
4. The server public keys a device receives at enrolment are the real ones. They are pinned then and
   a different key later is refused; the first contact itself is trusted.
5. The web application the browser loads is the code in this repository, served unmodified.
6. Server time is the only time used for decisions; a client clock is never trusted.
7. Security signals (`POST /api/v1/signals`) come from an operator or a service identity with a valid
   session; their content is believed.
8. Behind a reverse proxy, `QG_TRUSTED_PROXIES` names that proxy, so the client address the server
   uses for rate limits and source-scoped responses is the real one.

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
13. Only the owner's devices give a file a new key, because the server cannot check that re-encrypted
    contents are unchanged and a recipient could otherwise replace them. After a revocation, a file
    whose owner has no unlocked device stays "new key pending" until the owner unlocks one. Until then
    the lost device still cannot obtain the key: its slots are gone and its requests are refused.
14. Devices that were enrolled with a code a thief used before the loss was reported are separate
    devices and are not revoked by the report. Revocation cancels codes that are still pending, but an
    operator must review the person's recent enrolments.
15. The browser runs whatever code the origin serves. A malicious server or edge that changes the web
    application can read passphrases and keys in the browser. The command-line client does not have
    this exposure.
16. A thief holding one of a person's devices can report that person's other devices lost, because
    any device of the owner may report another. An operator must notice and correct it; revocation
    is never undone.
17. Until a recovery kit is issued, files carry no recovery slot, and a file whose owner and
    recipients have lost every device cannot be recovered. Files committed before the kit was issued
    stay without one. The two-approval rule for a recovery release is enforced by the server's
    policy: whoever holds the kit and a copy of both volumes can open recovery slots without approvals.
18. QG-R013 (the log fails its own consistency check) freezes every key release until an operator
    acknowledges the alert. It is the one deliberately global response: every other response is
    scoped to a session, device, identity, credential or source.
19. The server takes the client address from `X-Forwarded-For` only from the addresses in
    `QG_TRUSTED_PROXIES` (default `127.0.0.1`). Behind a proxy that is not listed, every client shares
    the proxy's address for rate limits and source-scoped responses. A server run directly on loopback
    trusts that header from every local client. The Compose file does not set this variable for the
    TLS profile.
20. Sessions are kept in server memory. A server restart ends every session, and devices sign in
    again.
21. The local Docker stack serves plain HTTP on `127.0.0.1:8080`. Transport encryption is not part of
    any claim; the optional TLS profile is for local testing only.
22. QG-R008 compares a person's key releases per minute with their own EWMA baseline, so a person who
    rarely opens files and then opens a folder of ten or more within a minute is asked to prove their
    session again (the only false alerts measured in section 7).
23. QuantumGuard runs as one API node with one SQLite database. A revocation is committed with
    `synchronous=FULL` before the report returns, and `make scenario-interrupt` shows it still holds
    after the server is killed and restarted; running several API nodes is not supported or claimed.
24. The prototype is unaudited apart from the internal review in section 6, was built in a short
    time, and is meant for synthetic data only.

## 5. Claims and tests

The status column is the result of running each command on the host on 26 November 2026 on `main`
at commit `3ca93c5`. The `make test-*` and `make dev-scenario-*` targets need `uv` (and `pnpm` for the
`web/` tests) after `make setup`; `make scenario-<name>` runs the same scenario inside the running
container. `make test` runs every Python suite and six scenarios inside a Docker test image, with the
security suite in strict mode, where a skipped test counts as a failure. `tests/security` and
`tests/attacks` hold 172 tests; `make test-security` writes `claims.json` with the outcome of every
test id in `tests/security`. Most claims in `tests/security/test_negative_claims.py` are also asserted
a second time through a separate test harness in `tests/security/test_negative_claims_adapter.py`.

### Revocation and lost devices

| Id | Claim | Test | Command | Status |
|---|---|---|---|---|
| C1 | A revoked device cannot start a session | `tests/security/test_negative_claims.py::test_revoked_device_cannot_start_session`; `tests/api/test_incidents.py::test_denied_session_attempts_counted_and_one_alert` | `make test-security`, `make test-api` | passes |
| C2 | A request from a revoked device on any route is refused with `QG_DENY_REVOKED`, gets a receipt, appears on the incident timeline and raises one QG-R001 alert | `tests/api/test_incidents.py::test_denied_attempt_recorded_on_any_route`; `tests/detect/test_qg_r001.py::test_revoked_device_attempt_denied_and_alerted` | `make test-api`, `make test-detect` | passes |
| C3 | A revoked device's existing session dies in the same transaction that deletes its key slots; repeating the revoke returns the same incident; a corrected compromise time re-scopes it | `tests/security/test_negative_claims.py::test_revoked_devices_existing_session_dies_in_same_transaction`; `tests/api/test_incidents.py::test_revoke_result_and_idempotence` | `make test-security`, `make test-api` | passes |
| C4 | No key material reaches a device after its revocation while slot requests race the revoke (1,000 requests in the reliability test) | `tests/reliability/test_revocation_race.py::test_revoke_races_1000_slot_requests`; `tests/security/test_revocation_race.py::test_revoked_device_gets_no_slot_under_concurrent_release` | `make test-reliability`, `make test-security` | passes |
| C5 | After a loss report, files are classified as exposed, held or never released against the loss time, re-keyed exposed first, and stay readable by the remaining devices | `cli/qg/scenarios/revoke.py::run` | `make scenario-revoke` | passes |
| C6 | An incident cannot be closed while files still wait for new keys | `tests/api/test_incidents.py::test_close_requires_rekey` | `make test-api` | passes |
| C7 | Enrolment for a person is held (QG-R011) while their loss report is open, and after a held attempt until an operator lifts the response | `tests/api/test_incidents.py::test_enrolment_held_while_loss_open`; `tests/detect/test_qg_r011.py::test_enrolment_held_during_open_loss_report` | `make test-api`, `make test-detect` | passes |
| C8 | Revocation cancels pending enrolment codes for the person and codes the lost device created, including codes for other people | `tests/attacks/test_revocation_leftovers.py::test_revocation_cancels_codes_minted_by_the_lost_device`; `tests/attacks/test_r2_revocation_invites.py::test_revocation_cancels_codes_the_lost_device_minted_for_other_people` | `make test-security` | passes |
| C9 | A revoked session id presented without a valid MAC writes no receipt and no denied attempt | `tests/attacks/test_revocation_leftovers.py::test_revoked_session_id_without_mac_does_not_write_evidence` | `make test-security` | passes |
| C10 | An expired lease stops a download in the middle of a file; a lease works only for the session that received it | `tests/security/test_negative_claims.py::test_expired_lease_stops_download_mid_file`; `tests/attacks/test_spec_deviations.py::test_lease_is_bound_to_the_session_that_opened_the_slot`; `tests/security/test_review_probes.py::test_lease_misuse_refused` | `make test-security` | passes |

### Cryptography and binding

| Id | Claim | Test | Command | Status |
|---|---|---|---|---|
| C11 | X-Wing matches the three Appendix C vectors of draft-connolly-cfrg-xwing-kem-11 (Python and browser) | `tests/crypto/test_official_kats.py::test_xwing_draft11`; `web/src/crypto/primitives.test.ts::draft-11 Appendix C vector` | `make test-crypto` | passes |
| C12 | ML-KEM-768 matches NIST ACVP key generation and C2SP Wycheproof decapsulation vectors | `tests/crypto/test_official_kats.py::test_mlkem768_keygen`; `tests/crypto/test_official_kats.py::test_mlkem768_decaps_wycheproof` | `make test-crypto` | passes |
| C13 | ML-DSA-65 matches NIST ACVP key generation and signature verification with context vectors | `tests/crypto/test_official_kats.py::test_mldsa65_keygen`; `tests/crypto/test_official_kats.py::test_mldsa65_sigver_with_context` | `make test-crypto` | passes |
| C14 | A single bit flip anywhere in a protected file fails decryption | `tests/crypto/test_properties.py::test_any_single_bit_flip_fails`; `tests/security/test_negative_claims.py::test_ciphertext_bit_flip_fails`; `web/src/crypto/envelope.test.ts::a single bit flip anywhere fails` | `make test-crypto`, `make test-security` | passes |
| C15 | Reordered or truncated chunks and a wrong AAD fail; a chunk from another file fails | `tests/crypto/test_properties.py::test_reorder_truncate_and_wrong_aad_fail`; `tests/crypto/test_properties.py::test_chunk_from_other_file_with_same_key_fails`; `tests/security/test_negative_claims.py::test_chunk_reordered_or_truncated_fails`; `tests/security/test_negative_claims.py::test_wrong_aad_fails` | `make test-crypto`, `make test-security` | passes |
| C16 | A chunk nonce never repeats within a file version | `tests/crypto/test_properties.py::test_nonce_never_repeats_within_file` | `make test-crypto` | passes |
| C17 | An inner wrap opens only for its device, file, version and directory epoch; a key slot moved to another file or another device fails | `tests/crypto/test_properties.py::test_wrap_bound_to_device_file_version_epoch`; `tests/security/test_negative_claims.py::test_slot_moved_to_another_context_fails`; `web/src/crypto/envelope.test.ts::a wrap bound to another file, version, device or epoch fails; wrong device key fails` | `make test-crypto`, `make test-security` | passes |
| C18 | An outer seal opens only for its slot | `tests/crypto/test_properties.py::test_seal_bound_to_slot` | `make test-crypto` | passes |
| C19 | A checkpoint is accepted only when both the Ed25519 and the ML-DSA-65 signature verify under the right keys and purpose | `tests/crypto/test_qg_vectors.py::test_checkpoint_vectors`; `tests/security/test_negative_claims.py::test_checkpoint_with_one_bad_signature_rejected`; `web/src/crypto/merkle.test.ts::checkpoint verifies under the dual-signature rule` | `make test-crypto`, `make test-security` | passes |
| C20 | The Python and browser clients produce the same bytes for canonical JSON, request MACs, transcripts, file envelopes and keystores | `tests/crypto/test_qg_vectors.py` (all tests); the vector tests in `web/src/crypto/` | `make test-crypto` | passes |
| C21 | A keystore opened with a wrong passphrase or a modified header fails | `tests/crypto/test_qg_vectors.py::test_keystore_must_fail` | `make test-crypto` | passes |
| C22 | The evidence log hashes and proofs follow RFC 6962 | `tests/crypto/test_merkle_rfc6962.py::test_reference_roots`; `tests/crypto/test_merkle_rfc6962.py::test_proofs_verify_for_random_sizes` | `make test-crypto` | passes |

### Directory and uploads

| Id | Claim | Test | Command | Status |
|---|---|---|---|---|
| C23 | The server refuses an object built on an older directory | `tests/security/test_negative_claims.py::test_older_directory_rejected_by_server`; `tests/detect/test_qg_r003.py::test_stale_epoch_share_requires_fresh_session` | `make test-security`, `make test-detect` | passes |
| C24 | The client refuses a directory older than the highest it has seen | `tests/security/test_negative_claims.py::test_older_directory_rejected_by_client` | `make test-security` | passes |
| C25 | A manifest naming a recipient that policy does not allow is refused | `tests/security/test_negative_claims.py::test_manifest_naming_unauthorized_recipient_rejected` | `make test-security` | passes |

### Enrolment, sessions and the gateway

| Id | Claim | Test | Command | Status |
|---|---|---|---|---|
| C26 | Enrolment without proof of the signing key, or without proof of the KEM key, is refused and publishes nothing | `tests/api/test_auth.py::test_enrol_requires_both_proofs`; `tests/security/test_negative_claims.py::test_enrollment_without_key_possession_proof_rejected` | `make test-api`, `make test-security` | passes |
| C27 | An invite is single use and expires after 15 minutes | `tests/api/test_auth.py::test_invite_single_use_and_expiry`; `tests/security/test_negative_claims.py::test_expired_invite_rejected`; `tests/security/test_negative_claims.py::test_invite_reused_rejected` | `make test-api`, `make test-security` | passes |
| C28 | A replayed sequence number is refused, ends the session and raises QG-R002; a gap is accepted; a bad MAC is refused without advancing the sequence | `tests/api/test_auth.py::test_replay_gap_and_bad_mac`; `tests/security/test_negative_claims.py::test_replayed_request_rejected_and_session_ended`; `tests/security/test_negative_claims.py::test_sequence_gap_tolerated_but_regression_rejected`; `tests/detect/test_qg_r002.py::test_replay_ends_the_session` | `make test-api`, `make test-security`, `make test-detect` | passes |
| C29 | The request MAC binds method, path, query, sequence, body and session | `tests/api/test_auth.py::test_mac_covers_query_and_body`; `tests/security/test_review_probes.py::test_request_mac_binds_every_part` | `make test-api`, `make test-security` | passes |
| C30 | Sessions end after 600 s idle and after 3,600 s in total; a session start is single use | `tests/api/test_auth.py::test_session_idle_expiry`; `tests/api/test_auth.py::test_session_hard_cap`; `tests/security/test_review_probes.py::test_session_start_is_single_use_and_expires` | `make test-api`, `make test-security` | passes |
| C31 | Every non-public route answers 401 without a session and carries the gateway dependency | `tests/security/test_route_inventory.py::test_every_non_public_contract_route_without_session_returns_401`; `tests/security/test_route_inventory.py::test_every_non_public_route_has_gateway_dependency` | `make test-security` | passes |
| C32 | A suite other than `QG-1`, at any depth of a request body, is refused with `QG_BAD_SUITE` and raises QG-R014 | `tests/security/test_negative_claims.py::test_unknown_suite_rejected`; `tests/attacks/test_spec_deviations.py::test_nested_object_with_other_suite_is_bad_suite_and_alerted`; `tests/detect/test_qg_r014.py::test_unknown_suite_is_refused_and_alerted` | `make test-security`, `make test-detect` | passes |
| C33 | Malformed, oversized, deeply nested, floating-point, duplicate-key and out-of-range input is refused as input, not as a server error | `tests/security/test_review_probes.py::test_malformed_input_refused`; `tests/attacks/test_spec_deviations.py::test_huge_path_integer_is_refused_as_input_not_server_error`; `tests/api/test_auth.py::test_body_limits` | `make test-security`, `make test-api` | passes |
| C34 | Failed key proofs never throttle the device they name and never stop another person signing in; a correct proof is always accepted | `tests/attacks/test_detection_responses.py::test_unauthenticated_failures_cannot_throttle_another_persons_device`; `tests/attacks/test_r2_source_block.py::test_keyless_failures_do_not_stop_another_person_signing_in`; `tests/detect/test_qg_r012.py::test_handshake_proof_failures_never_throttle_the_claimed_device` | `make test-security`, `make test-detect` | passes |
| C35 | Forged MACs on a known session id do not write alerts without bound | `tests/attacks/test_r2_source_block.py::test_forged_macs_on_a_known_session_id_do_not_write_unbounded_alerts` | `make test-security` | passes |
| C36 | When the policy engine is unavailable, or blob storage fails, requests are refused and no key is released | `tests/security/test_negative_claims.py::test_policy_engine_down_means_deny_without_key_release`; `tests/security/test_review_probes.py::test_storage_failure_fails_closed`; `cli/qg/scenarios/interrupt.py::run` | `make test-security`, `make scenario-interrupt` | passes |
| C37 | A retired service key is refused on any route and raises QG-R010 | `tests/attacks/test_spec_deviations.py::test_retired_service_key_is_refused_on_any_route`; `tests/detect/test_qg_r010.py::test_retired_key_is_denied_and_alerted` | `make test-security`, `make test-detect` | passes |

### Insiders, recovery and server data

| Id | Claim | Test | Command | Status |
|---|---|---|---|---|
| C38 | Another person's objects answer the same as objects that do not exist | `tests/security/test_negative_claims.py::test_other_users_object_ids_return_not_found_without_existence_leak`; `tests/security/test_review_probes.py::test_other_peoples_objects_are_indistinguishable_from_absent` | `make test-security` | passes |
| C39 | Only the owner's devices make a new version of a file: a recipient cannot re-key the owner out, change the recipient set, or replace the contents | `tests/attacks/test_rekey_authorization.py::test_recipient_cannot_rekey_owner_out_of_file`; `tests/attacks/test_rekey_authorization.py::test_pending_rekey_must_keep_the_remaining_recipients`; `tests/attacks/test_r2_rekey_content.py::test_holder_rekey_cannot_replace_content_after_owner_unshare`; `tests/attacks/test_r2_rekey_content.py::test_holder_can_not_self_queue_a_rekey_and_replace_content`; `tests/attacks/test_r2_rekey_content.py::test_holder_rekey_cannot_add_back_the_unshared_person` | `make test-security` | passes |
| C40 | Approving your own sensitive change, or one that targets you, is refused | `tests/security/test_negative_claims.py::test_self_approval_of_sensitive_change_rejected`; `tests/security/test_review_probes.py::test_approval_roles_and_duplicates`; `cli/qg/scenarios/privilege.py::run` | `make test-security`, `make scenario-privilege` | passes |
| C41 | A recovery slot cannot be used without two approvals from two other people; the kit holder then opens the file | `tests/security/test_negative_claims.py::test_recovery_slot_unusable_without_two_independent_approvals`; `tests/api/test_recovery.py::test_recover_requires_two_approvals_then_opens`; `tests/unit/test_cli.py::test_recover_with_kit_after_two_approvals` | `make test-security`, `make test-api`, `make test-unit` | passes |
| C42 | The data and keys volumes together cannot open a recovery slot; the kit's private half is never written to them | `tests/api/test_recovery.py::test_data_and_keys_volumes_together_cannot_open_a_recovery_slot`; `tests/attacks/test_recovery_kit_on_server.py::test_server_volumes_alone_cannot_open_a_recovery_slot`; `tests/api/test_recovery.py::test_server_without_kit_then_admin_issues_it` | `make test-api`, `make test-security` | passes |
| C43 | A copy of the server database, without the `keys/` volume, cannot decrypt a file | `tests/security/test_negative_claims.py::test_server_database_copy_alone_cannot_decrypt_file` | `make test-security` | passes |
| C44 | Nobody lifts an automatic response that contains them | `tests/attacks/test_detection_responses.py::test_operator_cannot_lift_a_response_that_contains_themselves`; `tests/security/test_review_probes.py::test_lift_requires_operator` | `make test-security` | passes |
| C45 | A role that appears with no signed change raises QG-R005 and quarantines that person for sensitive files only; QG-R007 reports the new path | `tests/security/test_negative_claims.py::test_privilege_without_signed_record_raises_qg_r005`; `tests/detect/test_qg_r005.py::test_unsigned_privilege_quarantines_the_identity`; `tests/detect/test_qg_r007.py::test_new_path_alert_has_the_path_and_no_response`; `cli/qg/scenarios/privilege.py::run` | `make test-security`, `make test-detect`, `make scenario-privilege` | passes |
| C46 | Touching a decoy file or decoy service key raises QG-R004 and quarantines the device | `tests/security/test_negative_claims.py::test_decoy_touch_raises_qg_r004_and_quarantines_device`; `tests/detect/test_qg_r004.py::test_decoy_file_quarantines_the_device`; `tests/detect/test_qg_r004.py::test_decoy_service_key_quarantines_the_device` | `make test-security`, `make test-detect` | passes |
| C47 | No generated secret appears in any server log line, and the server never prints an enrolment code | `tests/security/test_negative_claims.py::test_no_generated_secret_appears_in_any_log_line`; `tests/api/test_auth.py::test_server_never_prints_codes` | `make test-security`, `make test-api` | passes |
| C48 | The browser client refuses a server that presents keys other than those pinned at enrolment | `web/src/client/real/client.test.ts::refuses a server that swaps its keys, and locks on QG_NO_SESSION` | `make test-unit` | passes |

### Evidence

| Id | Claim | Test | Command | Status |
|---|---|---|---|---|
| C49 | One decision's receipt verifies offline against a dual-signed checkpoint; an incident proof bundle verifies with pinned keys; after one byte of a stored receipt is changed, the verifier names the first bad leaf index | `cli/qg/scenarios/verify.py::run` | `make scenario-verify` | passes |
| C50 | A byte changed in the log is detected by the offline verifier; a proof for the wrong index and a rollback to a smaller tree are refused | `tests/security/test_negative_claims.py::test_log_byte_flip_detected_by_offline_verifier`; `tests/security/test_review_probes.py::test_proofs_reject_wrong_index_and_rollback` | `make test-security` | passes |
| C51 | `qg verify` warns when keys are not pinned and reports a tampered receipt with its leaf index | `tests/unit/test_cli.py::test_report_lost_bundle_verify_selftest` | `make test-unit` | passes |
| C52 | The browser verifier names the index of a tampered receipt and refuses foreign server keys | `web/src/crypto/merkle.test.ts::a tampered receipt reports its leaf index (report re-signed so only the leaf is wrong)`; `web/src/crypto/merkle.test.ts::foreign server keys are refused when keys are pinned` | `make test-crypto` | passes |
| C53 | A stored receipt changed on the server raises QG-R013 and freezes key release until acknowledged | `tests/detect/test_qg_r013.py::test_tampered_receipt_freezes_key_release` | `make test-detect` | passes |
| C54 | One alert reaches the API, the server log and `SECURITY_EVENTS.jsonl` with the same id | `tests/detect/test_alert_channels.py::test_alert_appears_on_every_channel` | `make test-detect` | passes |

### Reliability and supporting workflows

| Id | Claim | Test | Command | Status |
|---|---|---|---|---|
| C55 | A server killed in the middle of a re-key restarts and finishes it; duplicate revokes return one incident; malformed input is refused; the revoked device receives no key release after the revocation | `cli/qg/scenarios/interrupt.py::run` | `make scenario-interrupt` | passes |
| C56 | A rotated service key keeps working until retired; a retired key is refused and raises QG-R010; the signed key set verifies at every epoch | `cli/qg/scenarios/rotate.py::run` | `make scenario-rotate` | passes |
| C57 | Each recipient device verifies a message's sender signature without seeing other devices' envelopes; after one of a person's devices is revoked, messages reach only the remaining device | `tests/api/test_messages.py::test_each_of_three_recipient_devices_verifies_the_signature`; `tests/api/test_messages.py::test_server_refuses_a_signature_over_other_digests`; `tests/security/test_review_probes.py::test_messages_not_addressable_to_revoked_device`; `cli/qg/scenarios/messaging.py::run` | `make test-api`, `make test-security`, `make scenario-messaging` | passes |

## 6. Review findings and fixes

Before submission an independent reviewer, who could only write tests and findings, attacked the
server in three passes. It found the twelve weaknesses below: 2 High, 7 Medium and 3 Low. They were
real defects. Each was fixed, and each has a regression test that failed before its fix and passes
now (all run with `make test-security`). Two further issues were fixed while the first pass ran: the
recovery private key was stored on the server (High; test in C42) and a lease was not bound to its
session (Low; test in C10).

| Severity | What was wrong | Fix | Test |
|---|---|---|---|
| High | A device holding a slot could re-key a file for a recipient list it chose, cutting the owner out and deleting the old content | A re-key must keep exactly the remaining recipients | `tests/attacks/test_rekey_authorization.py::test_recipient_cannot_rekey_owner_out_of_file`; `tests/attacks/test_rekey_authorization.py::test_pending_rekey_must_keep_the_remaining_recipients` |
| High | After that fix, a recipient could still commit a "re-key" with new contents, which the owner would then read | Only the owner's devices create or commit any new version of a file | `tests/attacks/test_r2_rekey_content.py::test_holder_rekey_cannot_replace_content_after_owner_unshare`; `tests/attacks/test_r2_rekey_content.py::test_holder_can_not_self_queue_a_rekey_and_replace_content` |
| Medium | Enrolment codes the lost device minted for its own person survived the revocation | Revocation cancels the person's pending codes | `tests/attacks/test_revocation_leftovers.py::test_revocation_cancels_codes_minted_by_the_lost_device` |
| Medium | A revoked session id alone, with no MAC, wrote receipts and denied attempts without limit | A denied attempt is recorded only when the MAC verifies, under the session rate limit | `tests/attacks/test_revocation_leftovers.py::test_revoked_session_id_without_mac_does_not_write_evidence` |
| Medium | Anyone could throttle any device, including the operator's, by sending failed proofs naming it | Failures that prove no key are counted against the source, not the named device | `tests/attacks/test_detection_responses.py::test_unauthenticated_failures_cannot_throttle_another_persons_device` |
| Medium | An operator could lift the automatic response that contained them | Lifting your own containment is refused; an admin may lift one that contains an operator | `tests/attacks/test_detection_responses.py::test_operator_cannot_lift_a_response_that_contains_themselves` |
| Medium | After the source fix, five keyless failures blocked every person behind the same address from signing in | The response is keyed on address and claimed device, a correct proof is always accepted, and an operator can lift it | `tests/attacks/test_r2_source_block.py::test_keyless_failures_do_not_stop_another_person_signing_in` |
| Medium | Codes a lost admin device minted for other people survived the revocation | Revocation also cancels codes the person or the lost device created for anyone | `tests/attacks/test_r2_revocation_invites.py::test_revocation_cancels_codes_the_lost_device_minted_for_other_people` |
| Medium | Forged MACs on a known session id wrote one new alert per five requests without bound | Failures pass a per-address limit first, and repeats merge into the open alert | `tests/attacks/test_r2_source_block.py::test_forged_macs_on_a_known_session_id_do_not_write_unbounded_alerts` |
| Low | A nested signed object naming another suite was refused as invalid input with no QG-R014 alert | The suite is checked at every depth of the body | `tests/attacks/test_spec_deviations.py::test_nested_object_with_other_suite_is_bad_suite_and_alerted` |
| Low | A path integer above 2^63-1 caused a server error instead of an input error | Every path integer is bounded | `tests/attacks/test_spec_deviations.py::test_huge_path_integer_is_refused_as_input_not_server_error` |
| Low | A retired or decoy service key was refused only on one route | The service key is checked by the gateway on every private route | `tests/attacks/test_spec_deviations.py::test_retired_service_key_is_refused_on_any_route` |

## 7. Detection coverage

Each rule is one file in `backend/qg/detect/rules/`; all fourteen are implemented and each has a test
that runs with `make test-detect`. Every alert names the **identity** (`identity`: person and name,
device, session; for failures before any key is proven, the source address and the claimed device or
person), the **service** it concerns (`service`: for example `key-release`, `files`, `gateway`,
`enrolment`, `evidence-log`) and the **event** that was observed (`event`: kind, time and details such
as the file id or route), together with its rule, the condition in words and the receipts that matched
(QG-R013 names the failing leaf index instead). `tests/detect/conftest.py::check_names` asserts these
fields on the alert of every rule. Alerts are available at
`GET /api/v1/alerts`, as JSON lines with `"event":"alert"` on the server's standard output, and in
`SECURITY_EVENTS.jsonl` in the data directory (C54). An operator can lift every response except
QG-R013's, which ends when an operator acknowledges the alert; nobody lifts a response that contains
them.

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
| 5 or more failed key proofs or bad MACs in 60 s from one address naming one device or person | QG-R012 | Medium | Refuse further failed proofs from that address for that claim for 5 minutes; correct proofs are accepted | `tests/detect/test_qg_r012.py::test_bad_mac_burst_blocks_only_that_source_and_claim`; `tests/detect/test_qg_r012.py::test_handshake_proof_failures_never_throttle_the_claimed_device` |
| 5 or more signature failures in 60 s on an authenticated session | QG-R012 | Medium | Throttle that session for 5 minutes | `tests/detect/test_qg_r012.py::test_signature_failures_on_a_session_throttle_that_session` |
| A stored receipt, leaf hash or checkpoint no longer matches the log (self-audit every 15 s and before every bundle export) | QG-R013 | Critical | Freeze all key release until an operator acknowledges the alert. This is the one deliberately global response: when the log cannot vouch for itself, no key leaves the server | `tests/detect/test_qg_r013.py::test_tampered_receipt_freezes_key_release` |
| A suite other than `QG-1` is requested | QG-R014 | Medium | The request is refused with `QG_BAD_SUITE`; no further response | `tests/detect/test_qg_r014.py::test_unknown_suite_is_refused_and_alerted` |

Specified, not yet implemented: none.

### Measured detection quality

`make bench-detect` (`bench/detection.py`, results in `bench/detection.json`) runs 10 rounds of a
seeded benign workload (sign-in, protect, open, open a whole folder within a minute, share, messages,
directory refresh, an approved two-person role change, runs of mistyped file ids) and injects
160 labelled attacks at random points: one per rule scenario plus three variants the rules were not
written against (replay of an older sequence number, enumeration mixing denied and not-found ids,
forged handshake proofs instead of forged MACs). Every alert is attributed to the step that created it.

| Measure | Value |
|---|---|
| Attacks detected (recall) | 160 of 160 (1.000) |
| Precision | 0.964 (6 false alerts) |
| F1 | 0.982 |
| False alerts per 1,000 benign events | 1.164 (6 over 5,156 audited benign decisions) |
| Time to alert, first malicious request to stored alert | median 16.33 ms, p95 44.09 ms, range 0.92–75.5 ms |

All 6 false alerts are QG-R008: a person who normally opens a file now and then opened a folder of
10–12 of their own files within one minute. The response is the mildest one (prove the session again);
nothing is locked or lost. The workload and attacks are our own, so these numbers show the rules work as
designed on synthetic traffic; they are not a measurement against attacks we have not imagined.

## 8. Server roles in a decision

The gateway checks, in order: the session exists, the request MAC, the sequence number, the device is
still active, any active automatic response, the rate limit, and that the policy engine is available.
The route then asks the policy engine for a decision, which allows only when an allow rule matches and
no deny rule matches. Detection runs on events after enforcement; if detection fails, nothing is
granted.

## 9. Library provenance

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
