# QuantumGuard API contract (v1)

This file is the human-readable contract. `spec/openapi.yaml` is exported from the running
application and must describe exactly what is written here; `make spec-lint` fails when the two
drift. Cryptographic encodings are defined in `spec/SUITE.md`.

## 1. Conventions

- Base path `/api/v1`. JSON bodies are UTF-8. Unknown fields are rejected (`QG_INVALID_INPUT`).
- Binary values in JSON: base64url without padding (written `b64u` below).
- Ids: a type prefix plus 22 base64url characters from 16 random bytes:
  `usr_ dev_ fil_ slt_ ses_ inv_ rcp_ inc_ alr_ rsp_ chg_ svc_ key_ msg_ sig_ enr_ lse_`.
- Times: RFC 3339 UTC with milliseconds, `2026-11-26T12:00:00.000Z`. Server time is authoritative;
  a client clock is never trusted for a decision.
- Integers only (no floats) in every signed or hashed object.
- Lists accept `?limit=` (default 50, max 200) and `?before=<id>` and return
  `{"items": [...], "next_before": "<id>" | null}`.
- Every object that is signed or stored carries `"suite": "QG-1"`.

### 1.1 Authenticated requests

Every route outside section 2 needs three headers:

| Header | Value |
|---|---|
| `QG-Session` | session id |
| `QG-Seq` | decimal integer, strictly greater than the last one the server accepted |
| `QG-MAC` | b64u HMAC-SHA-384 over method, path with query, sequence and body hash (`spec/SUITE.md`) |

Clients send one request at a time per session so sequence numbers arrive in order. Gaps are
accepted; a value that is not greater than the last accepted one is a replay.

When a request produces a receipt the response carries `QG-Receipt: rcp_...`.
Every response carries `QG-Request-Id`.

### 1.2 Errors

```json
{"error": {"code": "QG_DENY_POLICY", "message": "Short sentence safe to show.", "reason": "self_approval",
           "request_id": "...", "receipt_id": "rcp_... | null"}}
```

`reason` is a stable machine word from the tables below; it never contains internal detail.

| Code | HTTP | Meaning |
|---|---|---|
| `QG_INVALID_INPUT` | 400 | Body, parameter or header failed validation |
| `QG_BAD_SUITE` | 400 | `suite` is not `QG-1` |
| `QG_BAD_SIGNATURE` | 400 | A signature or key confirmation did not verify |
| `QG_NO_SESSION` | 401 | Missing or unknown session (also after expiry) |
| `QG_BAD_MAC` | 401 | Request MAC did not verify |
| `QG_REPLAY` | 401 | Sequence number not greater than the last accepted; the session is ended |
| `QG_DENY_REVOKED` | 403 | The device is revoked |
| `QG_DENY_POLICY` | 403 | Policy said no |
| `QG_QUARANTINED` | 403 | A scoped automatic response is active for this session, device or identity |
| `QG_STALE_EPOCH` | 409 | Object built on a directory epoch older than allowed; fetch the directory and retry |
| `QG_LEASE_EXPIRED` | 403 | Lease is missing, expired or cancelled |
| `QG_NOT_FOUND` | 404 | Unknown object, or one the caller may not see |
| `QG_CONFLICT` | 409 | State does not allow this (already committed, already approved, already revoked) |
| `QG_RATE_LIMITED` | 429 | Too many requests; `Retry-After` is set |
| `QG_UNAVAILABLE_FAIL_CLOSED` | 503 | A dependency is down; nothing was released |

### 1.3 Roles

`employee`, `admin`, `operator`, `auditor`. A person may hold several. Policy decides every route;
the lists in this file say which role is expected to be allowed, not a guarantee.

## 2. Public routes (no session)

| Route | Returns |
|---|---|
| `GET /healthz` | `{"status":"ok"}` |
| `GET /api/v1/meta` | `{suite, version, commit, demo, server_keys:{ed25519_pk, mldsa_pk, kem_pk}, recovery_pk (`null` until a recovery kit has been issued), policy_bundle_hash, limits:{chunk_bytes, max_file_bytes, max_recipients, lease_seconds, session_ttl_seconds, session_hard_cap_seconds}, features:{messaging, slhdsa}}` |
| `GET /api/v1/directory` | Current signed directory (3.1). `?epoch=n` returns that epoch or `QG_NOT_FOUND` |
| `GET /api/v1/log/checkpoint` | Latest signed checkpoint (3.6) |
| `GET /api/v1/keys` | Signed service key set (9) |
| `GET /api/v1/bench/latest` | Contents of `bench/latest.json`, or `QG_NOT_FOUND` |
| `POST /api/v1/enroll/start` | 4.1 |
| `POST /api/v1/enroll/finish` | 4.1 |
| `POST /api/v1/session/start` | 4.2 |
| `POST /api/v1/session/finish` | 4.2 |

## 3. Shared objects

### 3.1 Directory

```
{suite, epoch, prev_hash, issued_at,
 users:   [{user_id, name, roles[], status: "active"|"quarantined"|"disabled"}],
 devices: [{suite, device_id, user_id, name, kem_pk, sig_pk, created_at, expires_at, directory_epoch}],
 revoked: [{device_id, revoked_at, epoch}],
 recovery_pk,                       // null until a recovery kit has been issued
 signatures: {ed25519, mldsa}}
```

### 3.2 Device (list view, not signed)

`{device_id, user_id, user_name, name, status: "active"|"revoked"|"quarantined", created_at, last_seen_at, is_current, open_incident_id | null}`

### 3.3 File

```
{file_id, name, classification: "internal"|"confidential"|"restricted",
 size_bytes, version, chunk_count, owner: {user_id, name}, created_at, updated_at,
 recipients: [{device_id, user_id, user_name, device_name}],
 can_open, rekey: "none"|"pending"|"in_progress"}
```

File names and sizes are metadata the server can read; contents and file keys are not.

### 3.4 Receipt

`{suite, id, ts, request_hash, subject:{user_id, device_id, session_id}, action, resource, policy_bundle_hash, matched_rules[], decision: "allow"|"deny", reason_code, key_epoch, directory_epoch, leaf_index}`

`action` values: `enroll session.start session.end file.create file.commit slot.release chunk.read file.share file.unshare file.delete rekey.commit device.report_lost device.revoke device.rename invite.create change.request change.approve change.reject alert.ack response.lift service.create service.rotate signal.receive message.send recovery.release incident.close bundle.export access`. `access` is a request on a route that has no more specific action; it is what a refused request from a revoked device is recorded as on such routes.

### 3.5 Alert

```
{id, ts, rule_id, severity: "critical"|"high"|"medium", status: "open"|"acknowledged",
 subject: {user_id, device_id, session_id},   // any may be null
 summary, explanation: {condition, receipt_ids[]},
 response: {id, action: "deny"|"end_session"|"quarantine_device"|"quarantine_identity"|"throttle"|"require_fresh_session"|"hold_enrolment"|"freeze_key_release"|"none",
            scope: {kind: "session"|"device"|"identity"|"credential"|"source"|"global", id}, expires_at | null, lifted_at | null, lifted_by | null} | null,
 incident_id | null, acknowledged_by | null}
```

### 3.6 Checkpoint

`{suite, tree_size, root_hash, ts, signatures: {ed25519, mldsa}}`

## 4. Enrolment and session

### 4.1 Enrol

`POST /enroll/start` `{suite, code, device_name, kem_pk, sig_pk}` ->
`{enroll_id, challenge, xwing_ct, user:{user_id, name, roles[]}, directory_epoch, server_time}`

`POST /enroll/finish` `{enroll_id, signature, key_confirm}` -> `{certificate, directory}`

Enrolment codes are made to be read aloud and typed: 16 characters of Crockford base32
(`0-9 A-Z` without `I L O U`), shown in four groups, for example `K7QM-2XVD-9RTA-HB4N` (80 bits).
The server normalises what it receives before hashing: trim, upper-case, drop hyphens and spaces,
read `O` as `0` and `I` or `L` as `1`. Clients send what the person typed.

| Failure | Code and reason |
|---|---|
| Code unknown, used or expired | `QG_INVALID_INPUT` / `invite_invalid` (one answer for all three) |
| Signature or key confirmation wrong | `QG_BAD_SIGNATURE` / `proof_failed` |
| A loss report is open for this person | `QG_QUARANTINED` / `enrolment_held` (rule QG-R011). The hold applies while the incident is open or re-keying, and after a refused attempt it stays until an operator lifts the response |

### 4.2 Session

`POST /session/start` `{suite, device_id}` -> `{start_id, challenge, xwing_ct, directory_epoch, server_time}`

`POST /session/finish` `{start_id, signature, key_confirm}` ->
`{session_id, expires_at, hard_expires_at, user:{user_id, name, roles[], status}, device:{device_id, name}, directory_epoch, first_session: bool}`

`POST /session/end` (authenticated) -> `204`.

Unknown and revoked devices get the same shape from `/session/start`; the refusal happens at
`/session/finish` with `QG_DENY_REVOKED` for a revoked device (rule QG-R001) and `QG_BAD_SIGNATURE` otherwise.

## 5. Invites and people

People are read from the directory (`users`). There is no separate user list route.

| Route | Who | Body -> result |
|---|---|---|
| `POST /invites` | admin; anyone for themselves | `{user_id}` (existing person, new device) or `{name, roles[]}` (new person) -> `{invite_id, code, user_id, expires_at}`. The code is returned once. Inviting a new person with `admin` or `operator` creates a change request instead: `{change_id}` |
| `GET /invites` | admin; own | `[{invite_id, user_id, user_name, created_by, expires_at, status: "pending"|"used"|"expired"|"cancelled"}]` |
| `DELETE /invites/{id}` | creator, admin | `204` |

## 6. Files

| Route | Body -> result |
|---|---|
| `GET /files` | `?q=&classification=` -> list of File (only files the caller owns or has a slot for) |
| `POST /files` | `{name, classification, size_bytes, chunk_count}` -> `{file_id, version: 1}` (pending version) |
| `GET /files/{id}` | File plus `versions:[{version, committed_at, committed_by_device, reason}]` and `activity:[Receipt]` (last 20 for this file) |
| `DELETE /files/{id}` | owner -> `204`; slots, blobs and pending versions removed |
| `POST /files/{id}/versions` | `{reason: "rekey"|"update", size_bytes, chunk_count}` -> `{version}` (pending) |
| `PUT /files/{id}/versions/{v}/chunks/{n}` | raw ciphertext chunk, `Content-Type: application/octet-stream` -> `204`. Idempotent for the same bytes |
| `POST /files/{id}/versions/{v}/commit` | `{manifest, manifest_sig, wraps:[{device_id, xwing_ct, wrapped_dek}], recovery_wrap:{xwing_ct, wrapped_dek}}` -> `{file: File, receipt_id}` |
| `GET /files/{id}/slot` | -> `{slot_id, file_id, version, device_id, wrap_epoch, inner_wrap:{xwing_ct, wrapped_dek}, manifest, manifest_sig, signer_device_id, lease:{lease_id, expires_at}, receipt_id}`. `wrap_epoch` is the directory epoch the inner wrap was bound to: the manifest's for a wrap made at commit, the share statement's for a wrap added by `/share` |
| `GET /files/{id}/chunks/{n}` | header `QG-Lease: lse_...` -> raw ciphertext chunk. The lease is checked on every chunk |
| `POST /files/{id}/share` | `{share:{suite, file_id, version, recipients:[device_id], directory_epoch}, share_sig, wraps:[...]}` -> `{file: File, receipt_id}` |
| `POST /files/{id}/unshare` | `{user_id}` -> `{file: File, receipt_id}`; that person's slots are deleted and the file is queued for re-key |
| `GET /rekey/pending` | -> `{rekeys:[{file_id, name, version, reason: "exposed"|"held"|"unshare", incident_id | null, recipients:[device_id]}], shares:[{file_id, name, version, device_id, device_name}]}` |

- `rekeys` lists files owned by this device's person that need a new key (only the owner's devices
  may commit a version with `reason: "rekey"`; a holder who is not the owner gets `QG_DENY_POLICY` /
  `owner_required`, because the server cannot check that a re-encrypted file still has the same
  contents). The client re-encrypts
  under a new file key, uploads a new version with `reason: "rekey"` and commits it for exactly
  `recipients`. Commit swaps the version atomically and removes the old slots and ciphertext.
- `shares` lists files this device can open that another active device of the same person cannot
  yet; the client adds a wrap with `/share`. This is how a second device catches up.
- Commit failures: recipient not allowed by policy -> `QG_DENY_POLICY` / `recipient_not_allowed`;
  manifest signature -> `QG_BAD_SIGNATURE`; hash or chunk count mismatch -> `QG_INVALID_INPUT` /
  `ciphertext_mismatch`; old epoch -> `QG_STALE_EPOCH`; already committed -> `QG_CONFLICT`.
- `recovery_wrap` is required once the directory carries a `recovery_pk` and must be absent before:
  `QG_INVALID_INPUT` / `recovery_wrap_required` or `no_recovery_key`.
- A lease is bound to the session that received it; a chunk read with another session's lease answers `QG_LEASE_EXPIRED`.
- Only the owner's devices create or commit a later version of a file, whatever the `reason`; anyone else answers `QG_DENY_POLICY` / `owner_required`.
- A file the caller may not see answers `QG_NOT_FOUND` on every route.

## 7. Devices and incidents

| Route | Who | Body -> result |
|---|---|---|
| `GET /devices` | everyone: own devices; operator, admin, auditor: `?scope=all` | list of Device |
| `PATCH /devices/{id}` | owner | `{name}` -> Device (publishes a new directory epoch) |
| `POST /devices/{id}/report-lost` | owner of the device, from another device | `{lost_at, note?}` -> RevokeResult |
| `POST /devices/{id}/revoke` | operator | `{compromise_time, reason}` -> RevokeResult |
| `GET /incidents` | operator, auditor; employee sees own | `?status=` -> list of IncidentSummary |
| `GET /incidents/{id}` | same | Incident |
| `GET /incidents/{id}/exposure` | same | Exposure |
| `GET /incidents/{id}/bundle` | operator, auditor | ProofBundle (`spec/SUITE.md`), verifiable offline with `qg verify` |
| `POST /incidents/{id}/close` | operator | Incident; refused with `QG_CONFLICT` / `rekey_pending` while exposed files wait |

Revocation also cancels every pending enrolment code for that person, and every pending code that person or the lost device created for anyone.

Reporting your own device lost revokes it at once: safety first, the operator can correct the
compromise time afterwards by calling `/revoke` on the same device, which re-scopes the incident
and never restores access. Both calls are idempotent and return the same incident.

```
RevokeResult    {incident_id, device_id, status: "revoked", directory_epoch, time_to_enforce_ms,
                 sessions_ended, slots_deleted, checkpoint: Checkpoint, receipt_id}
IncidentSummary {id, device_id, device_name, user_id, user_name, status: "open"|"rekeying"|"contained"|"closed",
                 reported_at, compromise_time, counts:{exposed, held, never_released, rekeyed, pending}, denied_attempts}
Incident        IncidentSummary + {reported_by:{user_id, name}, note, time_to_enforce_ms, directory_epoch,
                 timeline:[{step: "reported"|"revoked"|"scoped"|"rekey_started"|"rekey_progress"|"rekey_done"|"denied_attempt"|"rescoped"|"bundle_exported"|"closed",
                            ts, receipt_id | null, detail}],
                 alert_ids[]}
Exposure        {incident_id, compromise_time,
                 exposed:[ExposedFile], held:[ExposedFile], never_released:[ExposedFile],
                 suspect_decisions:[Receipt]}
ExposedFile     {file_id, name, classification, releases:[{ts, receipt_id}], rekey: "pending"|"done"|"not_needed", new_version | null}
```

`contained` means every exposed and held file has a new key. `denied_attempts` counts requests
from the revoked device after the revoke committed.

## 8. Changes, alerts, signals, policy

| Route | Who | Body -> result |
|---|---|---|
| `GET /changes` | admin, operator, auditor | `?status=` -> list of Change |
| `POST /changes` | admin | `{change:{suite, type: "role_grant"|"role_revoke"|"recovery_release", target_user_id, role | null, file_id | null, reason, directory_epoch}, signature}` -> Change |
| `POST /changes/{id}/approve` | a different admin (operator too for `recovery_release`) | `{signature}` -> Change (applied when approvals are complete) |
| `POST /changes/{id}/reject` | admin | `{reason}` -> Change |
| `GET /alerts` | operator, auditor | `?status=&rule_id=` -> list of Alert |
| `GET /alerts/{id}` | operator, auditor | Alert plus `receipts:[Receipt]` and, for QG-R007, `path:[{from, to, relation}]` |
| `POST /alerts/{id}/ack` | operator | `{note?}` -> Alert |
| `POST /responses/{id}/lift` | operator who is not the person, device or session the response contains; an admin when the contained person is an operator | `{reason}` -> Alert. Lifting your own containment answers `QG_DENY_POLICY` / `self_lift` |
| `POST /signals` | operator; service identity | Security Event Token shaped body (`spec/SUITE.md`) -> `{signal_id, accepted: true, duplicate: bool}` |
| `GET /signals` | operator, auditor | recent signals, newest first: the fields of the `Signal` type in `web/src/client/types.ts`, which mirror `spec/openapi.json` |
| `GET /policy` | everyone | `{bundle_hash, version, signed_at, signatures, document, rules:[{id, effect: "allow"|"deny", description, roles[], actions[], conditions}]}`. `document` is the b64u of the exact signed bundle bytes; `bundle_hash` is its SHA-256 and `signatures` cover it, so a client can check the rules it is shown |
| `GET /overview` | admin, operator, auditor | `{active_devices, revoked_devices, pending_rekeys, open_alerts, open_incidents, last_time_to_enforce_ms | null, directory_epoch, tree_size, decisions_by_hour:[{hour, allow, deny}]}` (last 24 hours) |

`Change` = `{id, type, target_user:{user_id, name}, role, file_id, reason, requested_by:{user_id, name, device_id}, requested_at, status: "pending"|"applied"|"rejected", approvals:[{user_id, name, device_id, at, signature}], approvals_required, change, change_hash, signature}`.

`change` is the exact statement the requester signed, `signature` is that signature, and `change_hash` is the b64u SHA-256 of its canonical JSON. An approver verifies `signature` against the requester's certificate, recomputes `change_hash` from `change`, and signs it (context `QG/v1/change`); the server rejects an approval whose signature does not cover that hash.

Approval rules (the seeded organisation has two admins and one operator, so these must be satisfiable):

- `role_grant` of `admin` or `operator`: `approvals_required` is 1, from an admin who is neither the requester nor the target.
- `role_grant` of `employee` or `auditor`, and every `role_revoke`: `approvals_required` is 0; applied at once and recorded.
- `recovery_release`: `approvals_required` is 2, from admins or operators other than the requester.

Approving your own request, or a request that targets you, answers `QG_DENY_POLICY` / `self_approval`.

## 9. Evidence, services, messaging, recovery

| Route | Who | Body -> result |
|---|---|---|
| `GET /log/receipts` | own receipts; auditor, operator: all | `?user_id=&device_id=&resource=&action=&decision=` -> list of Receipt |
| `GET /log/receipts/{id}` | same | Receipt |
| `GET /log/proof/{index}` | any session | `?tree_size=` -> `{leaf_index, tree_size, leaf_hash, audit_path[], checkpoint}` |
| `GET /log/consistency` | any session | `?from=&to=` -> `{from, to, proof[]}` |
| `GET /services` | admin, operator, auditor | `[{service_id, name, status, keys:[{key_id, alg, status: "active"|"retiring"|"retired", created_at, retired_at | null}]}]` |
| `POST /services` | admin | `{name}` -> service with its first key |
| `POST /services/{id}/rotate` | admin; operator with `emergency: true` | `{reason, emergency}` -> service; publishes a new signed key set |
| `GET /messages` | everyone | `[{message_id, from:{user_id, name, device_id}, to_user_id, sent_at, envelope:{xwing_ct, ciphertext}, envelope_digests:[{device_id, digest}], signature}]`. `envelope` is the calling device's only. `envelope_digests` lists the digest of every envelope of the message, sorted by `device_id`; the sender's signature covers those digests and `to_user_id` (`spec/SUITE.md` 11), so any one recipient device can verify it without seeing the others' ciphertext |
| `POST /messages` | everyone | `{to_user_id, envelopes:[{device_id, xwing_ct, ciphertext}], signature}` -> `{message_id}`. The server recomputes the envelope digests and answers `QG_BAD_SIGNATURE` when the signature does not cover them |
| `POST /files/{id}/recover` | admin holding the recovery kit | `{change_id}` -> `{recovery_wrap, wrap_epoch, version, file_id, manifest, manifest_sig, signer_device_id, lease:{lease_id, expires_at}, receipt_id}` only when that `recovery_release` change is applied. Each change releases once (`QG_CONFLICT` / `already_used`); a file committed before a kit existed answers `QG_NOT_FOUND` / `no_recovery_slot` |

`GET /keys` (public) -> `{suite, epoch, keys:[{service_id, key_id, alg, public_key, status}], signatures:{ed25519, mldsa}}`.
A retired key presented to any route answers `QG_DENY_POLICY` / `key_retired` and raises QG-R010.

## 10. First start and demo data

On first start the server generates its keys into `keys/` and creates the synthetic organisation.
It does not print or log any enrolment code: no secret ever appears in server output.

The recovery kit is issued the same way, once, by whoever operates the server:

```
docker compose exec quantumguard python -m qg.admin recovery-kit init --out /tmp/recovery-kit.json
```

The private half goes to that command's output or the chosen file (never inside the data or keys
volumes); the server keeps only the public half and publishes it in the next directory epoch. A second
run is refused. Until a kit exists, files carry no recovery slot.

Codes for the seeded people are issued by a local command that needs access to the data directory,
which is the same trust as owning the server:

```
docker compose exec quantumguard python -m qg.admin invite --all --json     # one code per seeded person
docker compose exec quantumguard python -m qg.admin invite --user-id usr_... --json
```

It prints `{"invites":[{"user_id","name","roles","code","expires_at"}]}` to its own standard output
(the caller's terminal, not the server log). These codes are single use and live 24 hours.
`make demo` calls it, then works through the public API like any other client. No HTTP route
creates a code without a session, and no route creates data without a session or an invite.

## 11. Responses to failures that prove no key

A failed session proof or a bad request MAC does not prove who sent it, so the automatic response
(rule QG-R012) falls on the source, never on the device that was named: scope kind `source`, id
`<address>|<claimed device or person>`. For 300 seconds further failed proofs or bad MACs from that
address for that claim answer `QG_RATE_LIMITED` / `source_throttled` (or `QG_BAD_MAC`) without new
records; a correct proof is always accepted, and an operator can lift the response. Behind a reverse
proxy set `QG_TRUSTED_PROXIES` to the proxy's address so the client address is taken from
`X-Forwarded-For`; without it every client appears to come from the proxy.
