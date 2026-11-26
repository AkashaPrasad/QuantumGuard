# QuantumGuard: five-minute demo script

## Before recording

- Start the stack with `docker compose up --build -d --wait`, issue the recovery kit with
  `make recovery-kit` (keep its output offline; without a kit, files carry no recovery wrap), and run
  `docker compose exec quantumguard python -m qg.admin invite --all --json` for fresh codes.
- Use five browser profiles at `http://localhost:8080`, each with its own storage:
  - A: "Aiko's laptop", enrolled with Aiko Tanaka's code (the device that will be lost).
  - B: "Aiko's phone", enrolled with a code from **Devices**, **Add a device** on A.
  - C: Priya Raman, operator.
  - D and E: Mira Okafor and Tomas Lindqvist, the two admins.
- On A, protect two files before the take: `cell-line-inventory.xlsx` (restricted, shared with
  Daniel Mensah) and `trial-protocol.pdf` (confidential). Open the first one once.
- Keep one terminal open in the repository root.
- Every name and file is synthetic. Do not show the terminal output of the invite command after the
  codes have been used.

## Script

| Time | On screen | Spoken |
|---|---|---|
| 0:00 | Public page `/`, top section with the claim | "QuantumGuard protects a sensitive file so that, when a device is reported lost, no request from that device gets key material, every file it could read is listed and re-keyed, and every decision lands in a log anyone can verify offline. I will enrol a device, protect a file, lose the device, and prove what happened." |
| 0:30 | Profile A, **Enrol** (`/app/enrol`): enter the code, name "Aiko's laptop", passphrase. The key animation shows two key pairs created | "Enrolment is a one-time code. The browser creates two key pairs locally: ML-DSA-65 for signing and X-Wing, which is X25519 and ML-KEM-768 together, for key exchange. It proves it holds both private keys before the server issues a certificate. The private keys never leave this device; they are stored under the passphrase with Argon2id." |
| 1:00 | **Files** (`/app/files`): drop a file into **Protect**, choose recipients; the chunk animation shows 1 MiB blocks sealed, then beams to each recipient device | "The file is encrypted here in one-megabyte AES-256-GCM chunks under a new file key. That key is wrapped for each recipient device and for the organisation's recovery key, and the server seals each wrap again. The server stores ciphertext and sealed slots. It never sees the file key." |
| 1:25 | Open the file; the receipt sheet shows decision, matched rule, policy hash and leaf index | "Opening asks the policy engine now, not at sign-in. On allow, the server releases this device's slot with a 60-second lease. Every decision gets a receipt: who, which device, which rule, which policy version, and its place in the log." |
| 1:45 | Profile B, **Devices** (`/app/devices`): **Report lost** next to "Aiko's laptop", pick a time earlier than the last open, confirm | "The laptop is gone. From her phone, Aiko reports it lost and says when she last had it, which is earlier than now. Reporting takes two clicks and a time." |
| 2:00 | The dialog shows "Access removed from Aiko's laptop", **Enforced in** in milliseconds, sessions ended and the new directory epoch | "One transaction revoked the device, deleted its key slots, ended its sessions and published a new signed device list. The number here is the time to enforce, measured by the server." |
| 2:15 | Profile C, **Incidents** (`/app/ops/incidents`), open the incident: timeline (reported, revoked, scoped), **Enforced in**, exposure lists | "The operator sees the timeline. The exposure report splits files three ways against the loss time: opened after it, key held before it, or never released to that device. Exposed files are re-keyed first." |
| 2:40 | Profile B, the pending-work banner counts down to zero as new keys are made | "The phone is another of Aiko's devices, and only the owner's devices may give a file a new key, because the server cannot check that re-encrypted contents are unchanged. It re-encrypts each file under a new key for the remaining devices only. The server switches versions in one step and deletes the old slots and ciphertext. A crash in the middle resumes." |
| 3:00 | Profile A, any action: full page "Access removed from this device" | "The lost laptop tries again. Its session no longer exists and a new one is refused." |
| 3:10 | Profile C, **Alerts** (`/app/ops/alerts`): the QG-R001 alert: **Who, where, what** (Aiko Tanaka, her laptop, the gateway, the revoked-device attempt), its condition, receipts and response | "That attempt is a receipt and a critical alert from rule QG-R001. Every alert names the identity, the service and the event, which rule fired, and the receipts behind it. Detection is fourteen fixed rules, with no machine learning." |
| 3:30 | Profile D, **People** (`/app/admin/people`): request the operator role for Aiko. **Changes** (`/app/admin/changes`) shows the request with "A different admin must approve this." and **Approve** disabled. Profile E approves it | "Privilege changes are signed. Granting admin or operator needs a different admin to approve; the requester cannot approve their own request, and the server refuses it even if asked directly. A role that appears in the identity source without a signed change raises rule QG-R005, which quarantines that person for sensitive files, and QG-R007, which draws the new path to the recovery key." |
| 4:00 | Profile C, incident page: **Export proof bundle**; then **Verify** (`/app/evidence/verify`), load the bundle: "Verified on this device", the tree climbs to the signed root | "The proof bundle holds every receipt of this incident with its inclusion path, and checkpoints signed with both Ed25519 and ML-DSA-65. The browser checks it with public keys only and makes no network request." |
| 4:15 | Load a copy of the bundle with one character of a receipt changed: "Verification failed" with the leaf index. Terminal: `make scenario-verify` prints its JSON line with `first_bad_index` | "Change one character and verification fails at that receipt's index. The same check runs from the command line, and the verify scenario changes a byte inside the server's own stored log to show it is caught." |
| 4:30 | Public page, **What we do not protect**, then **Measured performance** | "What we do not protect: anything a device already decrypted before it was revoked, malware on an unlocked device, weak passphrases, keys in hardware, metadata, floods, and side channels. Measured on one machine, revocation is enforced in about ten milliseconds, an authenticated request adds under two milliseconds at the 95th percentile, and across 160 injected attacks every one was detected with about one false alert per thousand benign events." |
| 4:50 | Repository URL on screen | "The code, the threat model with a test for every claim, and three commands to run it are at the repository on screen." |

## Notes

- QG-R005 and QG-R007 are triggered by an identity-source signal, which the console does not send.
  To show them, cut to the terminal at 3:50 and run `make scenario-privilege`; its result line names
  `"alert_rule":"QG-R005"`, `"response":"quarantine_identity"` and `"path_rule":"QG-R007"`.
- Read the time to enforce from the screen during the take; do not quote a number that is not shown.
- Keep the video at or under five minutes.
