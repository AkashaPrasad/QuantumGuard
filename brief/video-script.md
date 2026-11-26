# QuantumGuard: demo video script (about 3:40)

The browser part is automated and timed: `bash scripts/demo-video.sh` starts a fresh demo stack on
`http://localhost:18080`, opens a visible Chromium window, enrols Aiko's phone and the operator off camera,
then counts down 8 seconds and plays the take. Everything happens in **one window** with three tabs: Aiko's
laptop (`laptop.localhost`), Aiko's phone (`phone.localhost`) and Priya the operator (`ops.localhost`); each tab
is its own device. Record just that window.

- Every cue is printed in the terminal the moment it starts, with its time. A small caption bar shows the
  same line on screen; turn it off with `QG_DEMO_CAPTIONS=0`.
- Window size: `QG_DEMO_SIZE=1440x900` (default). Lead-in before the take: `QG_DEMO_LEAD_IN=8` seconds.
- Remove the demo stack afterwards with `bash scripts/demo-video.sh --down`. The stack on port 8080 is never
  touched. Every name and file is synthetic.

## Narration

Read at an easy pace (about 150 words a minute). Each block starts when its cue appears.

| Time | On screen | Say |
|---|---|---|
| 0:00 | Public page: the claim, then **How it works** | "This is QuantumGuard. When a laptop goes missing, most systems wait for a session to expire. QuantumGuard cuts the device off in milliseconds, lists every file it could have read, gives those files new keys, and leaves a record anyone can verify offline, all with post-quantum cryptography." |
| 0:12 | **Launch console**, then **Enrol**: code, device name, passphrase; two key pairs are created | "Aiko enrols her laptop with a one-time code. The browser creates two key pairs: ML-DSA-65 for signing, and X-Wing, which combines X25519 with ML-KEM-768, for key exchange. It proves it holds both private keys before the server certifies the device. The keys never leave the laptop; they are stored under her passphrase with Argon2id." |
| 0:40 | **Files**, **Protect**: a confidential trial protocol; chunks are sealed; the receipt | "She protects a confidential trial protocol. It is encrypted right here, in one-megabyte AES-GCM chunks. The file key is wrapped for each of her devices, and the server seals every wrap again, so the server cannot read the file, and a device cannot open it without the server's release." |
| 1:00 | The file opens: "Checked on this device" | "Opening asks the policy engine at that moment, not at sign-in. An allow releases the key with a sixty-second lease, and every decision, allow or deny, becomes a receipt in a Merkle log." |
| 1:15 | Aiko's phone opens the same file | "Her phone has its own wrapped key, so it opens the same file." |
| 1:28 | Laptop, **Devices**, **Report lost** on the phone, last safe an hour ago; "Access removed", enforced in milliseconds | "Now the phone is lost. From her laptop, Aiko reports it, last safe an hour ago. One transaction revokes the device, deletes its key slots, ends its sessions and publishes a new signed device list. The server measured it: a few milliseconds." |
| 1:50 | The phone: "Access removed from this device" | "The phone tries again. It is refused, the attempt is recorded, and an alert fires." |
| 2:00 | Laptop: the file has its new key; the incident is **Contained** | "The phone opened that file after the time it was lost, so the file counts as exposed. Aiko's laptop gives it a new key by itself, and the incident is contained." |
| 2:15 | Operator, **Alerts**: QG-R001; the sheet shows **Who, where, what**, the reason and the receipts | "Priya, the operator, sees alert QG-R001. Every alert names the identity, the service and the event, the rule that fired, and the receipts behind it. Detection is fourteen fixed rules, with no machine learning. In our benchmark it caught all 160 injected attacks, with about one false alert per thousand normal events." |
| 2:35 | The incident, **Export proof bundle**, then **Verify**: "Verified on this device" | "She exports the incident's proof bundle: every receipt with its Merkle proof, and checkpoints signed with both Ed25519 and ML-DSA-65. It verifies right here in the browser, with public keys only and no network request." |
| 3:00 | A copy with one receipt changed: verification fails at that entry | "Change a single receipt, and verification fails and points at the exact entry." |
| 3:15 | Public page: **What we do not protect**, then **Measured performance** | "We state plainly what we do not protect: anything decrypted before revocation, malware on an unlocked device, metadata. Every number here is measured on this build." |
| 3:30 | Back to the top; repository link | "The code, the threat model with a test for every claim, and a three-command setup are on GitHub. Thank you." |

## Before you record

- Close other windows over the top-left of the screen, or set `QG_DEMO_SIZE` to your screen.
- Do a silent take first if you like: the run is the same every time, with fresh data.
- Read the enforcement time from the screen (it is also printed in the terminal); do not quote a number that
  is not shown.
