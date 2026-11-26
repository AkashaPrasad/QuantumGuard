# Flow: verify-evidence
Persona and goal: An auditor (or anyone holding a receipt) wants to check, without trusting the server, that a decision is in the log and the log has not been changed.
Entry points: Evidence -> Verify; "Verify" on any receipt slip; "Verify it here" on an incident; dropping a bundle file on the Verify page.
Happy path (one receipt):
1. Paste or pick a receipt id, "Verify" -> `GET /log/receipts/:id`, `GET /log/proof/:index`, `GET /log/checkpoint`; hashing and both signature checks run on this device.
2. The proof climbs: receipt -> each tree level -> root matches the signed checkpoint -> Ed25519 signature valid -> ML-DSA-65 signature valid. Result: "Verified on this device" with the checkpoint details.
Happy path (bundle): drop the file; every receipt in it is checked with no network request. Result lists the count and the checkpoint.
Failure: "Verification failed at entry 412" with which check failed (hash path, root, or which signature). The slip gets no stamp.
States: empty (explains what can be verified and where receipt ids are found) | loading (steps appear as they finish) | error | offline (single receipt needs the network; a bundle does not, and the page says so).
Exit points and what is saved: nothing.
Clicks to complete: 1. Keyboard path: input -> Verify; the step list is a live region.
Tour anchors: `evidence-verify`. Animations: MerkleClimb -> verifier steps; reduced motion shows the step list only.
Playwright test ids: `verify-input`, `verify-submit`, `verify-drop`, `verify-steps`, `verify-result`, `verify-failed-index`.
