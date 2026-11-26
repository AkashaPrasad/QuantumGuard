# Flow: rekey-pending
Persona and goal: After a revocation or an unshare, files need new keys. The person should not have to do anything, only see that it is happening and when it is finished.
Entry points: automatic after unlock and after report-lost, revoke or unshare whenever `GET /rekey/pending` is not empty.
Happy path:
1. A banner under the top bar: "8 files are getting new keys. Keep this tab open." with a progress bar and "Details".
2. For each file this device re-encrypts under a new key and commits a new version (`POST /files/:id/versions`, chunks, commit) for the remaining devices only.
3. Banner turns to "All affected files have new keys" for 6 seconds, then leaves. The incident becomes Contained.
States: loading | paused (offline or locked: "Paused, resumes when you are back") | error on one file (skipped, listed in Details with Retry; the rest continue) | nothing pending (no banner).
Refresh or close midway: the journal is on the server; the banner resumes from the remaining files.
Exit points and what is saved: new versions and slots; old ciphertext and slots deleted by the commit.
Clicks to complete: 0. Keyboard path: banner is a status region (`role="status"`), "Details" is a button.
Tour anchors: none. Animations: none (a plain progress bar; this is background work).
Playwright test ids: `rekey-banner`, `rekey-progress`, `rekey-details`, `rekey-done`.
