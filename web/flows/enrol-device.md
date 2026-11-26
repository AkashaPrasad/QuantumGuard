# Flow: enrol-device
Persona and goal: A new person (or an existing one on a new device) holding a code from an admin wants this browser to become a trusted device.
Entry points: `/app/enrol`; "Launch console" on the public site when the browser has no device; link from `/app/unlock` ("Enrol a different device").
Happy path:
1. Enter the enrolment code (auto-uppercased, hyphens optional). Continue.
2. Name this device (prefilled from the platform, for example "MacBook, Chrome"). Continue.
3. Choose a passphrase and repeat it. Strength line updates as they type; 10 characters minimum; show and hide. "Create my keys" -> `POST /enroll/start`, `POST /enroll/finish`, then `POST /session/start|finish`.
4. Progress screen lists the five real steps as they finish: keys created on this device, possession proved, certificate issued (shows directory epoch), keystore sealed, session started. Then "Open the console".
States: loading (step 4 only) | error in place on the step that caused it | offline (buttons disabled with reason) | not applicable: empty, session expired, device revoked.
Errors: `invite_invalid` returns to step 1 with the code kept and the message; `enrolment_held` shows the hold explanation with no retry; `QG_BAD_SIGNATURE` offers "Start again", which returns to step 1 and clears the passphrase.
Exit points and what is saved: keystore in IndexedDB (private keys non-extractable, or wrapped under the passphrase); nothing else. Leaving before step 4 saves nothing.
Clicks to complete: 4. Keyboard path: Enter advances each step; focus lands on the first field of each step; Back is a button, and browser Back steps back inside the flow.
Refresh mid-flow: steps 1 to 3 restart at step 1 (the code is not stored); a refresh during step 4 shows "Enrolment was interrupted. The code is single use; ask for a new one if this device is not listed."
Tour anchors: none (the tour starts after first unlock).
Animations: KeyIssue -> `generating_keys` and `certificate_issued` events.
Playwright test ids: `enrol-code`, `enrol-device-name`, `enrol-passphrase`, `enrol-passphrase-confirm`, `enrol-next`, `enrol-back`, `enrol-create`, `enrol-progress`, `enrol-done`, `enrol-error`.
