# Flow: add-second-device
Persona and goal: An employee wants their phone or second computer to open the same files.
Entry points: Devices -> "Add a device".
Happy path:
1. "Add a device" -> `POST /invites {user_id: me}`. A panel shows the code in large mono type, a copy button, a 15-minute countdown, and three numbered instructions for the new device.
2. On the new device: enrol-device flow with that code.
3. Back on the first device the new device appears in the list within a few seconds, and the catch-up banner says "Sharing 9 files with Aiko's phone (4 of 9)" -> `GET /rekey/pending` (`shares`) and `POST /files/:id/share` for each.
States: loading | error | offline | code expired (panel says so and offers "New code") | enrolment held (a lost-device report is open; explains why).
Exit points and what is saved: an invite; later, slots for the new device. The first device must be unlocked for the catch-up; if it is closed the banner returns next time.
Clicks to complete: 1 on the first device. Keyboard path: code is in a read-only input so it can be selected; copy button announces "Copied".
Tour anchors: `devices-add`. Animations: WrapBeams (compact) during catch-up.
Playwright test ids: `devices-add`, `invite-code`, `invite-countdown`, `rekey-banner` (the same banner reports catch-up shares).
