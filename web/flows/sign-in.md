# Flow: sign-in (unlock)
Persona and goal: Someone returning to an enrolled device wants to get back to work.
Entry points: `/app/unlock`; any `/app/*` route while locked (returns there afterwards); the lock overlay after idle.
Happy path:
1. The screen names the device and person. Type the passphrase, press Enter -> keystore opens locally, then `POST /session/start|finish`.
2. Lands on Files (employee) or Overview (other roles), or on the page they were on.
States: loading (button shows "Unlocking", field disabled) | error inline under the field | offline (can still try; message explains the passphrase was right but the server was not reached) | device revoked (replaces the form with the Access removed page).
Errors: `QG_LOCAL_PASSPHRASE` inline, field keeps focus and selects its text; `QG_DENY_REVOKED` -> revoked page; `QG_QUARANTINED` -> message with the lift time.
Exit points and what is saved: a session in memory only. Closing the tab ends it.
Auto-lock: after 10 minutes without input the overlay appears; a 60-second warning toast precedes it. The session clock in the top bar counts down.
Clicks to complete: 1 (Enter). Keyboard path: field is focused on arrival.
Tour anchors: none. Animations: none.
Playwright test ids: `unlock-passphrase`, `unlock-submit`, `unlock-error`, `unlock-forget`, `lock-overlay`.
