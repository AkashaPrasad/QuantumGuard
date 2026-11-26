# Flow: revoke-device-operator
Persona and goal: An operator learns a device is compromised (a call, an alert, a signal) and must cut it off, or correct the loss time on an existing report.
Entry points: All devices -> "Revoke"; an alert -> "Revoke this device"; an incident -> "Correct the loss time".
Happy path:
1. "Revoke" on the device row. Dialog: device, owner, "Compromised since" (presets and exact time), reason (required, one line).
2. "Revoke access now" -> `POST /devices/:id/revoke`. Result panel as in report-lost-device, then "Open incident".
Correcting the time: the same dialog prefilled; submitting re-scopes the incident (timeline gains "Scope recalculated") and never restores access.
States: loading | error with Retry (idempotent) | offline | session expired.
Errors: `role_required`; `QG_NOT_FOUND`.
Exit points and what is saved: revocation, incident, receipts, a forced checkpoint.
Clicks to complete: 2 plus time and reason. Keyboard path: as report-lost-device.
Tour anchors: `ops-devices`. Animations: RevokeCut.
Playwright test ids: `ops-device-row-<device_id>`, `ops-device-revoke-<device_id>`, `revoke-time`, `revoke-reason`, `revoke-confirm`, `revoke-result`, `revoke-open-incident`.
