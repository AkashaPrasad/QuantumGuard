# Flow: report-lost-device  (the hero flow)
Persona and goal: An employee has lost a device and needs it cut off now, from the device they still have.
Entry points: Devices -> "Report lost" on any device that is not this one; command palette "Report a lost device"; Help.
Happy path (2 clicks and a time):
1. Click "Report lost" on the device (click 1). A dialog names the device and asks "When did you last have it?" with presets (Just now, 1 hour ago, This morning, Yesterday) and an exact date and time. Default: Just now. One line explains why the time matters: files opened after it are treated as exposed.
2. Click "Revoke access now" (click 2) -> `POST /devices/:id/report-lost`.
3. The dialog becomes the result: "Access removed in 38 ms", directory epoch 14 -> 15, sessions ended, key slots deleted, and the counts exposed / held / never released. Buttons: "See what was affected" (incident page) and "Done".
4. The re-key banner starts on this device: "8 files are getting new keys (2 of 8)". It continues across pages and after a refresh.
States: loading (confirm button shows "Revoking", cannot be double-submitted) | error in the dialog with Retry (the call is idempotent) | offline: the dialog says the report cannot be sent and shows the operator contact line | session expired -> lock overlay first.
Errors: `QG_DENY_POLICY` (not your device); `QG_CONFLICT` (already revoked) shows the existing incident instead of an error.
On the lost device: its next request shows the full-page "Access removed from this device" state; enrolment from it is held while the report is open.
Exit points and what is saved: an incident; the device is revoked at once. There is no undo: a found device is enrolled again as a new device.
Clicks to complete: 2 plus the time. Keyboard path: dialog focus starts on the first preset; arrow keys move between presets; Enter on the confirm button.
Tour anchors: `devices-list`, `devices-report-lost`.
Animations: RevokeCut -> the revoke response (beam cut, slot dissolves, epoch ticks).
Playwright test ids: `device-row-<device_id>`, `device-report-<device_id>`, `report-preset-<name>`, `report-time`, `report-note`, `report-confirm`, `report-cancel`, `report-result`, `report-enforce-ms`, `report-view-incident`, `rekey-banner`.
