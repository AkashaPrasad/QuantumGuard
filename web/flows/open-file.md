# Flow: open-file
Persona and goal: Someone wants to read a file that was shared with this device.
Entry points: "Open" on a row in Files (one click); "Open" in the file detail sheet; `/app/files/:id`.
Happy path:
1. Click Open -> `GET /files/:id/slot` (policy decides now) -> chunks download and decrypt on this device -> the browser saves the file.
2. The row shows a verified mark ("Checked on this device") and "View receipt".
States: loading (row button becomes a small progress with "Asking", "Released", "Decrypting 3 of 12") | error inline in the row with Retry | offline disables Open with reason | session expired -> lock overlay.
Errors: `QG_DENY_POLICY` shows "You do not have access to this" with the receipt link (the denial is recorded); `QG_LEASE_EXPIRED` offers "Open again"; `QG_LOCAL_INTEGRITY` shows the integrity message and saves nothing.
Exit points and what is saved: the decrypted file through a one-time object URL that is revoked immediately; nothing in browser storage.
Clicks to complete: 1. Keyboard path: row actions are buttons in tab order; Enter on a focused row opens the detail sheet.
Tour anchors: `files-list`.
Animations: OpenLayers -> `released` then `unwrapped`.
Playwright test ids: `file-row-<file_id>`, `file-open-<file_id>`, `file-open-progress`, `file-verified`, `file-receipt-link`.
