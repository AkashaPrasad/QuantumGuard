# Flow: incident-review
Persona and goal: An operator (or the affected employee, for their own device) wants to know what the lost device could have seen, confirm it is contained, and keep proof.
Entry points: Incidents list; the result panel after a revoke; an alert's incident link; Overview "Open incidents".
Happy path:
1. The incident page header: device, owner, status, and four figures: time to enforce, exposed, held, attempts denied since.
2. Timeline, oldest first: Reported -> Revoked -> Scope calculated -> New keys started -> New keys finished -> each denied attempt -> Proof exported -> Closed. Each entry has its time and receipt link. Polls every 2 seconds while not contained.
3. Exposure tabs: Exposed (opened at or after the loss time), Held (key received before), Never released, Suspect decisions. Each file row shows when it was released and whether it has a new key.
4. "Export proof bundle" -> `GET /incidents/:id/bundle` saves a JSON file; "Verify it here" opens verify-evidence with it loaded.
5. "Close incident" when everything has a new key.
States: loading | empty tabs ("Nothing in this group") | error | offline | session expired.
Errors: `rekey_pending` on Close explains what is still waiting; `QG_NOT_FOUND`.
Exit points and what is saved: receipts for export and close.
Clicks to complete: 1 to see everything; 1 to export; 1 to close. Keyboard path: tabs are arrow-key navigable; timeline entries are a list.
Tour anchors: `incident-figures`, `incident-timeline`, `incident-exposure`, `incident-export`.
Animations: timeline entries enter as real events arrive.
Playwright test ids: `incident-status`, `incident-enforce-ms`, `incident-timeline`, `incident-step-<step>`, `incident-tab-<group>`, `incident-file-<file_id>`, `incident-export`, `incident-verify`, `incident-correct-time`, `incident-close`.
