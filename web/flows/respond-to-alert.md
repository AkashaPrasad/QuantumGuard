# Flow: respond-to-alert
Persona and goal: An operator sees an alert and needs to understand why it fired, what was done automatically, and decide whether to keep or lift that response.
Entry points: Alerts list; Overview "Open alerts"; the alert count in the sidebar.
Happy path:
1. The list shows severity, rule id, one-line summary, who or what it concerns, the automatic response and when it ends.
2. Open an alert (sheet): "Why this fired" (the rule's condition in words), "Evidence" (the receipts that matched, each openable), "What was done" (action, scope, expiry). For a new privilege path (QG-R007) the path is drawn.
3. "Acknowledge" (optional note) -> `POST /alerts/:id/ack`. If the response should end early: "Lift response" with a required reason -> `POST /responses/:id/lift`.
States: loading | empty ("No open alerts") | error | offline | session expired.
Errors: `QG_CONFLICT` (already acknowledged or lifted) refreshes; `role_required`.
Exit points and what is saved: receipts for acknowledge and lift.
Clicks to complete: 2 to acknowledge. Keyboard path: list -> sheet -> buttons.
Tour anchors: `alerts-list`. Animations: new alerts enter at the top of the list.
Playwright test ids: `alert-row-<id>`, `alert-why`, `alert-evidence`, `alert-response`, `alert-ack`, `alert-lift`, `alert-lift-reason`, `alert-lift-confirm`, `alert-revoke-device`.
