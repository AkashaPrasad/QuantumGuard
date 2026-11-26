# Flow: rotate-service-key
Persona and goal: An admin rotates a service's signing key on schedule; an operator rotates it at once when it may have leaked.
Entry points: Services -> a service -> "Rotate key".
Happy path:
1. Dialog: the service, its active key, a reason, and for operators an "Emergency: retire the old key immediately" switch (admins get a normal rotation where the old key is retiring for a short overlap).
2. "Rotate" -> `POST /services/:id/rotate`. The key list shows the new active key, the old one as Retiring or Retired, and the key set epoch.
States: loading | empty ("No services yet" with "Add a service" for admins) | error | offline | session expired.
Errors: `role_required`; `QG_CONFLICT` if a rotation is already in progress.
Exit points and what is saved: a new signed key set; a receipt. Use of a retired key afterwards raises QG-R010, visible in Alerts.
Clicks to complete: 3. Keyboard path: standard dialog.
Tour anchors: `services-list`. Animations: none.
Playwright test ids: `service-row-<id>`, `service-rotate-<id>`, `rotate-reason`, `rotate-emergency`, `rotate-submit`, `service-key-<key_id>`, `service-add`.
