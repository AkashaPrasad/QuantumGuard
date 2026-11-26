# Flow: role-change-and-approval
Persona and goal: An admin wants to give or remove a role; a second admin has to agree before a sensitive role takes effect.
Entry points: People -> row menu -> "Change role"; Change requests.
Happy path:
1. Requester: pick the role and write a reason -> `POST /changes` (signed by this device). The request shows as Pending, "0 of 2 approvals".
2. Approver (a different admin, on their own device): Change requests -> open the request -> "Approve" -> `POST /changes/:id/approve`. At the required count the change is applied and the directory epoch advances.
States: loading | empty ("No change requests") | error | offline | session expired.
Preventing the error: on a request you made, or one about you, Approve is disabled with "A different admin must approve this." If the call is made anyway the `self_approval` message appears.
Errors: `self_approval`; `QG_CONFLICT` (already decided) refreshes the row.
Exit points and what is saved: a signed change record; receipts for request and each approval.
Clicks to complete: 3 to request, 2 to approve. Keyboard path: table rows -> sheet -> buttons.
Tour anchors: `changes-list`. Animations: none.
Playwright test ids: `people-change-role-<user_id>`, `change-role`, `change-reason`, `change-submit`, `change-row-<id>`, `change-approve`, `change-reject`, `change-self-note`.
