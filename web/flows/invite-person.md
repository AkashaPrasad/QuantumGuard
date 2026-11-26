# Flow: invite-person
Persona and goal: An admin wants to bring a new person into the organisation.
Entry points: People -> "Invite a person"; command palette.
Happy path:
1. Dialog: name, role (Employee, Auditor, Operator, Admin). Choosing Operator or Admin shows "Needs approval from a second admin before the code is issued."
2. "Create code" -> `POST /invites`. Result: the code once, with Copy, the 15-minute countdown, and "This code is shown once."
   For Operator or Admin: result is "Sent for approval" with a link to Change requests.
States: loading | error in the dialog | offline | session expired.
Errors: `QG_INVALID_INPUT` on the name; `role_required` if the caller is not an admin.
Exit points and what is saved: an invite (or a change request). Closing the dialog hides the code for good; People lists the invite as Pending with Cancel.
Clicks to complete: 3. Keyboard path: name -> role select -> Create.
Tour anchors: `people-invite`. Animations: none.
Playwright test ids: `people-invite`, `invite-name`, `invite-role`, `invite-submit`, `invite-code`, `invite-copy`, `invite-row-<invite_id>`, `invite-cancel-<invite_id>`.
