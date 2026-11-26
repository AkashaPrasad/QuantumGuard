# Flow: recovery
Persona and goal: Every device that could open a file is gone. An admin holding the recovery kit needs the file back, and nobody should be able to do that alone.
Entry points: Settings -> Recovery; a file's detail sheet when no active device can open it.
Happy path:
1. Settings -> Recovery explains the kit (a key created at first start and shown once; the server does not keep it) and lists recovery requests.
2. "Request recovery" for a file with a reason -> `POST /changes {type: recovery_release}`.
3. Two other admins approve it in Change requests.
4. The kit holder runs the command shown on the request (`qg recover <file> --change <id> --kit <path>`) on a trusted machine. The console never asks for the kit.
States: loading | empty ("No recovery requests") | error | offline | session expired.
Errors: `self_approval`; `QG_DENY_POLICY` when the change is not yet applied.
Exit points and what is saved: a change record, approvals, a `recovery.release` receipt when the slot is released.
Clicks to complete: 3 to request. Keyboard path: standard form.
Tour anchors: none. Animations: none.
Playwright test ids: `recovery-request`, `recovery-file`, `recovery-reason`, `recovery-submit`, `recovery-row-<id>`, `recovery-command`.
