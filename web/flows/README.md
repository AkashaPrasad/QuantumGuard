# User flows

One file per flow. Shared rules live here so each flow stays short.

## Navigation
```
Public   /  (home, with sections: how it works, product, architecture, security, limits, performance, questions)
         /docs   /status
Console  /app/enrol   /app/unlock
  My work        /app/files  /app/files/:id  /app/devices  /app/activity  /app/messages
  Organisation   /app/overview  /app/admin/people  /app/admin/changes  /app/admin/services  /app/admin/settings   (admin)
  Security       /app/overview  /app/ops/devices  /app/ops/alerts  /app/ops/incidents  /app/ops/incidents/:id  /app/ops/policy   (operator)
  Evidence       /app/evidence  /app/evidence/verify   (auditor, operator; everyone sees their own receipts in Activity)
  Help           /app/help
```
After unlock an employee lands on Files; admin, operator and auditor land on Overview. Menu groups a person has no role for are not shown. A deep link to a route the person may not use shows "Not available for your role" with a link home, never a blank page.

## States every console screen has
| State | What is shown |
|---|---|
| loading | Skeleton rows in the final layout; no spinners over content |
| empty | One serif headline, one sentence, the primary action |
| error | `ErrorNotice` in place of the content, with Retry |
| offline | Banner under the top bar: "You are offline. Nothing is sent until the connection returns." Mutating buttons are disabled with that reason |
| session expired | Lock overlay over the current page. After idle time it says "This device locked itself after 10 minutes idle."; after a manual lock or an ended session it says "This device is locked." Unlocking returns to the same place with input kept |
| device revoked | Full-page "Access removed from this device": what happened, when, who to contact, and "Forget this device" |

## Error messages
Every message says what happened, why, and what to do next, in one or two sentences. The details line shows code, reason and request id; a receipt id links to the receipt.

| Code (reason) | Title | Body |
|---|---|---|
| QG_INVALID_INPUT (invite_invalid) | That code did not work | It may be mistyped, already used, or older than 15 minutes. Ask your admin for a new one. |
| QG_INVALID_INPUT (other) | Something in the form was not accepted | Check the highlighted fields and try again. |
| QG_BAD_SIGNATURE | This device could not prove its keys | The keys on this device do not match the server's record. Lock and unlock, and if it repeats ask an operator to re-enrol the device. |
| QG_NO_SESSION | This device is locked | Enter your passphrase to continue. Nothing you typed was lost. |
| QG_BAD_MAC / QG_REPLAY | The session was ended to be safe | A request arrived out of order or altered. Unlock again; if this repeats, tell an operator. |
| QG_DENY_REVOKED | Access removed from this device | It was reported lost or revoked. If that is a mistake, contact your operator. |
| QG_DENY_POLICY (self_approval) | A second person has to approve this | You requested it or it is about you. Ask another admin to approve. |
| QG_DENY_POLICY (self_lift) | Someone else has to lift this | The response contains you or this device. Another operator, or an admin, can lift it. |
| QG_DENY_POLICY (role_required) | Not available for your role | This action needs a role you do not hold. |
| QG_DENY_POLICY (no_slot, other) | You do not have access to this | The policy did not allow it. The decision is recorded; ask the file owner or an admin if you need access. |
| QG_QUARANTINED | Access is paused for now | An automatic safety response is active. An operator can lift it; the time it ends is shown when known. |
| QG_QUARANTINED (enrolment_held) | Enrolment is on hold | A device of yours was reported lost, so new devices wait for an operator. |
| QG_STALE_EPOCH | The device list changed while you worked | We fetched the new list. Try again. |
| QG_LEASE_EXPIRED | The download paused for a new permission | Permission to read lasts 60 seconds. Open the file again to continue. |
| QG_NOT_FOUND | Not found | It does not exist or you may not see it. |
| QG_CONFLICT (rekey_pending) | Files are still waiting for new keys | Close the incident after every affected file has a new key. |
| QG_CONFLICT (other) | That was already done | The page shows the current state. |
| QG_RATE_LIMITED | Too many requests | Wait a moment and try again. |
| QG_UNAVAILABLE_FAIL_CLOSED | The service stopped to stay safe | A part it depends on is unavailable, so nothing was released. Try again shortly. |
| QG_OFFLINE | No connection | Check the network and try again. Nothing was sent. |
| QG_LOCAL_PASSPHRASE | That passphrase did not unlock this device | Try again. Passphrases are case sensitive. |
| QG_LOCAL_INTEGRITY | This file failed its integrity check | What arrived is not what was protected, so it was not opened. Tell an operator. |

## Conventions
- Test ids: `data-testid="<screen>-<element>"`. Tour anchors: `data-tour="<name>"`, never a class.
- Times show as relative with the exact UTC time in a tooltip and in every receipt.
- Ids and hashes show shortened (`rcp_4f2a…9c1d`) with a copy button; full value in the receipt.
- Destructive confirmations name the object and the consequence; the confirm button repeats the verb ("Revoke access now").
- Toasts confirm; they are never the only place an error or a result appears.
