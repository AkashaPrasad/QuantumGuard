import { QgError } from '@/client/client'
import type { QgCode } from '@/client/types'

export interface ErrorCopy {
  title: string
  body: string
  code: string
  reason: string | null
  requestId: string | null
  receiptId: string | null
}

type Entry = { title: string; body: string }

// The catalogue from web/flows/README.md. Keys are `CODE` or `CODE/reason`.
const COPY: Record<string, Entry> = {
  'QG_INVALID_INPUT/invite_invalid': {
    title: 'That code did not work',
    body: 'It may be mistyped, already used, or older than 15 minutes. Ask your admin for a new one.',
  },
  QG_INVALID_INPUT: {
    title: 'Something in the form was not accepted',
    body: 'Check the highlighted fields and try again.',
  },
  QG_BAD_SUITE: {
    title: 'This client is out of date',
    body: 'The server speaks a different protocol version. Reload the page to get the current client.',
  },
  QG_BAD_SIGNATURE: {
    title: 'This device could not prove its keys',
    body: "The keys on this device do not match the server's record. Lock and unlock, and if it repeats ask an operator to re-enrol the device.",
  },
  QG_NO_SESSION: {
    title: 'This device is locked',
    body: 'Enter your passphrase to continue. Nothing you typed was lost.',
  },
  QG_BAD_MAC: {
    title: 'The session was ended to be safe',
    body: 'A request arrived altered. Unlock again; if this repeats, tell an operator.',
  },
  QG_REPLAY: {
    title: 'The session was ended to be safe',
    body: 'A request arrived out of order. Unlock again; if this repeats, tell an operator.',
  },
  QG_DENY_REVOKED: {
    title: 'Access removed from this device',
    body: 'It was reported lost or revoked. If that is a mistake, contact your operator.',
  },
  'QG_DENY_POLICY/self_approval': {
    title: 'A second person has to approve this',
    body: 'You requested it or it is about you. Ask another admin to approve.',
  },
  'QG_DENY_POLICY/role_required': {
    title: 'Not available for your role',
    body: 'This action needs a role you do not hold.',
  },
  'QG_DENY_POLICY/recipient_not_allowed': {
    title: 'One of those people cannot be given this file',
    body: 'Policy does not allow that recipient for this sensitivity. Remove them or lower the sensitivity.',
  },
  QG_DENY_POLICY: {
    title: 'You do not have access to this',
    body: 'The policy did not allow it. The decision is recorded; ask the file owner or an admin if you need access.',
  },
  'QG_QUARANTINED/enrolment_held': {
    title: 'Enrolment is on hold',
    body: 'A device of yours was reported lost, so new devices wait for an operator.',
  },
  QG_QUARANTINED: {
    title: 'Access is paused for now',
    body: 'An automatic safety response is active. An operator can lift it.',
  },
  QG_STALE_EPOCH: {
    title: 'The device list changed while you worked',
    body: 'We fetched the new list. Try again.',
  },
  QG_LEASE_EXPIRED: {
    title: 'The download paused for a new permission',
    body: 'Permission to read lasts 60 seconds. Open the file again to continue.',
  },
  QG_NOT_FOUND: { title: 'Not found', body: 'It does not exist or you may not see it.' },
  'QG_CONFLICT/rekey_pending': {
    title: 'Files are still waiting for new keys',
    body: 'Close the incident after every affected file has a new key.',
  },
  QG_CONFLICT: { title: 'That was already done', body: 'The page shows the current state.' },
  QG_RATE_LIMITED: { title: 'Too many requests', body: 'Wait a moment and try again.' },
  QG_UNAVAILABLE_FAIL_CLOSED: {
    title: 'The service refused, to be safe',
    body: 'A part it depends on is unavailable, so nothing was released. Try again shortly.',
  },
  QG_OFFLINE: { title: 'No connection', body: 'Check the network and try again. Nothing was sent.' },
  QG_LOCAL_PASSPHRASE: {
    title: 'That passphrase did not unlock this device',
    body: 'Try again. Passphrases are case sensitive.',
  },
  QG_LOCAL_INTEGRITY: {
    title: 'This failed its integrity check',
    body: 'What arrived is not what was protected, so it was not opened. Tell an operator.',
  },
  QG_LOCAL_CANCELLED: { title: 'Cancelled', body: 'Nothing was saved.' },
}

const FALLBACK: Entry = {
  title: 'Something went wrong',
  body: 'The action did not complete. Try again; if it repeats, give an operator the details below.',
}

export function describeError(err: unknown): ErrorCopy {
  if (err instanceof QgError) {
    const entry = (err.reason && COPY[`${err.code}/${err.reason}`]) || COPY[err.code] || FALLBACK
    return {
      ...entry,
      code: err.code,
      reason: err.reason,
      requestId: err.requestId,
      receiptId: err.receiptId,
    }
  }
  return { ...FALLBACK, code: 'CLIENT_ERROR', reason: null, requestId: null, receiptId: null }
}

export function isCode(err: unknown, ...codes: QgCode[]): err is QgError {
  return err instanceof QgError && codes.includes(err.code)
}
