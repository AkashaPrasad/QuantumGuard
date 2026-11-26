/** `rcp_4f2a…9c1d`: enough to recognise, short enough for a table. */
export function shortId(id: string | null | undefined, keep = 4): string {
  if (!id) return '—'
  const cut = id.indexOf('_')
  const prefix = cut > 0 && cut <= 4 ? id.slice(0, cut + 1) : ''
  const body = id.slice(prefix.length)
  if (body.length <= keep * 2 + 1) return id
  return `${prefix}${body.slice(0, keep)}…${body.slice(-keep)}`
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v >= 10 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`
}

const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' })

export function relativeTime(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return '—'
  const diff = (new Date(iso).getTime() - now) / 1000
  const abs = Math.abs(diff)
  if (abs < 45) return diff <= 0 ? 'just now' : 'in a moment'
  if (abs < 3600) return rtf.format(Math.round(diff / 60), 'minute')
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), 'hour')
  if (abs < 86400 * 30) return rtf.format(Math.round(diff / 86400), 'day')
  return new Date(iso).toISOString().slice(0, 10)
}

/** `2026-11-26 12:00:00 UTC`, the form used in receipts. */
export function exactTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return `${d.toISOString().slice(0, 19).replace('T', ' ')} UTC`
}

/** Value for an `<input type="datetime-local">` in the viewer's own time zone. */
export function toLocalInput(d: Date): string {
  const pad = (x: number) => String(x).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

export function countdown(msLeft: number): string {
  const s = Math.max(0, Math.floor(msLeft / 1000))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`
}

export function initials(name: string): string {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((p) => p[0]!.toUpperCase())
    .join('')
}

const ACTION_WORDS: Record<string, string> = {
  enroll: 'Enrolled a device',
  'session.start': 'Unlocked a device',
  'session.end': 'Locked a device',
  'file.create': 'Started protecting a file',
  'file.commit': 'Protected a file',
  'slot.release': 'Key released to open a file',
  'chunk.read': 'Read file contents',
  'file.share': 'Shared a file',
  'file.unshare': 'Stopped sharing a file',
  'file.delete': 'Deleted a file',
  'rekey.commit': 'Gave a file a new key',
  'device.report_lost': 'Reported a device lost',
  'device.revoke': 'Revoked a device',
  'device.rename': 'Renamed a device',
  'invite.create': 'Created an enrolment code',
  'change.request': 'Requested a change',
  'change.approve': 'Approved a change',
  'change.reject': 'Rejected a change',
  'alert.ack': 'Acknowledged an alert',
  'response.lift': 'Lifted an automatic response',
  'service.create': 'Added a service',
  'service.rotate': 'Rotated a service key',
  'signal.receive': 'Received an identity signal',
  'message.send': 'Sent a message',
  'recovery.release': 'Released a recovery slot',
  'incident.close': 'Closed an incident',
  'bundle.export': 'Exported a proof bundle',
  access: 'Made a request',
}

export function actionWords(action: string): string {
  return ACTION_WORDS[action] ?? action
}
