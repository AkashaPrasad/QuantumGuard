// Deterministic synthetic data for the invented organisation "Kestrel Biolabs".
// Everything here is made up. Hashes and keys are random-looking strings from a seeded
// generator so the output is stable between reloads; timestamps are relative to `now`.
import type * as T from '../types'

export const ORG_NAME = 'Kestrel Biolabs'
export const PASSPHRASE = 'correct horse battery'
export const POLICY_HASH_SEED = 'kestrel-policy-v7'

export type PersonaKey = 'aiko' | 'mira' | 'priya' | 'jonas'
export type PersonKey = PersonaKey | 'tomas' | 'daniel'

// ---------- small helpers (also used by client.ts) ----------

export type Rng = () => number

export function makeRng(label: string): Rng {
  let h = 2166136261
  for (let i = 0; i < label.length; i++) {
    h ^= label.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  let a = h >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

/** Random-looking base64url text for `bytes` bytes, no padding. */
export function randB64u(rng: Rng, bytes: number): string {
  const n = Math.ceil((bytes * 4) / 3)
  let s = ''
  for (let i = 0; i < n; i++) s += B64U[Math.floor(rng() * 64)]
  return s
}

/** Prefix plus 22 base64url characters, as the API describes ids. */
export function idOf(prefix: string, rng: Rng): string {
  return `${prefix}_${randB64u(rng, 16)}`
}

export function iso(ms: number): string {
  return new Date(ms).toISOString()
}

export const MIN = 60_000
export const HOUR = 3_600_000
export const DAY = 86_400_000

const sigCache = new Map<string, T.Signatures>()
/** Dual signature of the right rough size (Ed25519 64 bytes, ML-DSA-65 3309 bytes). */
export function sigsFor(label: string): T.Signatures {
  let s = sigCache.get(label)
  if (!s) {
    s = {
      ed25519: randB64u(makeRng(`${label}:ed`), 64),
      mldsa: randB64u(makeRng(`${label}:ml`), 3309),
    }
    sigCache.set(label, s)
  }
  return s
}

export function hashFor(label: string): string {
  return randB64u(makeRng(`hash:${label}`), 32)
}

// ---------- people ----------

export interface Person {
  key: PersonKey
  user_id: string
  name: string
  roles: T.Role[]
  code: string
}

export const PEOPLE: Person[] = [
  { key: 'mira', user_id: 'usr_K3mR9aQ0vXb2LwT7nY5pHg', name: 'Mira Okafor', roles: ['admin'], code: 'KESTREL-MIRA' },
  { key: 'tomas', user_id: 'usr_T7oM4sL1nDqV8cZ2jE6uBw', name: 'Tomas Lindqvist', roles: ['admin'], code: 'KESTREL-TOMAS' },
  { key: 'priya', user_id: 'usr_P2rYaR8mN5xK0tF3hCwQzA', name: 'Priya Raman', roles: ['operator'], code: 'KESTREL-PRIYA' },
  { key: 'jonas', user_id: 'usr_J9wB3rE7oN1sH4kUdXyL5g', name: 'Jonas Weber', roles: ['auditor'], code: 'KESTREL-JONAS' },
  { key: 'aiko', user_id: 'usr_AiKo5tNk2vY8bQ1xZ4mR7c', name: 'Aiko Tanaka', roles: ['employee'], code: 'KESTREL-AIKO' },
  { key: 'daniel', user_id: 'usr_DnL3mEnS8hA0yG6wUq4TpV', name: 'Daniel Mensah', roles: ['employee'], code: 'KESTREL-DANIEL' },
]

export interface SeedDevice {
  key: string
  device_id: string
  user_id: string
  name: string
  status: T.Device['status']
  created_at: string
  last_seen_at: string | null
  kem_pk: string
  sig_pk: string
}

interface DeviceDef {
  key: string
  person: PersonKey
  name: string
  ageDays: number
  status: T.Device['status']
  seenMinAgo: number | null
}

const DEVICE_DEFS: DeviceDef[] = [
  { key: 'mira1', person: 'mira', name: "Mira's ThinkPad X1", ageDays: 140, status: 'active', seenMinAgo: 12 },
  { key: 'mira2', person: 'mira', name: "Mira's iPad", ageDays: 96, status: 'active', seenMinAgo: 340 },
  { key: 'tomas1', person: 'tomas', name: "Tomas's MacBook Pro", ageDays: 133, status: 'active', seenMinAgo: 47 },
  { key: 'priya1', person: 'priya', name: "Priya's Ops Laptop", ageDays: 118, status: 'active', seenMinAgo: 5 },
  { key: 'priya2', person: 'priya', name: "Priya's Phone", ageDays: 60, status: 'active', seenMinAgo: 95 },
  { key: 'jonas1', person: 'jonas', name: "Jonas's Audit Laptop", ageDays: 87, status: 'active', seenMinAgo: 210 },
  { key: 'aiko1', person: 'aiko', name: "Aiko's MacBook Air", ageDays: 72, status: 'active', seenMinAgo: 3 },
  { key: 'aiko2', person: 'aiko', name: 'Lab bench tablet', ageDays: 41, status: 'active', seenMinAgo: 180 },
  { key: 'daniel1', person: 'daniel', name: "Daniel's Dell XPS", ageDays: 65, status: 'quarantined', seenMinAgo: 48 },
  { key: 'daniel0', person: 'daniel', name: "Daniel's Pixel 8", ageDays: 90, status: 'revoked', seenMinAgo: null },
]

interface FileDef {
  key: string
  name: string
  cls: T.Classification
  owner: PersonKey
  readers: PersonKey[]
  bytes: number
  ageDays: number
  version?: number
  skipDevices?: string[]
}

const FILE_DEFS: FileDef[] = [
  { key: 'assay', name: 'Assay-results-batch-41.xlsx', cls: 'confidential', owner: 'aiko', readers: ['mira', 'priya'], bytes: 2_516_582, ageDays: 6, skipDevices: ['aiko2'] },
  { key: 'helix', name: 'Supplier-contract-Helix.pdf', cls: 'restricted', owner: 'mira', readers: ['tomas'], bytes: 1_153_434, ageDays: 31 },
  { key: 'plasmid', name: 'Plasmid-library-inventory.csv', cls: 'internal', owner: 'aiko', readers: ['daniel', 'priya'], bytes: 412_160, ageDays: 52, version: 2 },
  { key: 'coldstore', name: 'Cold-storage-audit-Q3.docx', cls: 'internal', owner: 'daniel', readers: ['aiko', 'jonas'], bytes: 689_152, ageDays: 40, version: 2 },
  { key: 'compoundk', name: 'Compound-K-synthesis-protocol.pdf', cls: 'restricted', owner: 'aiko', readers: ['mira', 'tomas'], bytes: 3_250_585, ageDays: 18 },
  { key: 'payroll', name: 'Payroll-October.xlsx', cls: 'restricted', owner: 'tomas', readers: ['mira'], bytes: 287_744, ageDays: 27 },
  { key: 'ethics', name: 'Ethics-board-minutes-2026-09.docx', cls: 'confidential', owner: 'mira', readers: ['tomas', 'jonas'], bytes: 198_656, ageDays: 55 },
  { key: 'freezer', name: 'Freezer-fault-log.txt', cls: 'internal', owner: 'priya', readers: ['aiko', 'daniel'], bytes: 64_512, ageDays: 14 },
  { key: 'grant', name: 'Grant-application-draft-v3.docx', cls: 'confidential', owner: 'tomas', readers: ['mira', 'aiko'], bytes: 1_474_560, ageDays: 9 },
  { key: 'vendor', name: 'Vendor-pricing-sheet-2026.xlsx', cls: 'confidential', owner: 'daniel', readers: ['priya', 'mira'], bytes: 523_264, ageDays: 33, version: 2 },
]

export interface SeedFile extends T.FileItem {
  key: string
  versions: T.FileDetail['versions']
}

export interface RuleTemplate {
  id: string
  severity: T.Severity
  summary: string
  condition: string
  action: T.ResponseAction
  scope: T.AlertResponse['scope']['kind']
}

export const RULE_TEMPLATES: RuleTemplate[] = [
  { id: 'QG-R001', severity: 'critical', summary: 'A revoked device tried to open a file', condition: 'A request arrived from a device after its revocation was committed', action: 'deny', scope: 'device' },
  { id: 'QG-R005', severity: 'critical', summary: 'Repeated denials on restricted files followed by a new request', condition: 'Four or more policy denials on restricted files within ten minutes from one device', action: 'quarantine_device', scope: 'device' },
  { id: 'QG-R007', severity: 'high', summary: 'A person reached a restricted file through an unusual chain of sharing', condition: 'A file was reachable only through three or more hops of sharing', action: 'none', scope: 'identity' },
  { id: 'QG-R009', severity: 'medium', summary: 'Unusual volume of file reads', condition: 'Chunk reads from one account exceeded three times the 30 day daily norm', action: 'none', scope: 'identity' },
  { id: 'QG-R010', severity: 'high', summary: 'A retired service key was presented', condition: 'A request was signed with a key whose status is retired', action: 'deny', scope: 'credential' },
  { id: 'QG-R011', severity: 'medium', summary: 'Enrolment held while a loss report is open', condition: 'A person with an open loss report asked for a new device certificate', action: 'hold_enrolment', scope: 'identity' },
]

export interface SeedIncident {
  incident: T.Incident
  exposure: T.Exposure
  result: T.RevokeResult
  candidates: string[]
}

export interface SeedInvite extends T.Invite {
  code: string
}

export interface Seed {
  now: number
  epoch: number
  users: T.DirectoryUser[]
  devices: SeedDevice[]
  files: SeedFile[]
  receipts: T.Receipt[]
  alerts: T.Alert[]
  incident: SeedIncident
  changes: T.Change[]
  services: T.Service[]
  policy: T.Policy
  invites: SeedInvite[]
  signals: T.Signal[]
  messages: { to_user_id: string; message: T.Message }[]
  /** First device id of each person, used to start a persona. */
  firstDevice: Record<PersonKey, string>
}

export function buildSeed(now: number): Seed {
  const rng = makeRng('kestrel-biolabs-seed-1')
  const person = (k: PersonKey): Person => PEOPLE.find((p) => p.key === k) as Person

  const users: T.DirectoryUser[] = PEOPLE.map((p) => ({
    user_id: p.user_id,
    name: p.name,
    roles: [...p.roles],
    status: 'active',
  }))

  // Devices
  const devices: SeedDevice[] = DEVICE_DEFS.map((d) => {
    const r = makeRng(`device:${d.key}`)
    return {
      key: d.key,
      device_id: idOf('dev', r),
      user_id: person(d.person).user_id,
      name: d.name,
      status: d.status,
      created_at: iso(now - d.ageDays * DAY),
      last_seen_at: d.seenMinAgo === null ? null : iso(now - d.seenMinAgo * MIN),
      kem_pk: randB64u(r, 1216),
      sig_pk: randB64u(r, 1984),
    }
  })
  const dev = (key: string): SeedDevice => devices.find((d) => d.key === key) as SeedDevice
  const firstDevice = {} as Record<PersonKey, string>
  for (const p of PEOPLE) {
    firstDevice[p.key] = (devices.find((d) => d.user_id === p.user_id) as SeedDevice).device_id
  }
  firstDevice.aiko = dev('aiko1').device_id
  const userName = (id: string): string => users.find((u) => u.user_id === id)?.name ?? 'Unknown'

  // Files
  const files: SeedFile[] = FILE_DEFS.map((f) => {
    const r = makeRng(`file:${f.key}`)
    const ownerP = person(f.owner)
    const holders = [f.owner, ...f.readers].flatMap((k) =>
      devices.filter(
        (d) => d.user_id === person(k).user_id && d.status !== 'revoked' && !(f.skipDevices ?? []).includes(d.key),
      ),
    )
    const created = now - f.ageDays * DAY
    const version = f.version ?? 1
    const updated = version > 1 ? now - (f.ageDays > 3 ? 2 * DAY + 5 * HOUR : 1 * DAY) : created
    return {
      key: f.key,
      file_id: idOf('fil', r),
      name: f.name,
      classification: f.cls,
      size_bytes: f.bytes,
      version,
      chunk_count: Math.max(1, Math.ceil(f.bytes / 1_048_576)),
      owner: { user_id: ownerP.user_id, name: ownerP.name },
      created_at: iso(created),
      updated_at: iso(updated),
      recipients: holders.map((d) => ({
        device_id: d.device_id,
        user_id: d.user_id,
        user_name: userName(d.user_id),
        device_name: d.name,
      })),
      can_open: true,
      rekey: 'none',
      versions: [
        { version: 1, committed_at: iso(created), committed_by_device: dev(`${f.owner}1`).device_id, reason: 'update' },
        ...(version > 1
          ? [{ version, committed_at: iso(updated), committed_by_device: dev('priya1').device_id, reason: 'rekey' }]
          : []),
      ],
    }
  })
  const file = (k: string): SeedFile => files.find((f) => f.key === k) as SeedFile

  // ---------- receipts ----------
  const policyHash = hashFor(POLICY_HASH_SEED)
  const pending: T.Receipt[] = []
  const mk = (
    ts: number,
    d: SeedDevice,
    action: string,
    resource: string,
    decision: T.Decision,
    reason: string,
    rules: string[],
    epoch = 14,
  ): T.Receipt => {
    const r = makeRng(`rcp:${pending.length}`)
    const rc: T.Receipt = {
      suite: 'QG-1',
      id: idOf('rcp', r),
      ts: iso(ts),
      request_hash: randB64u(r, 32),
      subject: { user_id: d.user_id, device_id: d.device_id, session_id: idOf('ses', makeRng(`ses:${d.key}:${Math.floor(ts / (6 * HOUR))}`)) },
      action,
      resource,
      policy_bundle_hash: policyHash,
      matched_rules: rules,
      decision,
      reason_code: reason,
      key_epoch: 3,
      directory_epoch: epoch,
      leaf_index: 0,
    }
    pending.push(rc)
    return rc
  }

  const activeKeys = ['mira1', 'mira2', 'tomas1', 'priya1', 'priya2', 'jonas1', 'aiko1', 'aiko2', 'daniel1']
  const openable = (d: SeedDevice): SeedFile[] => files.filter((f) => f.recipients.some((x) => x.device_id === d.device_id))
  const denyAt = new Set([5, 14, 23, 31, 40, 46])
  for (let i = 0; i < 48; i++) {
    const ts = now - 24 * HOUR + Math.floor(((i + rng()) * 23.5 * HOUR) / 48)
    const d = dev(activeKeys[Math.floor(rng() * activeKeys.length)])
    const mine = openable(d)
    const f = mine[Math.floor(rng() * mine.length)]
    if (denyAt.has(i)) {
      const other = files.filter((x) => !mine.includes(x))
      const target = other[Math.floor(rng() * other.length)]
      mk(ts, d, 'slot.release', target.file_id, 'deny', 'no_slot', ['QG-P002'])
      continue
    }
    const roll = rng()
    if (roll < 0.28) mk(ts, d, 'session.start', d.device_id, 'allow', 'allowed', ['QG-P001'])
    else if (roll < 0.62) mk(ts, d, 'slot.release', f.file_id, 'allow', 'allowed', ['QG-P002'])
    else if (roll < 0.84) mk(ts, d, 'chunk.read', f.file_id, 'allow', 'allowed', ['QG-P002'])
    else if (roll < 0.92) mk(ts, d, 'file.commit', f.file_id, 'allow', 'allowed', ['QG-P001'])
    else mk(ts, d, 'file.share', f.file_id, 'allow', 'allowed', ['QG-P006'])
  }

  // QG-R009 evidence: a burst of chunk reads from Aiko's laptop
  const burstFile = file('compoundk')
  const burst = Array.from({ length: 8 }, (_, i) =>
    mk(now - 170 * MIN + i * 90_000, dev('aiko1'), 'chunk.read', burstFile.file_id, 'allow', 'allowed', ['QG-P002']),
  )
  // QG-R005 evidence: four denials on restricted files from Daniel's laptop
  const restrictedDenials = (['helix', 'compoundk', 'payroll', 'helix'] as const).map((k, i) =>
    mk(now - 56 * MIN + i * 85_000, dev('daniel1'), 'slot.release', file(k).file_id, 'deny', 'classification_restricted', ['QG-P003']),
  )

  // The incident from two days ago
  const t0 = now - 2 * DAY
  const phone = dev('daniel0')
  const compromise = t0 - 5 * HOUR
  const reportRcp = mk(t0, dev('daniel1'), 'device.report_lost', phone.device_id, 'allow', 'allowed', ['QG-P008'], 13)
  const relVendor = mk(compromise + 70 * MIN, phone, 'slot.release', file('vendor').file_id, 'allow', 'allowed', ['QG-P002'], 12)
  mk(compromise + 71 * MIN, phone, 'chunk.read', file('vendor').file_id, 'allow', 'allowed', ['QG-P002'], 12)
  const relCold = mk(compromise + 170 * MIN, phone, 'slot.release', file('coldstore').file_id, 'allow', 'allowed', ['QG-P002'], 12)
  const relPlasmid = mk(compromise - 25 * HOUR, phone, 'slot.release', file('plasmid').file_id, 'allow', 'allowed', ['QG-P002'], 12)
  const denied1 = mk(t0 + 25 * MIN, phone, 'slot.release', file('vendor').file_id, 'deny', 'device_revoked', ['QG-P007'], 13)
  const denied2 = mk(t0 + 3 * HOUR, phone, 'session.start', phone.device_id, 'deny', 'device_revoked', ['QG-P007'], 13)
  const rekeyRcps = (['vendor', 'coldstore', 'plasmid'] as const).map((k, i) =>
    mk(t0 + 3000 + i * 1400, dev('priya1'), 'rekey.commit', file(k).file_id, 'allow', 'allowed', ['QG-P004'], 13),
  )
  // A few older routine events so the log has some history before the incident
  for (let i = 0; i < 9; i++) {
    const d = dev(activeKeys[(i * 3) % activeKeys.length])
    mk(now - 2 * DAY - 9 * HOUR - i * 2 * HOUR, d, 'session.start', d.device_id, 'allow', 'allowed', ['QG-P001'], 12)
  }

  const receipts = [...pending].sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts))
  receipts.forEach((r, i) => (r.leaf_index = i))

  // ---------- incident ----------
  const incId = idOf('inc', makeRng('incident:1'))
  const phoneFiles = ['plasmid', 'coldstore', 'freezer', 'vendor'].map(file)
  const exFile = (f: SeedFile, rekey: T.ExposedFile['rekey'], rels: T.Receipt[]): T.ExposedFile => ({
    file_id: f.file_id,
    name: f.name,
    classification: f.classification,
    releases: rels.map((r) => ({ ts: r.ts, receipt_id: r.id })),
    rekey,
    new_version: rekey === 'done' ? f.version : null,
  })
  const exposure: T.Exposure = {
    incident_id: incId,
    compromise_time: iso(compromise),
    exposed: [exFile(file('vendor'), 'done', [relVendor]), exFile(file('coldstore'), 'done', [relCold])],
    held: [exFile(file('plasmid'), 'done', [relPlasmid])],
    never_released: [exFile(file('freezer'), 'not_needed', [])],
    suspect_decisions: receipts.filter((r) => r.subject.device_id === phone.device_id && Date.parse(r.ts) >= compromise),
  }
  const daniel = person('daniel')
  const timeEnforce = 34
  const enforcedAt = t0 + timeEnforce
  const incident: T.Incident = {
    id: incId,
    device_id: phone.device_id,
    device_name: phone.name,
    user_id: daniel.user_id,
    user_name: daniel.name,
    status: 'contained',
    reported_at: iso(t0),
    compromise_time: iso(compromise),
    counts: { exposed: 2, held: 1, never_released: 1, rekeyed: 3, pending: 0 },
    denied_attempts: 2,
    reported_by: { user_id: daniel.user_id, name: daniel.name },
    note: 'Left in a taxi after the conference dinner.',
    time_to_enforce_ms: timeEnforce,
    directory_epoch: 13,
    alert_ids: [],
    timeline: [
      { step: 'reported', ts: iso(t0), receipt_id: reportRcp.id, detail: "Daniel Mensah reported the Pixel 8 lost from his Dell XPS" },
      { step: 'revoked', ts: iso(enforcedAt), receipt_id: reportRcp.id, detail: `Device revoked in ${timeEnforce} ms, 1 session ended, 4 key slots deleted` },
      { step: 'scoped', ts: iso(t0 + 1100), receipt_id: null, detail: '2 files exposed, 1 held, 1 never released' },
      { step: 'rekey_started', ts: iso(t0 + 1600), receipt_id: null, detail: 'Re-keying 3 files' },
      ...(['vendor', 'coldstore', 'plasmid'] as const).map((k, i) => ({
        step: 'rekey_progress' as const,
        ts: iso(t0 + 3000 + i * 1400),
        receipt_id: rekeyRcps[i].id,
        detail: `Re-keyed ${file(k).name} (${i + 1} of 3)`,
      })),
      { step: 'rekey_done', ts: iso(t0 + 6200), receipt_id: null, detail: 'All exposed and held files have a new key' },
      { step: 'denied_attempt', ts: iso(t0 + 25 * MIN), receipt_id: denied1.id, detail: 'The revoked device asked to open a file and was refused' },
      { step: 'denied_attempt', ts: iso(t0 + 3 * HOUR), receipt_id: denied2.id, detail: 'The revoked device tried to start a session and was refused' },
    ],
  }

  // ---------- alerts ----------
  const ruleOf = (id: string): RuleTemplate => RULE_TEMPLATES.find((r) => r.id === id) as RuleTemplate
  const alerts: T.Alert[] = [
    {
      id: idOf('alr', makeRng('alert:r001')),
      ts: iso(t0 + 25 * MIN),
      rule_id: 'QG-R001',
      severity: ruleOf('QG-R001').severity,
      status: 'acknowledged',
      subject: { user_id: daniel.user_id, device_id: phone.device_id, session_id: null },
      summary: `Revoked device ${phone.name} tried to open Vendor-pricing-sheet-2026.xlsx`,
      explanation: { condition: ruleOf('QG-R001').condition, receipt_ids: [denied1.id, denied2.id] },
      response: {
        id: idOf('rsp', makeRng('resp:r001')),
        action: 'deny',
        scope: { kind: 'device', id: phone.device_id },
        expires_at: null,
        lifted_at: null,
        lifted_by: null,
      },
      incident_id: incId,
      acknowledged_by: 'Priya Raman',
    },
    {
      id: idOf('alr', makeRng('alert:r009')),
      ts: iso(now - 158 * MIN),
      rule_id: 'QG-R009',
      severity: 'medium',
      status: 'open',
      subject: { user_id: person('aiko').user_id, device_id: dev('aiko1').device_id, session_id: null },
      summary: "8 chunk reads of Compound-K-synthesis-protocol.pdf in 12 minutes from Aiko's MacBook Air",
      explanation: { condition: ruleOf('QG-R009').condition, receipt_ids: burst.map((r) => r.id) },
      response: null,
      incident_id: null,
      acknowledged_by: null,
    },
    {
      id: idOf('alr', makeRng('alert:r005')),
      ts: iso(now - 49 * MIN),
      rule_id: 'QG-R005',
      severity: 'critical',
      status: 'open',
      subject: { user_id: daniel.user_id, device_id: dev('daniel1').device_id, session_id: null },
      summary: "Four restricted-file requests denied in 6 minutes from Daniel's Dell XPS",
      explanation: { condition: ruleOf('QG-R005').condition, receipt_ids: restrictedDenials.map((r) => r.id) },
      response: {
        id: idOf('rsp', makeRng('resp:r005')),
        action: 'quarantine_device',
        scope: { kind: 'device', id: dev('daniel1').device_id },
        expires_at: null,
        lifted_at: null,
        lifted_by: null,
      },
      incident_id: null,
      acknowledged_by: null,
    },
  ]
  incident.alert_ids = [alerts[0].id]

  const result: T.RevokeResult = {
    incident_id: incId,
    device_id: phone.device_id,
    status: 'revoked',
    directory_epoch: 13,
    time_to_enforce_ms: timeEnforce,
    sessions_ended: 1,
    slots_deleted: phoneFiles.length,
    checkpoint: {
      suite: 'QG-1',
      tree_size: receipts.findIndex((r) => r.id === reportRcp.id) + 1,
      root_hash: hashFor('checkpoint:incident'),
      ts: iso(t0),
      signatures: sigsFor('checkpoint:incident'),
    },
    receipt_id: reportRcp.id,
  }

  // ---------- changes ----------
  const tomas = person('tomas')
  const priya = person('priya')
  const jonas = person('jonas')
  const aiko = person('aiko')
  const miraP = person('mira')
  const ref = (p: Person, key: string) => ({ user_id: p.user_id, name: p.name, device_id: dev(key).device_id })
  const changes: T.Change[] = [
    {
      id: idOf('chg', makeRng('change:1')),
      type: 'role_grant',
      target_user: { user_id: aiko.user_id, name: aiko.name },
      role: 'operator',
      file_id: null,
      reason: 'Aiko covers device operations while Priya is on leave next week',
      requested_by: ref(tomas, 'tomas1'),
      requested_at: iso(now - 5 * HOUR),
      status: 'pending',
      approvals: [{ ...ref(miraP, 'mira1'), at: iso(now - 4 * HOUR) }],
      approvals_required: 2,
    },
    {
      id: idOf('chg', makeRng('change:2')),
      type: 'role_grant',
      target_user: { user_id: jonas.user_id, name: jonas.name },
      role: 'auditor',
      file_id: null,
      reason: 'Jonas starts the quarterly evidence review',
      requested_by: ref(miraP, 'mira1'),
      requested_at: iso(now - 3 * DAY - 2 * HOUR),
      status: 'applied',
      approvals: [{ ...ref(tomas, 'tomas1'), at: iso(now - 3 * DAY) }],
      approvals_required: 1,
    },
  ]

  // ---------- services ----------
  const svcKey = (label: string, alg: string, status: T.ServiceKey['status'], ageDays: number, retiredDays: number | null): T.ServiceKey => ({
    key_id: idOf('key', makeRng(`svckey:${label}`)),
    alg,
    status,
    created_at: iso(now - ageDays * DAY),
    retired_at: retiredDays === null ? null : iso(now - retiredDays * DAY),
  })
  const services: T.Service[] = [
    {
      service_id: idOf('svc', makeRng('svc:lims')),
      name: 'Sample tracking service',
      status: 'active',
      keys: [
        svcKey('lims1', 'ed25519+ml-dsa-65', 'retired', 210, 95),
        svcKey('lims2', 'ed25519+ml-dsa-65', 'retiring', 100, null),
        svcKey('lims3', 'ed25519+ml-dsa-65', 'active', 14, null),
      ],
    },
    {
      service_id: idOf('svc', makeRng('svc:gateway')),
      name: 'Plate reader gateway',
      status: 'active',
      keys: [svcKey('gw1', 'ed25519+ml-dsa-65', 'retired', 160, 40), svcKey('gw2', 'ed25519+ml-dsa-65', 'active', 40, null)],
    },
  ]

  // ---------- policy ----------
  const all: T.Role[] = ['employee', 'admin', 'operator', 'auditor']
  const policy: T.Policy = {
    bundle_hash: policyHash,
    version: 7,
    signed_at: iso(now - 9 * DAY),
    signatures: sigsFor('policy'),
    rules: [
      { id: 'QG-P001', effect: 'allow', description: 'Anyone with a fresh session may start a session and create or update files.', roles: all, actions: ['session.start', 'file.create', 'file.commit'], conditions: { session: 'fresh' } },
      { id: 'QG-P002', effect: 'allow', description: 'A device may open a file only through its own key slot.', roles: all, actions: ['slot.release', 'chunk.read'], conditions: { holds_slot: true, device_status: 'active' } },
      { id: 'QG-P003', effect: 'deny', description: 'Restricted files are never released to anyone who is not the owner or a named recipient.', roles: all, actions: ['slot.release'], conditions: { classification: 'restricted', named_recipient: false } },
      { id: 'QG-P004', effect: 'allow', description: 'Operators may revoke devices, close incidents and handle alerts.', roles: ['operator'], actions: ['device.revoke', 'incident.close', 'alert.ack', 'response.lift', 'rekey.commit'], conditions: {} },
      { id: 'QG-P005', effect: 'deny', description: 'Auditors read evidence only; they cannot create, share or delete files.', roles: ['auditor'], actions: ['file.create', 'file.share', 'file.delete'], conditions: {} },
      { id: 'QG-P006', effect: 'allow', description: 'Owners may share a file with active people in the directory.', roles: all, actions: ['file.share', 'file.unshare'], conditions: { owner: true, recipient_status: 'active' } },
      { id: 'QG-P007', effect: 'deny', description: 'A revoked device is refused everything except public routes.', roles: all, actions: ['*'], conditions: { device_status: 'revoked' } },
      { id: 'QG-P008', effect: 'allow', description: 'A person may report one of their own devices lost, from another device.', roles: all, actions: ['device.report_lost'], conditions: { owner: true, from_other_device: true } },
    ],
  }

  // ---------- invites, signals, messages ----------
  const invites: SeedInvite[] = PEOPLE.map((p) => ({
    invite_id: idOf('inv', makeRng(`invite:${p.key}`)),
    user_id: p.user_id,
    user_name: p.name,
    created_by: 'Mira Okafor',
    expires_at: iso(now + 7 * DAY),
    status: 'pending',
    code: p.code,
  }))

  const signals: T.Signal[] = [
    { signal_id: idOf('sig', makeRng('signal:1')), jti: 'mdm-7f3a', iss: 'https://mdm.example', received_at: iso(now - 7 * HOUR), event_type: 'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change', subject_id: dev('daniel1').device_id, event_timestamp: Math.floor((now - 7 * HOUR) / 1000), applied: true },
    { signal_id: idOf('sig', makeRng('signal:2')), jti: 'mdm-7f3a', iss: 'https://mdm.example', received_at: iso(now - 7 * HOUR + 4_000), event_type: 'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change', subject_id: dev('daniel1').device_id, event_timestamp: Math.floor((now - 7 * HOUR) / 1000), applied: false },
    { signal_id: idOf('sig', makeRng('signal:3')), jti: 'idp-11c2', iss: 'https://idp.example', received_at: iso(now - 26 * HOUR), event_type: 'https://schemas.openid.net/secevent/caep/event-type/credential-change', subject_id: dev('daniel1').device_id, event_timestamp: Math.floor((now - 26 * HOUR) / 1000), applied: true },
  ]

  const messages = [
    {
      to_user_id: aiko.user_id,
      message: {
        message_id: idOf('msg', makeRng('msg:1')),
        from: { user_id: priya.user_id, name: priya.name, device_id: dev('priya1').device_id },
        sent_at: iso(now - 26 * HOUR),
        text: 'The freezer fault log is updated. Please read the entry for rack 4 before Friday.',
        verified: true,
      },
    },
  ]

  return {
    now,
    epoch: 14,
    users,
    devices,
    files,
    receipts,
    alerts,
    incident: {
      incident,
      exposure,
      result,
      candidates: phoneFiles.map((f) => f.file_id),
    },
    changes,
    services,
    policy,
    invites,
    signals,
    messages,
    firstDevice,
  }
}
