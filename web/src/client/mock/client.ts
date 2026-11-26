// In-memory QgClient for development and UI state tests. No cryptography, no network:
// work is simulated with timers and progress events. Never bundled in production.
import { QgError } from '../client'
import type {
  DeviceState,
  EnrolStep,
  LocalDevice,
  OpenProgress,
  OpenedFile,
  ProtectProgress,
  QgClient,
  SessionInfo,
  VerifyResult,
  VerifyStep,
  WorkProgress,
} from '../client'
import type * as T from '../types'
import {
  DAY,
  HOUR,
  MIN,
  ORG_NAME,
  PASSPHRASE,
  PEOPLE,
  RULE_TEMPLATES,
  buildSeed,
  hashFor,
  idOf,
  iso,
  makeRng,
  randB64u,
  sigsFor,
} from './seed'
import type { PersonaKey, Seed, SeedDevice, SeedFile } from './seed'

export interface MockControl {
  setOffline(on: boolean): void
  expireSession(): void
  revokeCurrentDevice(): void
  failNext(code: T.QgCode, reason?: string): void
  raiseAlert(ruleId: string): void
  setLatency(ms: number): void
  reset(): void
}

export interface MockOptions {
  persona?: 'none' | PersonaKey
  latencyMs?: number
}

const STORAGE_KEY = 'qg-mock'
const CHUNK = 1_048_576
const BASE_LATENCY = 250

interface IncRec {
  inc: T.Incident
  exposure: T.Exposure
  result: T.RevokeResult
  candidates: string[]
  closed: boolean
}

interface InviteRec extends T.Invite {
  code: string
  created_by_user_id: string
}

interface Data {
  seed: Seed
  epoch: number
  users: T.DirectoryUser[]
  devices: SeedDevice[]
  files: SeedFile[]
  receipts: T.Receipt[]
  alerts: T.Alert[]
  alertPaths: Map<string, NonNullable<T.AlertDetail['path']>>
  incidents: IncRec[]
  changes: T.Change[]
  services: T.Service[]
  invites: InviteRec[]
  signals: T.Signal[]
  messages: { to_user_id: string; message: T.Message }[]
  rekeyMeta: Map<string, { reason: 'exposed' | 'held' | 'unshare'; incident_id: string | null }>
  usedCodes: Set<string>
  passphrases: Map<string, string>
  firstSeen: Set<string>
  keysetEpoch: number
}

interface Stored {
  persona: 'none' | PersonaKey
  enrolled: { user_id: string; device_id: string; device_name: string } | null
}

const MESSAGES: Partial<Record<T.QgCode, string>> = {
  QG_INVALID_INPUT: 'That input was not accepted.',
  QG_NO_SESSION: 'Unlock this device to continue.',
  QG_DENY_REVOKED: 'This device has been revoked.',
  QG_DENY_POLICY: 'Policy does not allow this.',
  QG_QUARANTINED: 'An automatic response is active for this device or person.',
  QG_NOT_FOUND: 'That item was not found.',
  QG_CONFLICT: 'The current state does not allow this.',
  QG_OFFLINE: 'The server cannot be reached.',
  QG_LOCAL_PASSPHRASE: 'That passphrase did not open the keystore.',
  QG_LOCAL_CANCELLED: 'Cancelled.',
  QG_LOCAL_INTEGRITY: 'A check failed on this device.',
}

function err(code: T.QgCode, reason?: string, receiptId?: string): QgError {
  return new QgError({
    code,
    reason: reason ?? null,
    message: MESSAGES[code] ?? 'The request failed.',
    receiptId: receiptId ?? null,
    requestId: `req_${randB64u(makeRng(`req:${Math.random()}`), 12)}`,
  })
}

function stable(x: unknown): string {
  if (Array.isArray(x)) return `[${x.map(stable).join(',')}]`
  if (x && typeof x === 'object') {
    const o = x as Record<string, unknown>
    return `{${Object.keys(o)
      .filter((k) => o[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${stable(o[k])}`)
      .join(',')}}`
  }
  return JSON.stringify(x) ?? 'null'
}

function digest(s: string): string {
  return randB64u(makeRng(`digest:${s}`), 32)
}

function hasTampered(x: unknown): boolean {
  if (Array.isArray(x)) return x.some(hasTampered)
  if (x && typeof x === 'object') {
    const o = x as Record<string, unknown>
    return o.tampered === true || Object.values(o).some(hasTampered)
  }
  return false
}

function isReceiptLike(x: unknown): x is T.Receipt {
  if (!x || typeof x !== 'object') return false
  const o = x as Record<string, unknown>
  return typeof o.id === 'string' && typeof o.leaf_index === 'number' && typeof o.ts === 'string'
}

function initData(): Data {
  const seed = buildSeed(Date.now())
  const inc = seed.incident
  return {
    seed,
    epoch: seed.epoch,
    users: structuredClone(seed.users),
    devices: structuredClone(seed.devices),
    files: structuredClone(seed.files),
    receipts: structuredClone(seed.receipts),
    alerts: structuredClone(seed.alerts),
    alertPaths: new Map(),
    incidents: [
      {
        inc: structuredClone(inc.incident),
        exposure: structuredClone(inc.exposure),
        result: structuredClone(inc.result),
        candidates: [...inc.candidates],
        closed: false,
      },
    ],
    changes: structuredClone(seed.changes),
    services: structuredClone(seed.services),
    invites: seed.invites.map((i) => ({ ...i, created_by_user_id: PEOPLE[0].user_id })),
    signals: structuredClone(seed.signals),
    messages: structuredClone(seed.messages),
    rekeyMeta: new Map(),
    usedCodes: new Set(),
    passphrases: new Map(seed.devices.map((d) => [d.device_id, PASSPHRASE])),
    firstSeen: new Set(),
    keysetEpoch: 6,
  }
}

function readStored(): Stored | null {
  try {
    if (typeof sessionStorage === 'undefined') return null
    const raw = sessionStorage.getItem(STORAGE_KEY)
    return raw ? (JSON.parse(raw) as Stored) : null
  } catch {
    return null
  }
}

function writeStored(s: Stored | null): void {
  try {
    if (typeof sessionStorage === 'undefined') return
    if (s) sessionStorage.setItem(STORAGE_KEY, JSON.stringify(s))
    else sessionStorage.removeItem(STORAGE_KEY)
  } catch {
    // storage may be blocked; the mock still works without it
  }
}

export function createMockClient(options: MockOptions = {}): QgClient & { control: MockControl } {
  let latency = options.latencyMs ?? BASE_LATENCY
  let offline = false
  let nextFailure: { code: T.QgCode; reason: string | null } | null = null
  let counter = 0
  let db = initData()
  let state: DeviceState = { kind: 'none' }
  let persona: 'none' | PersonaKey = 'none'
  let enrolled: Stored['enrolled'] = null
  const listeners = new Set<(s: DeviceState) => void>()

  const scale = (): number => latency / BASE_LATENCY
  const nid = (prefix: string): string => idOf(prefix, makeRng(`live:${prefix}:${++counter}:${db.seed.now}`))

  function sleep(ms: number, signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) return Promise.reject(err('QG_LOCAL_CANCELLED'))
    const wait = ms * scale()
    if (wait <= 0) return Promise.resolve()
    return new Promise((resolve, reject) => {
      const onAbort = (): void => {
        clearTimeout(timer)
        reject(err('QG_LOCAL_CANCELLED'))
      }
      const timer = setTimeout(() => {
        signal?.removeEventListener('abort', onAbort)
        resolve()
      }, wait)
      signal?.addEventListener('abort', onAbort, { once: true })
    })
  }

  // ---------- state ----------

  function setState(next: DeviceState): void {
    state = next
    for (const l of [...listeners]) l(state)
  }

  function localDevice(rec: SeedDevice): LocalDevice {
    const user = db.users.find((u) => u.user_id === rec.user_id)
    return {
      device_id: rec.device_id,
      device_name: rec.name,
      user_id: rec.user_id,
      user_name: user?.name ?? 'Unknown',
      roles: [...(user?.roles ?? [])],
      provider: 'noble',
      enrolled_at: rec.created_at,
    }
  }

  function persist(): void {
    if (state.kind === 'none') writeStored(persona === 'none' ? null : { persona, enrolled: null })
    else writeStored({ persona, enrolled })
  }

  function boot(): void {
    // An explicit persona option wins over anything left in sessionStorage.
    const stored = options.persona === undefined ? readStored() : null
    persona = options.persona ?? stored?.persona ?? 'none'
    enrolled = null
    if (persona !== 'none') {
      const first = db.seed.firstDevice[persona]
      const rec = db.devices.find((d) => d.device_id === first)
      state = rec ? { kind: 'locked', device: localDevice(rec) } : { kind: 'none' }
    } else if (stored?.enrolled && db.users.some((u) => u.user_id === stored.enrolled?.user_id)) {
      enrolled = stored.enrolled
      const rec = addDevice(enrolled.user_id, enrolled.device_name, enrolled.device_id)
      state = { kind: 'locked', device: localDevice(rec) }
    } else {
      state = { kind: 'none' }
    }
  }

  function addDevice(userId: string, name: string, deviceId?: string): SeedDevice {
    const id = deviceId ?? nid('dev')
    const r = makeRng(`newdev:${id}`)
    const rec: SeedDevice = {
      key: id,
      device_id: id,
      user_id: userId,
      name,
      status: 'active',
      created_at: iso(Date.now()),
      last_seen_at: iso(Date.now()),
      kem_pk: randB64u(r, 1216),
      sig_pk: randB64u(r, 1984),
    }
    db.devices.push(rec)
    db.passphrases.set(id, PASSPHRASE)
    return rec
  }

  // ---------- identity and gates ----------

  function me(): { user: T.DirectoryUser; device: SeedDevice; session: SessionInfo } {
    if (state.kind !== 'unlocked') throw err('QG_NO_SESSION')
    const { device: local, session } = state
    const device = db.devices.find((d) => d.device_id === local.device_id)
    const user = db.users.find((u) => u.user_id === local.user_id)
    if (!device || !user) throw err('QG_NO_SESSION')
    return { user, device, session }
  }

  function roles(): T.Role[] {
    return me().user.roles
  }

  function has(...wanted: T.Role[]): boolean {
    const mine = roles()
    return wanted.some((r) => mine.includes(r))
  }

  function need(...wanted: T.Role[]): void {
    if (!has(...wanted)) throw err('QG_DENY_POLICY', 'role_required')
  }

  async function gate(needsSession: boolean): Promise<void> {
    if (offline) throw err('QG_OFFLINE')
    if (nextFailure) {
      const f = nextFailure
      nextFailure = null
      throw err(f.code, f.reason ?? undefined)
    }
    await sleep(100)
    if (!needsSession) return
    if (state.kind === 'revoked') throw err('QG_DENY_REVOKED')
    if (state.kind === 'unlocked' && Date.parse(state.session.expires_at) < Date.now()) {
      setState({ kind: 'locked', device: state.device })
    }
    if (state.kind !== 'unlocked') throw err('QG_NO_SESSION')
  }

  // ---------- receipts, checkpoint, directory ----------

  function addReceipt(
    action: string,
    resource: string,
    decision: T.Decision = 'allow',
    reason = 'allowed',
    rules: string[] = ['QG-P001'],
    subject?: { user_id: string | null; device_id: string | null },
  ): T.Receipt {
    const r = makeRng(`live-rcp:${db.receipts.length}:${counter++}`)
    const who =
      subject ??
      (state.kind === 'unlocked' || state.kind === 'locked'
        ? { user_id: state.device.user_id, device_id: state.device.device_id }
        : { user_id: null, device_id: null })
    const rc: T.Receipt = {
      suite: 'QG-1',
      id: idOf('rcp', r),
      ts: iso(Date.now()),
      request_hash: randB64u(r, 32),
      subject: { ...who, session_id: state.kind === 'unlocked' ? state.session.session_id : null },
      action,
      resource,
      policy_bundle_hash: db.seed.policy.bundle_hash,
      matched_rules: rules,
      decision,
      reason_code: reason,
      key_epoch: 3,
      directory_epoch: db.epoch,
      leaf_index: db.receipts.length,
    }
    db.receipts.push(rc)
    return rc
  }

  function currentCheckpoint(): T.Checkpoint {
    const size = db.receipts.length
    return {
      suite: 'QG-1',
      tree_size: size,
      root_hash: hashFor(`root:${size}`),
      ts: iso(Date.now()),
      signatures: sigsFor(`cp:${size}`),
    }
  }

  function currentDirectory(): T.Directory {
    const live = db.devices.filter((d) => d.status !== 'revoked')
    return {
      suite: 'QG-1',
      epoch: db.epoch,
      prev_hash: hashFor(`dir:${db.epoch - 1}`),
      issued_at: iso(Date.now()),
      users: structuredClone(db.users),
      devices: live.map((d) => ({
        suite: 'QG-1',
        device_id: d.device_id,
        user_id: d.user_id,
        name: d.name,
        kem_pk: d.kem_pk,
        sig_pk: d.sig_pk,
        created_at: d.created_at,
        expires_at: iso(Date.parse(d.created_at) + 365 * DAY),
        directory_epoch: db.epoch,
      })),
      revoked: db.devices
        .filter((d) => d.status === 'revoked')
        .map((d) => ({ device_id: d.device_id, revoked_at: iso(Date.now()), epoch: db.epoch })),
      recovery_pk: hashFor('recovery-pk'),
      signatures: sigsFor(`dir:${db.epoch}`),
    }
  }

  // ---------- files ----------

  function visible(f: SeedFile): boolean {
    const { user } = me()
    return f.owner.user_id === user.user_id || f.recipients.some((r) => r.user_id === user.user_id)
  }

  function toItem(f: SeedFile): T.FileItem {
    const { device } = me()
    return {
      file_id: f.file_id,
      name: f.name,
      classification: f.classification,
      size_bytes: f.size_bytes,
      version: f.version,
      chunk_count: f.chunk_count,
      owner: { ...f.owner },
      created_at: f.created_at,
      updated_at: f.updated_at,
      recipients: f.recipients.map((r) => ({ ...r })),
      can_open: f.recipients.some((r) => r.device_id === device.device_id),
      rekey: f.rekey,
    }
  }

  function getVisibleFile(id: string): SeedFile {
    const f = db.files.find((x) => x.file_id === id)
    if (!f || !visible(f)) throw err('QG_NOT_FOUND')
    return f
  }

  function ownedFile(id: string): SeedFile {
    const f = getVisibleFile(id)
    if (f.owner.user_id !== me().user.user_id) throw err('QG_DENY_POLICY', 'not_owner')
    return f
  }

  function addRecipientDevices(f: SeedFile, devices: SeedDevice[]): void {
    for (const d of devices) {
      if (f.recipients.some((r) => r.device_id === d.device_id)) continue
      f.recipients.push({
        device_id: d.device_id,
        user_id: d.user_id,
        user_name: db.users.find((u) => u.user_id === d.user_id)?.name ?? 'Unknown',
        device_name: d.name,
      })
    }
  }

  const activeDevicesOf = (userId: string): SeedDevice[] =>
    db.devices.filter((d) => d.user_id === userId && d.status === 'active')

  const chunkDelay = (chunks: number): number => Math.min(80, 1200 / Math.max(1, chunks))

  // ---------- incidents ----------

  function viewIncident(rec: IncRec): T.Incident {
    const now = Date.now()
    const timeline = rec.inc.timeline
      .filter((s) => Date.parse(s.ts) <= now)
      .map((s) => ({ ...s }))
      .sort((a, b) => Date.parse(a.ts) - Date.parse(b.ts))
    const needing = [...rec.exposure.exposed, ...rec.exposure.held]
    const pending = needing.filter((f) => f.rekey === 'pending').length
    const rekeyed = needing.filter((f) => f.rekey === 'done').length
    const seen = (step: T.TimelineStep): boolean => timeline.some((s) => s.step === step)
    let status: T.IncidentStatus = 'open'
    if (rec.closed) status = 'closed'
    else if (pending === 0 && seen('rekey_done')) status = 'contained'
    else if (seen('rekey_started')) status = 'rekeying'
    return {
      ...rec.inc,
      status,
      timeline,
      counts: {
        exposed: rec.exposure.exposed.length,
        held: rec.exposure.held.length,
        never_released: rec.exposure.never_released.length,
        rekeyed,
        pending,
      },
      denied_attempts: timeline.filter((s) => s.step === 'denied_attempt').length,
    }
  }

  function summary(i: T.Incident): T.IncidentSummary {
    return {
      id: i.id,
      device_id: i.device_id,
      device_name: i.device_name,
      user_id: i.user_id,
      user_name: i.user_name,
      status: i.status,
      reported_at: i.reported_at,
      compromise_time: i.compromise_time,
      counts: { ...i.counts },
      denied_attempts: i.denied_attempts,
    }
  }

  function visibleIncident(rec: IncRec): boolean {
    return has('operator', 'auditor') || rec.inc.user_id === me().user.user_id || rec.inc.reported_by.user_id === me().user.user_id
  }

  function getIncidentRec(id: string): IncRec {
    const rec = db.incidents.find((i) => i.inc.id === id)
    if (!rec || !visibleIncident(rec)) throw err('QG_NOT_FOUND')
    return rec
  }

  function classify(candidates: string[], deviceId: string, compromiseMs: number): Pick<T.Exposure, 'exposed' | 'held' | 'never_released'> {
    const out: Pick<T.Exposure, 'exposed' | 'held' | 'never_released'> = { exposed: [], held: [], never_released: [] }
    for (const id of candidates) {
      const f = db.files.find((x) => x.file_id === id)
      if (!f) continue
      const rels = db.receipts.filter(
        (r) => r.subject.device_id === deviceId && r.action === 'slot.release' && r.decision === 'allow' && r.resource === id,
      )
      const entry: T.ExposedFile = {
        file_id: id,
        name: f.name,
        classification: f.classification,
        releases: rels.map((r) => ({ ts: r.ts, receipt_id: r.id })),
        rekey: 'pending',
        new_version: null,
      }
      if (rels.some((r) => Date.parse(r.ts) >= compromiseMs)) out.exposed.push(entry)
      else if (rels.length > 0) out.held.push(entry)
      else out.never_released.push({ ...entry, rekey: 'not_needed' })
    }
    return out
  }

  function queueRekeys(rec: IncRec): void {
    const mark = (list: T.ExposedFile[], reason: 'exposed' | 'held'): void => {
      for (const e of list) {
        if (e.rekey !== 'pending') continue
        const f = db.files.find((x) => x.file_id === e.file_id)
        if (!f) continue
        f.rekey = 'pending'
        if (!db.rekeyMeta.has(f.file_id)) db.rekeyMeta.set(f.file_id, { reason, incident_id: rec.inc.id })
      }
    }
    mark(rec.exposure.exposed, 'exposed')
    mark(rec.exposure.held, 'held')
  }

  function parseTime(value: string, field: string): number {
    const t = Date.parse(value)
    if (Number.isNaN(t)) throw err('QG_INVALID_INPUT', `${field}_invalid`)
    if (t > Date.now() + MIN) throw err('QG_INVALID_INPUT', `${field}_in_future`)
    return t
  }

  function revokeCore(
    deviceId: string,
    compromiseMs: number,
    kind: 'report' | 'revoke',
    note: string | null,
  ): T.RevokeResult {
    const { user } = me()
    const target = db.devices.find((d) => d.device_id === deviceId)
    if (!target) throw err('QG_NOT_FOUND')
    const action = kind === 'report' ? 'device.report_lost' : 'device.revoke'
    const existing = db.incidents.find((i) => i.inc.device_id === deviceId)

    if (existing && target.status === 'revoked') {
      const rcp = addReceipt(action, deviceId)
      if (kind === 'report') return { ...existing.result, receipt_id: rcp.id }
      // Operator correction: re-scope the incident; access is never restored.
      existing.inc.compromise_time = iso(compromiseMs)
      existing.exposure.compromise_time = iso(compromiseMs)
      const fresh = classify(existing.candidates, deviceId, compromiseMs)
      const keep = new Map([...existing.exposure.exposed, ...existing.exposure.held].map((e) => [e.file_id, e]))
      for (const list of [fresh.exposed, fresh.held]) {
        for (const e of list) {
          const prev = keep.get(e.file_id)
          if (prev?.rekey === 'done') {
            e.rekey = 'done'
            e.new_version = prev.new_version
          }
        }
      }
      existing.exposure.exposed = fresh.exposed
      existing.exposure.held = fresh.held
      existing.exposure.never_released = fresh.never_released
      existing.exposure.suspect_decisions = db.receipts.filter(
        (r) => r.subject.device_id === deviceId && Date.parse(r.ts) >= compromiseMs,
      )
      existing.inc.timeline.push({ step: 'rescoped', ts: iso(Date.now()), receipt_id: rcp.id, detail: `Compromise time corrected by ${user.name}` })
      queueRekeys(existing)
      return { ...existing.result, receipt_id: rcp.id }
    }

    const candidates = db.files.filter((f) => f.recipients.some((r) => r.device_id === deviceId)).map((f) => f.file_id)
    let slots = 0
    for (const f of db.files) {
      const before = f.recipients.length
      f.recipients = f.recipients.filter((r) => r.device_id !== deviceId)
      slots += before - f.recipients.length
    }
    target.status = 'revoked'
    db.epoch += 1
    const enforce = 20 + Math.floor(makeRng(`tte:${counter++}`)() * 41)
    const rcp = addReceipt(action, deviceId, 'allow', 'allowed', [kind === 'report' ? 'QG-P008' : 'QG-P004'])
    const found = classify(candidates, deviceId, compromiseMs)
    const incId = nid('inc')
    const owner = db.users.find((u) => u.user_id === target.user_id)
    const now = Date.now()
    const span = 6000 * scale()
    const needing = [...found.exposed, ...found.held]
    const at = (frac: number): string => iso(now + Math.round(span * frac))
    const timeline: T.Incident['timeline'] = [
      { step: 'reported', ts: iso(now), receipt_id: rcp.id, detail: kind === 'report' ? `${user.name} reported ${target.name} lost` : `${user.name} revoked ${target.name}` },
      { step: 'revoked', ts: iso(now + enforce), receipt_id: rcp.id, detail: `Device revoked in ${enforce} ms, ${slots} key slots deleted` },
      { step: 'scoped', ts: at(0.15), receipt_id: null, detail: `${found.exposed.length} files exposed, ${found.held.length} held, ${found.never_released.length} never released` },
      { step: 'rekey_started', ts: at(0.3), receipt_id: null, detail: `Re-keying ${needing.length} files` },
      ...needing.map((e, i) => ({
        step: 'rekey_progress' as const,
        ts: at(0.4 + (0.5 * (i + 1)) / needing.length),
        receipt_id: null,
        detail: `Re-key queued for ${e.name}`,
      })),
      ...(needing.length === 0
        ? [{ step: 'rekey_done' as const, ts: at(0.95), receipt_id: null, detail: 'Nothing needed a new key' }]
        : []),
    ]
    const rec: IncRec = {
      inc: {
        id: incId,
        device_id: deviceId,
        device_name: target.name,
        user_id: target.user_id,
        user_name: owner?.name ?? 'Unknown',
        status: 'open',
        reported_at: iso(now),
        compromise_time: iso(compromiseMs),
        counts: { exposed: 0, held: 0, never_released: 0, rekeyed: 0, pending: 0 },
        denied_attempts: 0,
        reported_by: { user_id: user.user_id, name: user.name },
        note,
        time_to_enforce_ms: enforce,
        directory_epoch: db.epoch,
        timeline,
        alert_ids: [],
      },
      exposure: {
        incident_id: incId,
        compromise_time: iso(compromiseMs),
        ...found,
        suspect_decisions: db.receipts.filter((r) => r.subject.device_id === deviceId && Date.parse(r.ts) >= compromiseMs).slice(-20),
      },
      result: {
        incident_id: incId,
        device_id: deviceId,
        status: 'revoked',
        directory_epoch: db.epoch,
        time_to_enforce_ms: enforce,
        sessions_ended: target.last_seen_at && now - Date.parse(target.last_seen_at) < 30 * MIN ? 1 : 0,
        slots_deleted: slots,
        checkpoint: currentCheckpoint(),
        receipt_id: rcp.id,
      },
      candidates,
      closed: false,
    }
    db.incidents.push(rec)
    queueRekeys(rec)
    return rec.result
  }

  function finishContainedIncidents(): void {
    const now = iso(Date.now())
    for (const rec of db.incidents) {
      const needing = [...rec.exposure.exposed, ...rec.exposure.held]
      const hasDone = rec.inc.timeline.some((s) => s.step === 'rekey_done')
      if (rec.closed || hasDone || needing.some((e) => e.rekey === 'pending')) continue
      for (const s of rec.inc.timeline) if (s.ts > now) s.ts = now
      rec.inc.timeline.push({ step: 'rekey_done', ts: now, receipt_id: null, detail: 'All exposed and held files have a new key' })
    }
  }

  // ---------- verification ----------

  async function emitVerify(rcp: T.Receipt, ok: boolean, onStep?: (s: VerifyStep) => void): Promise<void> {
    const r = makeRng(`verify:${rcp.id}`)
    const step = async (s: VerifyStep): Promise<void> => {
      onStep?.(s)
      await sleep(180)
    }
    await step({ kind: 'receipt', receipt: rcp, leaf_hash: randB64u(r, 32) })
    const levels = 5 + (rcp.leaf_index % 3)
    for (let level = 0; level < levels; level++) {
      await step({
        kind: 'node',
        level,
        hash: randB64u(r, 32),
        sibling: randB64u(r, 32),
        side: ((rcp.leaf_index >> level) & 1) === 0 ? 'right' : 'left',
      })
    }
    const signed = randB64u(r, 32)
    await step({ kind: 'root', computed: ok ? signed : randB64u(r, 32), signed, ok })
    if (!ok) return
    await step({ kind: 'signature', alg: 'ed25519', ok: true })
    await step({ kind: 'signature', alg: 'mldsa', ok: true })
  }

  // ---------- the client ----------

  const control: MockControl = {
    setOffline(on) {
      offline = on
    },
    expireSession() {
      if (state.kind === 'unlocked') setState({ kind: 'locked', device: state.device })
    },
    revokeCurrentDevice() {
      if (state.kind === 'none' || state.kind === 'revoked') return
      const local = state.device
      const rec = db.devices.find((d) => d.device_id === local.device_id)
      if (rec) {
        rec.status = 'revoked'
        db.epoch += 1
      }
      setState({ kind: 'revoked', device: local })
    },
    failNext(code, reason) {
      nextFailure = { code, reason: reason ?? null }
    },
    raiseAlert(ruleId) {
      const tpl = RULE_TEMPLATES.find((r) => r.id === ruleId) ?? {
        id: ruleId,
        severity: 'medium' as const,
        summary: `Rule ${ruleId} matched`,
        condition: 'A custom rule matched recent activity',
        action: 'none' as const,
        scope: 'identity' as const,
      }
      const current = state.kind === 'none' ? null : state.device.device_id
      const subjectDev = db.devices.find((d) => d.status === 'active' && d.device_id !== current) ?? db.devices[0]
      const recent = db.receipts.filter((r) => r.subject.device_id === subjectDev.device_id).slice(-3)
      const id = nid('alr')
      const response: T.AlertResponse | null =
        tpl.action === 'none'
          ? null
          : {
              id: nid('rsp'),
              action: tpl.action,
              scope: { kind: tpl.scope, id: tpl.scope === 'identity' ? subjectDev.user_id : subjectDev.device_id },
              expires_at: null,
              lifted_at: null,
              lifted_by: null,
            }
      if (tpl.action === 'quarantine_device') subjectDev.status = 'quarantined'
      db.alerts.push({
        id,
        ts: iso(Date.now()),
        rule_id: tpl.id,
        severity: tpl.severity,
        status: 'open',
        subject: { user_id: subjectDev.user_id, device_id: subjectDev.device_id, session_id: null },
        summary: tpl.summary,
        explanation: { condition: tpl.condition, receipt_ids: recent.map((r) => r.id) },
        response,
        incident_id: null,
        acknowledged_by: null,
      })
      if (tpl.id === 'QG-R007') {
        db.alertPaths.set(id, [
          { from: subjectDev.user_id, to: db.files[4].file_id, relation: 'shared_by' },
          { from: db.files[4].file_id, to: db.files[1].file_id, relation: 'derived_from' },
        ])
      }
    },
    setLatency(ms) {
      latency = Math.max(0, ms)
    },
    reset() {
      db = initData()
      offline = false
      nextFailure = null
      writeStored(null)
      boot()
      persist()
      for (const l of [...listeners]) l(state)
    },
  }

  boot()
  persist()

  const client: QgClient = {
    getState: () => state,
    subscribe(listener) {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    },

    // ----- public -----
    async meta() {
      await gate(false)
      return {
        suite: 'QG-1',
        version: '0.1.0-mock',
        commit: 'mock000',
        demo: true,
        server_keys: { ed25519_pk: randB64u(makeRng('srv:ed'), 32), mldsa_pk: randB64u(makeRng('srv:ml'), 1952), kem_pk: randB64u(makeRng('srv:kem'), 1216) },
        recovery_pk: hashFor('recovery-pk'),
        policy_bundle_hash: db.seed.policy.bundle_hash,
        limits: { chunk_bytes: CHUNK, max_file_bytes: 268_435_456, max_recipients: 16, lease_seconds: 60, session_ttl_seconds: 600, session_hard_cap_seconds: 28_800 },
        features: { messaging: true, slhdsa: false },
      }
    },
    async directory() {
      await gate(false)
      return currentDirectory()
    },
    async checkpoint() {
      await gate(false)
      return currentCheckpoint()
    },
    async health() {
      await gate(false)
      return { status: 'ok' }
    },
    async bench() {
      await gate(false)
      return {
        suite: 'QG-1',
        generated_at: iso(db.seed.now - 2 * DAY),
        organisation: ORG_NAME,
        results: [
          { name: 'protect_1mib_ms', p50: 41, p95: 63 },
          { name: 'open_1mib_ms', p50: 28, p95: 44 },
          { name: 'revoke_ms', p50: 34, p95: 52 },
        ],
      }
    },
    async keySet() {
      await gate(false)
      return {
        suite: 'QG-1',
        epoch: db.keysetEpoch,
        keys: db.services.flatMap((s) =>
          s.keys.map((k) => ({ service_id: s.service_id, key_id: k.key_id, alg: k.alg, public_key: randB64u(makeRng(`pk:${k.key_id}`), 1984), status: k.status })),
        ),
        signatures: sigsFor(`keyset:${db.keysetEpoch}`),
      }
    },

    // ----- this device -----
    async enrol(input, onStep?: (s: EnrolStep) => void) {
      await gate(false)
      if (state.kind !== 'none') throw err('QG_CONFLICT', 'already_enrolled')
      const name = input.device_name.trim()
      if (!name) throw err('QG_INVALID_INPUT', 'device_name_required')
      if (input.passphrase.length < 10) throw err('QG_INVALID_INPUT', 'passphrase_weak')
      const code = input.code.trim().toUpperCase()
      const invite = db.invites.find((i) => i.code.toUpperCase() === code && i.status === 'pending' && Date.parse(i.expires_at) > Date.now())
      if (!invite) throw err('QG_INVALID_INPUT', 'invite_invalid')
      const userId = invite.user_id
      const held = db.incidents.some((i) => {
        const st = viewIncident(i).status
        return i.inc.user_id === userId && (st === 'open' || st === 'rekeying')
      })
      if (held) throw err('QG_QUARANTINED', 'enrolment_held')
      const steps: EnrolStep[] = ['generating_keys', 'proving_possession', 'certificate_issued', 'sealing_keystore', 'session_started']
      let rec: SeedDevice | null = null
      for (const s of steps) {
        if (s === 'certificate_issued') {
          db.usedCodes.add(code)
          invite.status = 'used'
          rec = addDevice(userId, name)
          db.epoch += 1
          db.passphrases.set(rec.device_id, input.passphrase)
        }
        onStep?.(s)
        await sleep(2 * BASE_LATENCY)
      }
      if (!rec) throw err('QG_CONFLICT')
      const local = localDevice(rec)
      enrolled = { user_id: userId, device_id: rec.device_id, device_name: name }
      const session = newSession(userId)
      state = { kind: 'locked', device: local }
      addReceipt('enroll', rec.device_id, 'allow', 'allowed', ['QG-P001'], { user_id: userId, device_id: rec.device_id })
      setState({ kind: 'unlocked', device: local, session })
      persist()
      return local
    },

    async unlock(passphrase) {
      await gate(false)
      if (state.kind === 'none') throw err('QG_NOT_FOUND', 'not_enrolled')
      if (state.kind === 'revoked') throw err('QG_DENY_REVOKED')
      if (state.kind === 'unlocked') return state.session
      const local = state.device
      const rec = db.devices.find((d) => d.device_id === local.device_id)
      if (db.passphrases.get(local.device_id) !== passphrase) throw err('QG_LOCAL_PASSPHRASE')
      if (rec?.status === 'revoked') {
        setState({ kind: 'revoked', device: local })
        throw err('QG_DENY_REVOKED')
      }
      if (rec?.status === 'quarantined') throw err('QG_QUARANTINED', 'device_quarantined')
      const session = newSession(state.device.user_id)
      const device = localDevice(rec ?? db.devices[0])
      setState({ kind: 'unlocked', device, session })
      addReceipt('session.start', device.device_id)
      if (rec) rec.last_seen_at = iso(Date.now())
      return session
    },

    lock() {
      if (state.kind === 'unlocked') {
        addReceipt('session.end', state.device.device_id)
        setState({ kind: 'locked', device: state.device })
      }
    },

    async forgetDevice() {
      if (state.kind === 'none') return
      enrolled = null
      persona = 'none'
      setState({ kind: 'none' })
      persist()
    },

    // ----- files -----
    async listFiles(params) {
      await gate(true)
      const q = params?.q?.trim().toLowerCase()
      return db.files
        .filter(visible)
        .filter((f) => (q ? f.name.toLowerCase().includes(q) : true))
        .filter((f) => (params?.classification ? f.classification === params.classification : true))
        .sort((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at))
        .map(toItem)
    },

    async getFile(fileId) {
      await gate(true)
      const f = getVisibleFile(fileId)
      return {
        ...toItem(f),
        versions: f.versions.map((v) => ({ ...v })),
        activity: db.receipts.filter((r) => r.resource === fileId).slice(-20).reverse(),
      }
    },

    async protectFile(input, onProgress?: (p: ProtectProgress) => void, signal?) {
      await gate(true)
      const { user, device } = me()
      const name = input.file.name.trim()
      if (!name) throw err('QG_INVALID_INPUT', 'name_required')
      const recipientUsers = [...new Set(input.recipient_user_ids)]
      for (const id of recipientUsers) {
        const u = db.users.find((x) => x.user_id === id)
        if (!u) throw err('QG_INVALID_INPUT', 'recipient_unknown')
        if (u.status !== 'active') throw err('QG_DENY_POLICY', 'recipient_not_allowed')
      }
      const targets: SeedDevice[] = []
      for (const uid of [...recipientUsers, user.user_id]) {
        for (const d of activeDevicesOf(uid)) if (!targets.includes(d)) targets.push(d)
      }
      if (!targets.includes(device)) targets.push(device)
      const chunks = Math.max(1, Math.ceil(input.file.size / CHUNK))
      const cd = chunkDelay(chunks)
      for (let c = 1; c <= chunks; c++) {
        onProgress?.({ phase: 'encrypting', chunk: c, chunks })
        await sleep(cd, signal)
      }
      for (let c = 1; c <= chunks; c++) {
        onProgress?.({ phase: 'uploading', chunk: c, chunks })
        await sleep(cd, signal)
      }
      for (let i = 0; i < targets.length; i++) {
        onProgress?.({ phase: 'wrapping', device_id: targets[i].device_id, device_name: targets[i].name, done: i + 1, total: targets.length })
        await sleep(90, signal)
      }
      onProgress?.({ phase: 'committing' })
      await sleep(150, signal)
      if (signal?.aborted) throw err('QG_LOCAL_CANCELLED')
      const nowIso = iso(Date.now())
      const rec: SeedFile = {
        key: nid('key'),
        file_id: nid('fil'),
        name,
        classification: input.classification,
        size_bytes: input.file.size,
        version: 1,
        chunk_count: chunks,
        owner: { user_id: user.user_id, name: user.name },
        created_at: nowIso,
        updated_at: nowIso,
        recipients: [],
        can_open: true,
        rekey: 'none',
        versions: [{ version: 1, committed_at: nowIso, committed_by_device: device.device_id, reason: 'update' }],
      }
      addRecipientDevices(rec, targets)
      db.files.push(rec)
      addReceipt('file.create', rec.file_id)
      const commit = addReceipt('file.commit', rec.file_id)
      onProgress?.({ phase: 'done', receipt_id: commit.id })
      return { file: toItem(rec), receipt_id: commit.id }
    },

    async openFile(fileId, onProgress?: (p: OpenProgress) => void, signal?): Promise<OpenedFile> {
      await gate(true)
      const { device } = me()
      const f = getVisibleFile(fileId)
      onProgress?.({ phase: 'requesting' })
      await sleep(120, signal)
      if (!f.recipients.some((r) => r.device_id === device.device_id)) {
        const deny = addReceipt('slot.release', f.file_id, 'deny', 'no_slot', ['QG-P002'])
        throw err('QG_DENY_POLICY', 'no_slot', deny.id)
      }
      const release = addReceipt('slot.release', f.file_id, 'allow', 'allowed', ['QG-P002'])
      onProgress?.({ phase: 'released', receipt_id: release.id })
      await sleep(120, signal)
      onProgress?.({ phase: 'unwrapped' })
      await sleep(90, signal)
      const cd = chunkDelay(f.chunk_count)
      for (let c = 1; c <= f.chunk_count; c++) {
        onProgress?.({ phase: 'decrypting', chunk: c, chunks: f.chunk_count })
        await sleep(cd, signal)
      }
      addReceipt('chunk.read', f.file_id, 'allow', 'allowed', ['QG-P002'])
      onProgress?.({ phase: 'done' })
      return {
        blob: new Blob([`Mock content for ${f.name}. This is placeholder text from the development mock; no real file was decrypted.\n`], { type: 'text/plain' }),
        name: f.name,
        receipt_id: release.id,
        verified: true,
      }
    },

    async shareFile(fileId, userIds) {
      await gate(true)
      const f = ownedFile(fileId)
      for (const id of userIds) {
        const u = db.users.find((x) => x.user_id === id)
        if (!u) throw err('QG_INVALID_INPUT', 'recipient_unknown')
        if (u.status !== 'active') throw err('QG_DENY_POLICY', 'recipient_not_allowed')
      }
      for (const id of userIds) addRecipientDevices(f, activeDevicesOf(id))
      f.updated_at = iso(Date.now())
      const rcp = addReceipt('file.share', f.file_id, 'allow', 'allowed', ['QG-P006'])
      return { file: toItem(f), receipt_id: rcp.id }
    },

    async unshareFile(fileId, userId) {
      await gate(true)
      const f = ownedFile(fileId)
      if (userId === f.owner.user_id) throw err('QG_INVALID_INPUT', 'owner_cannot_be_removed')
      if (!f.recipients.some((r) => r.user_id === userId)) throw err('QG_NOT_FOUND')
      f.recipients = f.recipients.filter((r) => r.user_id !== userId)
      f.rekey = 'pending'
      db.rekeyMeta.set(f.file_id, { reason: 'unshare', incident_id: null })
      f.updated_at = iso(Date.now())
      const rcp = addReceipt('file.unshare', f.file_id, 'allow', 'allowed', ['QG-P006'])
      return { file: toItem(f), receipt_id: rcp.id }
    },

    async deleteFile(fileId) {
      await gate(true)
      const f = ownedFile(fileId)
      db.files = db.files.filter((x) => x !== f)
      db.rekeyMeta.delete(f.file_id)
      addReceipt('file.delete', f.file_id)
    },

    async pendingWork() {
      await gate(true)
      return pendingNow()
    },

    async runPendingWork(onProgress?: (p: WorkProgress) => void, signal?) {
      await gate(true)
      const work = pendingNow()
      let rekeyed = 0
      for (let i = 0; i < work.rekeys.length; i++) {
        const item = work.rekeys[i]
        const f = db.files.find((x) => x.file_id === item.file_id)
        if (!f) continue
        f.rekey = 'in_progress'
        const cd = chunkDelay(f.chunk_count)
        for (let c = 1; c <= f.chunk_count; c++) {
          onProgress?.({ kind: 'rekey', file_id: f.file_id, name: f.name, index: i + 1, total: work.rekeys.length, chunk: c, chunks: f.chunk_count })
          try {
            await sleep(cd, signal)
          } catch (e) {
            f.rekey = 'pending'
            throw e
          }
        }
        f.version += 1
        f.rekey = 'none'
        f.updated_at = iso(Date.now())
        f.versions.push({ version: f.version, committed_at: f.updated_at, committed_by_device: me().device.device_id, reason: 'rekey' })
        const rcp = addReceipt('rekey.commit', f.file_id, 'allow', 'allowed', ['QG-P004'])
        db.rekeyMeta.delete(f.file_id)
        for (const rec of db.incidents) {
          const entry = [...rec.exposure.exposed, ...rec.exposure.held].find((e) => e.file_id === f.file_id)
          if (!entry) continue
          entry.rekey = 'done'
          entry.new_version = f.version
          const step = rec.inc.timeline.find((s) => s.step === 'rekey_progress' && s.detail === `Re-key queued for ${f.name}`)
          if (step) {
            step.detail = `Re-keyed ${f.name} (${i + 1} of ${work.rekeys.length})`
            step.receipt_id = rcp.id
          }
        }
        rekeyed += 1
      }
      let shared = 0
      for (let i = 0; i < work.shares.length; i++) {
        const s = work.shares[i]
        const f = db.files.find((x) => x.file_id === s.file_id)
        const target = db.devices.find((x) => x.device_id === s.device_id)
        if (!f || !target) continue
        onProgress?.({ kind: 'share', file_id: f.file_id, name: f.name, index: i + 1, total: work.shares.length })
        await sleep(120, signal)
        addRecipientDevices(f, [target])
        addReceipt('file.share', f.file_id, 'allow', 'allowed', ['QG-P006'])
        shared += 1
      }
      finishContainedIncidents()
      return { rekeyed, shared }
    },

    // ----- devices and incidents -----
    async listDevices(scope = 'mine') {
      await gate(true)
      const { user, device } = me()
      if (scope === 'all') need('operator', 'admin', 'auditor')
      return db.devices
        .filter((d) => scope === 'all' || d.user_id === user.user_id)
        .map((d): T.Device => ({
          device_id: d.device_id,
          user_id: d.user_id,
          user_name: db.users.find((u) => u.user_id === d.user_id)?.name ?? 'Unknown',
          name: d.name,
          status: d.status,
          created_at: d.created_at,
          last_seen_at: d.last_seen_at,
          is_current: d.device_id === device.device_id,
          open_incident_id: db.incidents.find((i) => i.inc.device_id === d.device_id && !i.closed)?.inc.id ?? null,
        }))
    },

    async renameDevice(deviceId, name) {
      await gate(true)
      const { user, device } = me()
      const target = db.devices.find((d) => d.device_id === deviceId)
      if (!target) throw err('QG_NOT_FOUND')
      if (target.user_id !== user.user_id) throw err('QG_DENY_POLICY', 'not_owner')
      const clean = name.trim()
      if (!clean || clean.length > 64) throw err('QG_INVALID_INPUT', 'name_invalid')
      target.name = clean
      for (const f of db.files) for (const r of f.recipients) if (r.device_id === deviceId) r.device_name = clean
      db.epoch += 1
      addReceipt('device.rename', deviceId)
      if (deviceId === device.device_id && state.kind === 'unlocked') {
        setState({ kind: 'unlocked', device: localDevice(target), session: state.session })
      }
      return {
        device_id: target.device_id,
        user_id: target.user_id,
        user_name: user.name,
        name: target.name,
        status: target.status,
        created_at: target.created_at,
        last_seen_at: target.last_seen_at,
        is_current: deviceId === device.device_id,
        open_incident_id: db.incidents.find((i) => i.inc.device_id === deviceId && !i.closed)?.inc.id ?? null,
      }
    },

    async reportLost(deviceId, input) {
      await gate(true)
      const { user, device } = me()
      const target = db.devices.find((d) => d.device_id === deviceId)
      if (!target) throw err('QG_NOT_FOUND')
      if (deviceId === device.device_id) throw err('QG_DENY_POLICY', 'current_device')
      if (target.user_id !== user.user_id) throw err('QG_DENY_POLICY', 'not_owner')
      const lostAt = parseTime(input.lost_at, 'lost_at')
      return revokeCore(deviceId, lostAt, 'report', input.note?.trim() || null)
    },

    async revokeDevice(deviceId, input) {
      await gate(true)
      need('operator')
      const { device } = me()
      if (!db.devices.some((d) => d.device_id === deviceId)) throw err('QG_NOT_FOUND')
      if (deviceId === device.device_id) throw err('QG_DENY_POLICY', 'current_device')
      if (!input.reason.trim()) throw err('QG_INVALID_INPUT', 'reason_required')
      return revokeCore(deviceId, parseTime(input.compromise_time, 'compromise_time'), 'revoke', input.reason.trim())
    },

    async listIncidents(status) {
      await gate(true)
      return db.incidents
        .filter(visibleIncident)
        .map(viewIncident)
        .filter((i) => (status ? i.status === status : true))
        .sort((a, b) => Date.parse(b.reported_at) - Date.parse(a.reported_at))
        .map(summary)
    },

    async getIncident(id) {
      await gate(true)
      return viewIncident(getIncidentRec(id))
    },

    async getExposure(id) {
      await gate(true)
      return structuredClone(getIncidentRec(id).exposure)
    },

    async exportBundle(id) {
      await gate(true)
      need('operator', 'auditor')
      const rec = getIncidentRec(id)
      const rcp = addReceipt('bundle.export', rec.inc.device_id, 'allow', 'allowed', ['QG-P004'])
      rec.inc.timeline.push({ step: 'bundle_exported', ts: iso(Date.now()), receipt_id: rcp.id, detail: 'Proof bundle exported' })
      const ids = new Set<string>([
        ...rec.exposure.suspect_decisions.map((r) => r.id),
        ...[...rec.exposure.exposed, ...rec.exposure.held, ...rec.exposure.never_released].flatMap((e) => e.releases.map((r) => r.receipt_id)),
        ...rec.inc.timeline.map((s) => s.receipt_id).filter((x): x is string => x !== null),
      ])
      const body = {
        suite: 'QG-1',
        kind: 'mock_incident_bundle',
        incident: viewIncident(rec),
        exposure: structuredClone(rec.exposure),
        receipts: db.receipts.filter((r) => ids.has(r.id)),
        checkpoint: currentCheckpoint(),
      }
      return { ...body, __mock_digest: digest(stable(body)) }
    },

    async closeIncident(id) {
      await gate(true)
      need('operator')
      const rec = getIncidentRec(id)
      const view = viewIncident(rec)
      if (view.status === 'closed') throw err('QG_CONFLICT', 'already_closed')
      if (view.status !== 'contained') throw err('QG_CONFLICT', 'rekey_pending')
      const rcp = addReceipt('incident.close', rec.inc.device_id, 'allow', 'allowed', ['QG-P004'])
      rec.closed = true
      rec.inc.timeline.push({ step: 'closed', ts: iso(Date.now()), receipt_id: rcp.id, detail: `Closed by ${me().user.name}` })
      return viewIncident(rec)
    },

    // ----- people -----
    async createInvite(input) {
      await gate(true)
      const { user } = me()
      const expires = iso(Date.now() + 7 * DAY)
      const code = `QG-${randB64u(makeRng(`code:${++counter}:${db.seed.now}`), 6).toUpperCase().replace(/[-_]/g, 'X')}`
      let target: T.DirectoryUser | undefined
      if ('user_id' in input) {
        target = db.users.find((u) => u.user_id === input.user_id)
        if (!target) throw err('QG_NOT_FOUND')
        if (!has('admin') && target.user_id !== user.user_id) throw err('QG_DENY_POLICY', 'role_required')
      } else {
        need('admin')
        const nm = input.name.trim()
        if (!nm || input.roles.length === 0) throw err('QG_INVALID_INPUT', 'name_and_roles_required')
        if (input.roles.some((r) => r === 'admin' || r === 'operator')) {
          const change: T.Change = {
            id: nid('chg'),
            type: 'role_grant',
            target_user: { user_id: nid('usr'), name: nm },
            role: input.roles.find((r) => r === 'admin' || r === 'operator') ?? null,
            file_id: null,
            reason: `Invite for new person ${nm}`,
            requested_by: { user_id: user.user_id, name: user.name, device_id: me().device.device_id },
            requested_at: iso(Date.now()),
            status: 'pending',
            approvals: [],
            approvals_required: 2,
          }
          db.changes.push(change)
          addReceipt('change.request', change.id, 'allow', 'allowed', ['QG-P006'])
          return { change_id: change.id }
        }
        target = { user_id: nid('usr'), name: nm, roles: [...input.roles], status: 'active' }
        db.users.push(target)
        db.epoch += 1
      }
      const inv: InviteRec = {
        invite_id: nid('inv'),
        user_id: target.user_id,
        user_name: target.name,
        created_by: user.name,
        created_by_user_id: user.user_id,
        expires_at: expires,
        status: 'pending',
        code,
      }
      db.invites.push(inv)
      addReceipt('invite.create', inv.invite_id)
      return { invite_id: inv.invite_id, code, user_id: target.user_id, expires_at: expires }
    },

    async listInvites() {
      await gate(true)
      const { user } = me()
      return db.invites
        .filter((i) => has('admin') || i.created_by_user_id === user.user_id || i.user_id === user.user_id)
        .map((i): T.Invite => {
          const expired = i.status === 'pending' && Date.parse(i.expires_at) < Date.now()
          return {
            invite_id: i.invite_id,
            user_id: i.user_id,
            user_name: i.user_name,
            created_by: i.created_by,
            expires_at: i.expires_at,
            status: expired ? 'expired' : i.status,
          }
        })
    },

    async cancelInvite(id) {
      await gate(true)
      const inv = db.invites.find((i) => i.invite_id === id)
      if (!inv) throw err('QG_NOT_FOUND')
      if (!has('admin') && inv.created_by_user_id !== me().user.user_id) throw err('QG_DENY_POLICY', 'role_required')
      if (inv.status !== 'pending') throw err('QG_CONFLICT', 'invite_not_pending')
      inv.status = 'cancelled'
    },

    // ----- changes -----
    async listChanges(status) {
      await gate(true)
      need('admin', 'operator', 'auditor')
      return structuredClone(db.changes.filter((c) => (status ? c.status === status : true)))
    },

    async requestChange(input) {
      await gate(true)
      need('admin')
      const { user, device } = me()
      const target = db.users.find((u) => u.user_id === input.target_user_id)
      if (!target) throw err('QG_NOT_FOUND')
      if (!input.reason.trim()) throw err('QG_INVALID_INPUT', 'reason_required')
      if ((input.type === 'role_grant' || input.type === 'role_revoke') && !input.role) throw err('QG_INVALID_INPUT', 'role_missing')
      if (input.type === 'role_grant' && input.role && target.roles.includes(input.role)) throw err('QG_CONFLICT', 'role_already_held')
      if (input.type === 'role_revoke' && input.role && !target.roles.includes(input.role)) throw err('QG_CONFLICT', 'role_not_held')
      if (input.type === 'recovery_release') {
        if (!input.file_id) throw err('QG_INVALID_INPUT', 'file_missing')
        if (!db.files.some((f) => f.file_id === input.file_id)) throw err('QG_NOT_FOUND')
      }
      const strong = input.type === 'recovery_release' || (input.type === 'role_grant' && (input.role === 'admin' || input.role === 'operator'))
      const change: T.Change = {
        id: nid('chg'),
        type: input.type,
        target_user: { user_id: target.user_id, name: target.name },
        role: input.role ?? null,
        file_id: input.file_id ?? null,
        reason: input.reason.trim(),
        requested_by: { user_id: user.user_id, name: user.name, device_id: device.device_id },
        requested_at: iso(Date.now()),
        status: 'pending',
        approvals: [],
        approvals_required: strong ? 2 : 1,
      }
      db.changes.push(change)
      addReceipt('change.request', change.id, 'allow', 'allowed', ['QG-P006'])
      return structuredClone(change)
    },

    async approveChange(id) {
      await gate(true)
      // The API names "a different admin"; the mock also lets operators give the second approval
      // because the seeded organisation has only two admins.
      need('admin', 'operator')
      const { user, device } = me()
      const change = db.changes.find((c) => c.id === id)
      if (!change) throw err('QG_NOT_FOUND')
      if (change.requested_by.user_id === user.user_id || change.target_user.user_id === user.user_id) {
        const deny = addReceipt('change.approve', change.id, 'deny', 'self_approval', ['QG-P006'])
        throw err('QG_DENY_POLICY', 'self_approval', deny.id)
      }
      if (change.status !== 'pending') throw err('QG_CONFLICT', 'not_pending')
      if (change.approvals.some((a) => a.user_id === user.user_id)) throw err('QG_CONFLICT', 'already_approved')
      change.approvals.push({ user_id: user.user_id, name: user.name, device_id: device.device_id, at: iso(Date.now()) })
      addReceipt('change.approve', change.id, 'allow', 'allowed', ['QG-P006'])
      if (change.approvals.length >= change.approvals_required) {
        change.status = 'applied'
        const target = db.users.find((u) => u.user_id === change.target_user.user_id)
        if (target && change.role) {
          if (change.type === 'role_grant' && !target.roles.includes(change.role)) target.roles.push(change.role)
          if (change.type === 'role_revoke') target.roles = target.roles.filter((r) => r !== change.role)
          db.epoch += 1
        }
      }
      return structuredClone(change)
    },

    async rejectChange(id, reason) {
      await gate(true)
      need('admin')
      const change = db.changes.find((c) => c.id === id)
      if (!change) throw err('QG_NOT_FOUND')
      if (!reason.trim()) throw err('QG_INVALID_INPUT', 'reason_required')
      if (change.status !== 'pending') throw err('QG_CONFLICT', 'not_pending')
      change.status = 'rejected'
      addReceipt('change.reject', change.id)
      return structuredClone(change)
    },

    // ----- alerts -----
    async listAlerts(params) {
      await gate(true)
      need('operator', 'auditor')
      return structuredClone(
        db.alerts
          .filter((a) => (params?.status ? a.status === params.status : true))
          .filter((a) => (params?.rule_id ? a.rule_id === params.rule_id : true))
          .sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts)),
      )
    },

    async getAlert(id) {
      await gate(true)
      need('operator', 'auditor')
      const a = db.alerts.find((x) => x.id === id)
      if (!a) throw err('QG_NOT_FOUND')
      const path = db.alertPaths.get(id)
      return {
        ...structuredClone(a),
        receipts: db.receipts.filter((r) => a.explanation.receipt_ids.includes(r.id)),
        ...(path ? { path } : {}),
      }
    },

    async ackAlert(id) {
      await gate(true)
      need('operator')
      const a = db.alerts.find((x) => x.id === id)
      if (!a) throw err('QG_NOT_FOUND')
      if (a.status === 'acknowledged') throw err('QG_CONFLICT', 'already_acknowledged')
      a.status = 'acknowledged'
      a.acknowledged_by = me().user.name
      addReceipt('alert.ack', a.id, 'allow', 'allowed', ['QG-P004'])
      return structuredClone(a)
    },

    async liftResponse(responseId, reason) {
      await gate(true)
      need('operator')
      const a = db.alerts.find((x) => x.response?.id === responseId)
      if (!a || !a.response) throw err('QG_NOT_FOUND')
      if (!reason.trim()) throw err('QG_INVALID_INPUT', 'reason_required')
      if (a.response.lifted_at) throw err('QG_CONFLICT', 'already_lifted')
      a.response.lifted_at = iso(Date.now())
      a.response.lifted_by = me().user.name
      if (a.response.action === 'quarantine_device') {
        const dv = db.devices.find((d) => d.device_id === a.response?.scope.id)
        if (dv?.status === 'quarantined') dv.status = 'active'
      }
      addReceipt('response.lift', responseId, 'allow', 'allowed', ['QG-P004'])
      return structuredClone(a)
    },

    // ----- evidence -----
    async listReceipts(params) {
      await gate(true)
      const { user } = me()
      const all = has('auditor', 'operator')
      const limit = Math.min(200, Math.max(1, params?.limit ?? 50))
      let rows = db.receipts
        .filter((r) => all || r.subject.user_id === user.user_id)
        .filter((r) => (params?.user_id ? r.subject.user_id === params.user_id : true))
        .filter((r) => (params?.device_id ? r.subject.device_id === params.device_id : true))
        .filter((r) => (params?.resource ? r.resource === params.resource : true))
        .filter((r) => (params?.action ? r.action === params.action : true))
        .filter((r) => (params?.decision ? r.decision === params.decision : true))
        .sort((a, b) => b.leaf_index - a.leaf_index)
      if (params?.before) {
        const idx = rows.findIndex((r) => r.id === params.before)
        rows = idx >= 0 ? rows.slice(idx + 1) : rows
      }
      const items = rows.slice(0, limit)
      return { items: structuredClone(items), next_before: rows.length > limit ? items[items.length - 1].id : null }
    },

    async getReceipt(id) {
      await gate(true)
      return structuredClone(ownReceipt(id))
    },

    async verifyReceipt(id, onStep?: (s: VerifyStep) => void): Promise<VerifyResult> {
      await gate(true)
      const rcp = ownReceipt(id)
      await emitVerify(rcp, true, onStep)
      return { ok: true, checked: 1, failed_index: null, reason: null, checkpoint: currentCheckpoint() }
    },

    async verifyBundle(bundle, onStep?: (s: VerifyStep) => void): Promise<VerifyResult> {
      if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) throw err('QG_INVALID_INPUT', 'bundle_malformed')
      const b = bundle as Record<string, unknown>
      const list = Array.isArray(b.receipts) ? b.receipts : []
      const receipts = list.filter(isReceiptLike)
      let failedIndex: number | null = null
      if (hasTampered(bundle)) {
        const idx = list.findIndex((x) => hasTampered(x))
        failedIndex = idx >= 0 ? idx : 0
      } else {
        if (typeof b.__mock_digest !== 'string') throw err('QG_INVALID_INPUT', 'bundle_malformed')
        const { __mock_digest: claimed, ...rest } = b
        if (digest(stable(rest)) !== claimed) failedIndex = 0
      }
      const ok = failedIndex === null
      const subject = receipts[failedIndex ?? 0] ?? db.receipts[db.receipts.length - 1]
      await emitVerify(subject, ok, onStep)
      const cp = b.checkpoint && typeof b.checkpoint === 'object' ? (b.checkpoint as T.Checkpoint) : null
      return {
        ok,
        checked: Math.max(receipts.length, 1),
        failed_index: failedIndex,
        reason: ok ? null : 'root_mismatch',
        checkpoint: cp,
      }
    },

    // ----- services, policy, overview, signals -----
    async listServices() {
      await gate(true)
      need('admin', 'operator', 'auditor')
      return structuredClone(db.services)
    },

    async createService(name) {
      await gate(true)
      need('admin')
      const nm = name.trim()
      if (!nm) throw err('QG_INVALID_INPUT', 'name_required')
      const svc: T.Service = {
        service_id: nid('svc'),
        name: nm,
        status: 'active',
        keys: [{ key_id: nid('key'), alg: 'ed25519+ml-dsa-65', status: 'active', created_at: iso(Date.now()), retired_at: null }],
      }
      db.services.push(svc)
      db.keysetEpoch += 1
      addReceipt('service.create', svc.service_id)
      return structuredClone(svc)
    },

    async rotateService(id, input) {
      await gate(true)
      if (!has('admin') && !(has('operator') && input.emergency)) throw err('QG_DENY_POLICY', 'role_required')
      const svc = db.services.find((s) => s.service_id === id)
      if (!svc) throw err('QG_NOT_FOUND')
      if (!input.reason.trim()) throw err('QG_INVALID_INPUT', 'reason_required')
      const now = iso(Date.now())
      for (const k of svc.keys) {
        if (k.status === 'retiring') {
          k.status = 'retired'
          k.retired_at = now
        } else if (k.status === 'active') {
          k.status = input.emergency ? 'retired' : 'retiring'
          if (input.emergency) k.retired_at = now
        }
      }
      svc.keys.push({ key_id: nid('key'), alg: 'ed25519+ml-dsa-65', status: 'active', created_at: now, retired_at: null })
      db.keysetEpoch += 1
      addReceipt('service.rotate', svc.service_id)
      return structuredClone(svc)
    },

    async policy() {
      await gate(true)
      return structuredClone(db.seed.policy)
    },

    async overview() {
      await gate(true)
      need('admin', 'operator', 'auditor')
      const now = Date.now()
      const top = Math.floor(now / HOUR) * HOUR
      const decisions = Array.from({ length: 24 }, (_, i) => {
        const start = top - (23 - i) * HOUR
        const inHour = db.receipts.filter((r) => Date.parse(r.ts) >= start && Date.parse(r.ts) < start + HOUR)
        return {
          hour: iso(start),
          allow: inHour.filter((r) => r.decision === 'allow').length,
          deny: inHour.filter((r) => r.decision === 'deny').length,
        }
      })
      const views = db.incidents.map(viewIncident)
      const last = db.incidents.map((i) => i.inc).sort((a, b) => Date.parse(b.reported_at) - Date.parse(a.reported_at))[0]
      return {
        active_devices: db.devices.filter((d) => d.status === 'active').length,
        revoked_devices: db.devices.filter((d) => d.status === 'revoked').length,
        pending_rekeys: db.files.filter((f) => f.rekey !== 'none').length,
        open_alerts: db.alerts.filter((a) => a.status === 'open').length,
        open_incidents: views.filter((i) => i.status !== 'closed').length,
        last_time_to_enforce_ms: last ? last.time_to_enforce_ms : null,
        directory_epoch: db.epoch,
        tree_size: db.receipts.length,
        decisions_by_hour: decisions,
      }
    },

    async listSignals() {
      await gate(true)
      need('operator', 'auditor')
      return structuredClone(db.signals)
    },

    // ----- messaging -----
    async listMessages() {
      await gate(true)
      const { user } = me()
      return db.messages.filter((m) => m.to_user_id === user.user_id).map((m) => structuredClone(m.message))
    },

    async sendMessage(toUserId, text) {
      await gate(true)
      const { user, device } = me()
      if (!db.users.some((u) => u.user_id === toUserId)) throw err('QG_NOT_FOUND')
      if (!text.trim()) throw err('QG_INVALID_INPUT', 'text_required')
      const id = nid('msg')
      db.messages.push({
        to_user_id: toUserId,
        message: { message_id: id, from: { user_id: user.user_id, name: user.name, device_id: device.device_id }, sent_at: iso(Date.now()), text, verified: true },
      })
      addReceipt('message.send', id)
      return { message_id: id }
    },
  }

  // ---------- helpers that need the client scope ----------

  function newSession(userId: string): SessionInfo {
    const first = !db.firstSeen.has(userId)
    db.firstSeen.add(userId)
    const now = Date.now()
    return {
      session_id: nid('ses'),
      expires_at: iso(now + 10 * MIN),
      hard_expires_at: iso(now + 8 * HOUR),
      first_session: first,
    }
  }

  function ownReceipt(id: string): T.Receipt {
    const rcp = db.receipts.find((r) => r.id === id)
    if (!rcp) throw err('QG_NOT_FOUND')
    if (!has('auditor', 'operator') && rcp.subject.user_id !== me().user.user_id) throw err('QG_NOT_FOUND')
    return rcp
  }

  function pendingNow(): T.RekeyPending {
    const { user, device } = me()
    const rekeys = db.files
      .filter((f) => f.rekey !== 'none' && db.rekeyMeta.has(f.file_id))
      .map((f) => {
        const meta = db.rekeyMeta.get(f.file_id)
        return {
          file_id: f.file_id,
          name: f.name,
          version: f.version,
          reason: meta?.reason ?? 'exposed',
          incident_id: meta?.incident_id ?? null,
          recipients: f.recipients.map((r) => r.device_id),
        }
      })
    const mine = activeDevicesOf(user.user_id)
    const shares: T.RekeyPending['shares'] = []
    for (const f of db.files) {
      if (!f.recipients.some((r) => r.device_id === device.device_id)) continue
      for (const d of mine) {
        if (f.recipients.some((r) => r.device_id === d.device_id)) continue
        shares.push({ file_id: f.file_id, name: f.name, version: f.version, device_id: d.device_id, device_name: d.name })
      }
    }
    return { rekeys, shares }
  }

  return Object.assign(client, { control })
}
