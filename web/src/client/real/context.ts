// Shared state of the real client: device state and listeners, the key ring, pinned server keys,
// and directory/checkpoint trust (SUITE.md 4, 8.1, 8.3, 9.3).
import { QgError, type DeviceState, type LocalDevice, type SessionInfo } from '../client'
import type * as T from '../types'
import { fromB64u } from '../../crypto/b64u'
import { ctEqual } from '../../crypto/bytes'
import { canon } from '../../crypto/canonical'
import { Keyring, type DeriveFn, type DeviceStore, type StoredDevice } from '../../crypto/keystore'
import { verifyConsistency } from '../../crypto/merkle'
import { getProvider, type CryptoProvider } from '../../crypto/provider'
import { SUITE, type ServerKeys } from '../../crypto/suite'
import { verifyCheckpoint, verifyDirectorySignature } from '../../crypto/verify'
import { Http, seg } from './http'

export const IDLE_LOCK_MS = 10 * 60 * 1000

export interface Ctx {
  http: Http
  store: DeviceStore
  prov: CryptoProvider
  derive: DeriveFn
  keyring: Keyring
  stored: StoredDevice | null
  state: DeviceState
  listeners: Set<(s: DeviceState) => void>
  /** Directories verified in this process, by epoch. */
  directories: Map<number, T.Directory>
  lastCheckpoint: T.Checkpoint | null
  idleTimer: ReturnType<typeof setTimeout> | null
  /** Called by the idle timer and auth events; set by the client. */
  lockNow: () => void
}

export function createCtx(opts: { store: DeviceStore; fetch?: typeof fetch; derive: DeriveFn }): Ctx {
  return {
    http: new Http(opts.fetch),
    store: opts.store,
    prov: getProvider(),
    derive: opts.derive,
    keyring: new Keyring(),
    stored: null,
    state: { kind: 'none' },
    listeners: new Set(),
    directories: new Map(),
    lastCheckpoint: null,
    idleTimer: null,
    lockNow: () => undefined,
  }
}

// ---- errors -----------------------------------------------------------------------------------

export function integrity(reason: string, message = 'A signature, hash or tag failed to verify on this device.'): QgError {
  return new QgError({ code: 'QG_LOCAL_INTEGRITY', message, reason })
}

export function cancelledError(): QgError {
  return new QgError({ code: 'QG_LOCAL_CANCELLED', message: 'Cancelled.' })
}

export function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw cancelledError()
}

/** Lets the browser paint progress between chunks. */
export function yieldToLoop(): Promise<void> {
  return new Promise((r) => setTimeout(r, 0))
}

// ---- state ------------------------------------------------------------------------------------

export function setState(ctx: Ctx, s: DeviceState): void {
  ctx.state = s
  for (const l of [...ctx.listeners]) {
    try {
      l(s)
    } catch {
      // a listener's failure never affects the client
    }
  }
}

export function localDevice(stored: StoredDevice): LocalDevice {
  return {
    device_id: stored.device.device_id,
    device_name: stored.device.device_name,
    user_id: stored.device.user_id,
    user_name: stored.device.user_name,
    roles: stored.device.roles as T.Role[],
    provider: 'noble',
    enrolled_at: stored.device.enrolled_at,
  }
}

/** The unlocked state's parts, or QG_NO_SESSION when locked. */
export function requireUnlocked(ctx: Ctx): { device: LocalDevice; session: SessionInfo; stored: StoredDevice } {
  if (ctx.state.kind !== 'unlocked' || !ctx.stored || !ctx.keyring.unlocked) {
    throw new QgError({ code: 'QG_NO_SESSION', message: 'Unlock this device first.' })
  }
  return { device: ctx.state.device, session: ctx.state.session, stored: ctx.stored }
}

/** Restarts the 10-minute idle auto-lock. */
export function touch(ctx: Ctx): void {
  if (ctx.idleTimer) clearTimeout(ctx.idleTimer)
  ctx.idleTimer = null
  if (ctx.state.kind !== 'unlocked') return
  ctx.idleTimer = setTimeout(() => ctx.lockNow(), IDLE_LOCK_MS)
}

// ---- server keys and trust ---------------------------------------------------------------------

export async function fetchMeta(ctx: Ctx): Promise<T.Meta> {
  const { data } = await ctx.http.public<T.Meta>('GET', '/api/v1/meta')
  if (!data || data.suite !== SUITE) throw new QgError({ code: 'QG_BAD_SUITE', message: 'The server does not speak QG-1.' })
  if (ctx.stored) assertPinned(ctx, data.server_keys)
  return data
}

/** SUITE.md 4: keys pinned at enrolment; a different key later is refused. */
export function assertPinned(ctx: Ctx, keys: ServerKeys): void {
  const pin = ctx.stored?.server_keys
  if (!pin) return
  if (keys.ed25519_pk !== pin.ed25519_pk || keys.mldsa_pk !== pin.mldsa_pk) {
    throw integrity('server_key_changed', 'The server presented keys that differ from the ones pinned at enrolment.')
  }
}

/** Pinned keys when enrolled; otherwise the keys /meta reports (before enrolment only). */
export async function serverKeys(ctx: Ctx): Promise<ServerKeys> {
  if (ctx.stored) return ctx.stored.server_keys
  const m = await fetchMeta(ctx)
  return { ed25519_pk: m.server_keys.ed25519_pk, mldsa_pk: m.server_keys.mldsa_pk }
}

async function persistEpoch(ctx: Ctx, epoch: number): Promise<void> {
  if (!ctx.stored || epoch <= ctx.stored.highest_epoch) return
  ctx.stored = { ...ctx.stored, highest_epoch: epoch }
  await ctx.store.save(ctx.stored)
}

/**
 * SUITE.md 8.1/8.3: accept a directory only if both signatures verify under the pinned keys and, when
 * it claims to be current, its epoch is not lower than the highest seen. When the previous epoch is
 * known, prev_hash must chain to it.
 */
export async function acceptDirectory(ctx: Ctx, dir: T.Directory, keys: ServerKeys, opts: { current: boolean }): Promise<T.Directory> {
  if (!verifyDirectorySignature(dir, keys, ctx.prov)) throw integrity('directory_signature')
  if (!Number.isSafeInteger(dir.epoch) || dir.epoch < 1) throw integrity('directory_epoch')
  const highest = Math.max(ctx.stored?.highest_epoch ?? 0, ...ctx.directories.keys())
  if (opts.current && dir.epoch < highest) throw integrity('directory_rollback', 'The server sent an older directory than this device has already seen.')
  const prev = ctx.directories.get(dir.epoch - 1)
  if (prev) {
    const h = await ctx.prov.sha256(canon(prev))
    if (!ctEqual(h, fromB64u(dir.prev_hash, 32))) throw integrity('directory_chain')
  }
  ctx.directories.set(dir.epoch, dir)
  if (opts.current) await persistEpoch(ctx, dir.epoch)
  return dir
}

/** The current directory, fetched and verified. */
export async function trustedDirectory(ctx: Ctx): Promise<T.Directory> {
  const keys = await serverKeys(ctx)
  const { data } = await ctx.http.public<T.Directory>('GET', '/api/v1/directory')
  return acceptDirectory(ctx, data, keys, { current: true })
}

/** A historical directory epoch (for signers of older manifests), verified. */
export async function trustedDirectoryAt(ctx: Ctx, epoch: number): Promise<T.Directory> {
  const cached = ctx.directories.get(epoch)
  if (cached) return cached
  const keys = await serverKeys(ctx)
  const { data } = await ctx.http.public<T.Directory>('GET', '/api/v1/directory', { query: { epoch } })
  if (data?.epoch !== epoch) throw integrity('directory_epoch')
  return acceptDirectory(ctx, data, keys, { current: false })
}

/**
 * SUITE.md 9.3: verify a checkpoint's dual signature and, when an older checkpoint was seen in this
 * process, the consistency proof from it (an authenticated route, so only when unlocked).
 */
export async function acceptCheckpoint(ctx: Ctx, cp: T.Checkpoint): Promise<T.Checkpoint> {
  const keys = await serverKeys(ctx)
  if (!verifyCheckpoint(cp, keys, undefined, ctx.prov)) throw integrity('checkpoint_signature')
  const last = ctx.lastCheckpoint
  if (last && cp.tree_size < last.tree_size) return cp
  if (last && cp.tree_size > last.tree_size && ctx.http.hasSession && last.tree_size > 0) {
    const { data } = await ctx.http.call<{ from: number; to: number; proof: string[] }>('GET', '/api/v1/log/consistency', {
      query: { from: last.tree_size, to: cp.tree_size },
    })
    const ok = verifyConsistency(last.tree_size, cp.tree_size, fromB64u(last.root_hash, 32), fromB64u(cp.root_hash, 32), data.proof.map((p) => fromB64u(p, 32)), ctx.prov)
    if (!ok) throw integrity('log_inconsistent', 'The evidence log is not consistent with a checkpoint seen earlier.')
  } else if (last && cp.tree_size === last.tree_size && cp.root_hash !== last.root_hash) {
    throw integrity('log_inconsistent', 'Two checkpoints of the same size disagree.')
  }
  if (!last || cp.tree_size >= last.tree_size) ctx.lastCheckpoint = cp
  return cp
}

// ---- directory helpers ------------------------------------------------------------------------

/** Active, unexpired, unrevoked devices of the given people (directory issued_at as the clock). */
export function activeDevices(dir: T.Directory, userIds: Iterable<string>): T.Certificate[] {
  const wanted = new Set(userIds)
  const revoked = new Set(dir.revoked.map((r) => r.device_id))
  const activeUsers = new Set(dir.users.filter((u) => u.status === 'active').map((u) => u.user_id))
  return dir.devices.filter(
    (d) => wanted.has(d.user_id) && activeUsers.has(d.user_id) && !revoked.has(d.device_id) && d.expires_at > dir.issued_at && d.suite === SUITE,
  )
}

export function findDevice(dir: T.Directory, deviceId: string): T.Certificate | null {
  return dir.devices.find((d) => d.device_id === deviceId) ?? null
}

export function userName(dir: T.Directory, userId: string): string {
  return dir.users.find((u) => u.user_id === userId)?.name ?? userId
}

/** Lists come back as `{items, next_before}` (spec/API.md 1); a bare array is accepted too. */
export function items<X>(data: unknown): X[] {
  if (Array.isArray(data)) return data as X[]
  if (data && typeof data === 'object' && Array.isArray((data as { items?: unknown }).items)) return (data as { items: X[] }).items
  return []
}

export function page<X>(data: unknown): T.Page<X> {
  return { items: items<X>(data), next_before: (data as { next_before?: string | null } | null)?.next_before ?? null }
}

export { seg }
