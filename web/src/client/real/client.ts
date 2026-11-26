// The real QgClient: talks to /api/v1 and runs the QG-1 client crypto on this device.
import { QgError, type DeviceState, type QgClient, type VerifyResult, type VerifyStep } from '../client'
import type * as T from '../types'
import { b64u, fromB64u } from '../../crypto/b64u'
import { fromUtf8, utf8 } from '../../crypto/bytes'
import { canon } from '../../crypto/canonical'
import { checkMessage, envelopeDigests, messageStatement, openMessage, sealMessage, type EnvelopeDigest, type MessageEnvelope } from '../../crypto/envelope'
import { approvalStatement, changeHash, changeStatement, isChangeStatement, verifyPolicy } from '../../crypto/statements'
import { idbDeviceStore, memoryDeviceStore, type DeriveFn, type DeviceStore } from '../../crypto/keystore'
import { SUITE, context, verifyDual } from '../../crypto/suite'
import { verifyProofBundle, verifyReceiptProof } from '../../crypto/verify'
import {
  acceptCheckpoint,
  activeDevices,
  createCtx,
  fetchMeta,
  findDevice,
  integrity,
  items,
  localDevice,
  page,
  requireUnlocked,
  seg,
  serverKeys,
  setState,
  signerKey,
  touch,
  trustedDirectory,
  type Ctx,
} from './context'
import { deriveArgon2id } from './derive'
import { openFile, protectFile, runPendingWork, shareFile } from './files'
import { enrol, forgetDevice, lock, markRevoked, unlock } from './session'

export interface RealClientOptions {
  store?: DeviceStore
  fetch?: typeof fetch
  derive?: DeriveFn
}

/**
 * spec/API.md 9: GET /messages returns the calling device's envelope (without its device_id) plus the
 * digest of every envelope of the message, which is what the sender signed (SUITE.md 11).
 */
interface WireMessage {
  message_id: string
  from: { user_id: string; name: string; device_id: string }
  to_user_id: string
  sent_at: string
  envelope: { xwing_ct: string; ciphertext: string }
  envelope_digests: EnvelopeDigest[]
  signature: string
}

function defaultStore(): DeviceStore {
  return typeof indexedDB === 'undefined' ? memoryDeviceStore() : idbDeviceStore
}

/** Loads the stored device into state (locked, or revoked if the server said so before). */
async function init(ctx: Ctx): Promise<void> {
  const stored = await ctx.store.load()
  ctx.stored = stored
  if (!stored) return
  setState(ctx, stored.revoked ? { kind: 'revoked', device: localDevice(stored) } : { kind: 'locked', device: localDevice(stored) })
}

/** Local-only lock after the server ended the session (no /session/end to send). */
function lockLocal(ctx: Ctx): void {
  ctx.keyring.lock()
  ctx.http.clearSession()
  if (ctx.idleTimer) clearTimeout(ctx.idleTimer)
  ctx.idleTimer = null
  if (ctx.stored && ctx.state.kind === 'unlocked') setState(ctx, { kind: 'locked', device: localDevice(ctx.stored) })
}

/**
 * SUITE.md 10: before approving, check that `change` is a well-formed statement describing the change
 * shown (type, target, role, file), that `change_hash` is SHA-256 of its canonical bytes, and that the
 * requester's signature covers it (a change the server created for an invite carries signature "").
 */
async function checkedChangeHash(ctx: Ctx, c: T.Change): Promise<string> {
  const st = c.change
  if (!isChangeStatement(st)) throw integrity('change_statement_unavailable', 'The server did not send the signed change statement, so it cannot be approved here.')
  if (st.type !== c.type || st.target_user_id !== c.target_user.user_id || st.role !== c.role || st.file_id !== c.file_id) {
    throw integrity('change_mismatch', 'The signed change does not match the change shown.')
  }
  const hash = await changeHash(st, ctx.prov)
  if (c.change_hash !== undefined && c.change_hash !== hash) throw integrity('change_hash')
  if (c.signature) {
    const pk = await signerKey(ctx, c.requested_by.device_id, st.directory_epoch)
    let ok = false
    try {
      ok = ctx.prov.mldsaVerify(pk, canon(st), fromB64u(c.signature), context('change'))
    } catch {
      ok = false
    }
    if (!ok) throw integrity('change_signature', 'The requester’s signature on this change did not verify.')
  }
  return hash
}

export function createRealClient(opts: RealClientOptions = {}): QgClient {
  const ctx = createCtx({ store: opts.store ?? defaultStore(), fetch: opts.fetch, derive: opts.derive ?? deriveArgon2id })
  ctx.lockNow = () => lock(ctx)
  ctx.http.onAuthEvent = (e) => {
    if (e === 'revoked') void markRevoked(ctx)
    else lockLocal(ctx)
  }
  ctx.http.onActivity = () => touch(ctx)
  const ready = init(ctx).catch(() => undefined)

  /** Authenticated JSON call after init. */
  async function api<R>(method: string, path: string, o: Parameters<typeof ctx.http.call>[2] = {}): Promise<R> {
    await ready
    requireUnlocked(ctx)
    return (await ctx.http.call<R>(method, path, o)).data
  }

  /** SUITE.md 10: ML-DSA signature with purpose change over canon(statement). */
  function signChange(statement: unknown): string {
    requireUnlocked(ctx)
    return b64u(ctx.prov.mldsaSign(ctx.keyring.sigSeed(), canon(statement), context('change')))
  }

  /**
   * SUITE.md 11: check that the message is for this person, that this device's envelope is among the
   * signed digests and that the sender's signature (sig_pk from the current verified directory) covers
   * them; only then decrypt. A message that fails any check is listed with no text and verified false.
   */
  async function decryptMessage(m: WireMessage, dir: T.Directory): Promise<T.Message> {
    const { stored } = requireUnlocked(ctx)
    const self = { device_id: stored.device.device_id, user_id: stored.device.user_id }
    const sender = findDevice(dir, m.from.device_id)
    const senderPk = sender && sender.user_id === m.from.user_id ? fromB64u(sender.sig_pk, 1952) : null
    let text = ''
    let verified = false
    if (await checkMessage(m, self, senderPk, ctx.prov)) {
      try {
        text = fromUtf8(await openMessage(ctx.keyring.kemSeed(), m.envelope, self.device_id, self.user_id, ctx.prov))
        verified = true
      } catch {
        verified = false
      }
    }
    return { message_id: m.message_id, from: m.from, sent_at: m.sent_at, text, verified }
  }

  const client: QgClient = {
    getState: (): DeviceState => ctx.state,
    subscribe(listener) {
      ctx.listeners.add(listener)
      return () => void ctx.listeners.delete(listener)
    },

    // ---- public ----
    async meta() {
      await ready
      return fetchMeta(ctx)
    },
    async directory() {
      await ready
      return trustedDirectory(ctx)
    },
    async checkpoint() {
      await ready
      const { data } = await ctx.http.public<T.Checkpoint>('GET', '/api/v1/log/checkpoint')
      return acceptCheckpoint(ctx, data)
    },
    async health() {
      return (await ctx.http.public<{ status: string }>('GET', '/healthz')).data
    },
    async bench() {
      try {
        return (await ctx.http.public<Record<string, unknown>>('GET', '/api/v1/bench/latest')).data
      } catch (e) {
        if (e instanceof QgError && e.code === 'QG_NOT_FOUND') return null
        throw e
      }
    },
    async keySet() {
      await ready
      const keys = await serverKeys(ctx)
      const { data } = await ctx.http.public<T.KeySet>('GET', '/api/v1/keys')
      if (data?.suite !== SUITE || !verifyDual(data, keys, 'keyset', ctx.prov).ok) throw integrity('keyset_signature')
      return data
    },

    // ---- this device ----
    async enrol(input, onStep) {
      await ready
      return enrol(ctx, input, onStep)
    },
    async unlock(passphrase) {
      await ready
      return unlock(ctx, passphrase)
    },
    lock: () => lock(ctx),
    async forgetDevice() {
      await ready
      return forgetDevice(ctx)
    },

    // ---- files ----
    async listFiles(params) {
      return items<T.FileItem>(await api('GET', '/api/v1/files', { query: { q: params?.q, classification: params?.classification } }))
    },
    getFile: (id) => api<T.FileDetail>('GET', `/api/v1/files/${seg(id)}`),
    async protectFile(input, onProgress, signal) {
      await ready
      return protectFile(ctx, input, onProgress, signal)
    },
    async openFile(id, onProgress, signal) {
      await ready
      return openFile(ctx, id, onProgress, signal)
    },
    async shareFile(id, userIds) {
      await ready
      return shareFile(ctx, id, userIds)
    },
    unshareFile: (id, userId) => api('POST', `/api/v1/files/${seg(id)}/unshare`, { json: { user_id: userId } }),
    async deleteFile(id) {
      await api<null>('DELETE', `/api/v1/files/${seg(id)}`)
    },
    pendingWork: () => api<T.RekeyPending>('GET', '/api/v1/rekey/pending'),
    async runPendingWork(onProgress, signal) {
      await ready
      return runPendingWork(ctx, onProgress, signal)
    },

    // ---- devices and incidents ----
    async listDevices(scope) {
      return items<T.Device>(await api('GET', '/api/v1/devices', { query: { scope: scope === 'all' ? 'all' : undefined } }))
    },
    async renameDevice(id, name) {
      const d = await api<T.Device>('PATCH', `/api/v1/devices/${seg(id)}`, { json: { name } })
      if (ctx.stored && id === ctx.stored.device.device_id) {
        ctx.stored = { ...ctx.stored, device: { ...ctx.stored.device, device_name: d.name } }
        await ctx.store.save(ctx.stored)
        if (ctx.state.kind === 'unlocked') setState(ctx, { ...ctx.state, device: localDevice(ctx.stored) })
      }
      return d
    },
    async reportLost(id, input) {
      const r = await api<T.RevokeResult>('POST', `/api/v1/devices/${seg(id)}/report-lost`, { json: input })
      await acceptCheckpoint(ctx, r.checkpoint)
      return r
    },
    async revokeDevice(id, input) {
      const r = await api<T.RevokeResult>('POST', `/api/v1/devices/${seg(id)}/revoke`, { json: input })
      await acceptCheckpoint(ctx, r.checkpoint)
      return r
    },
    async listIncidents(status) {
      return items<T.IncidentSummary>(await api('GET', '/api/v1/incidents', { query: { status } }))
    },
    getIncident: (id) => api<T.Incident>('GET', `/api/v1/incidents/${seg(id)}`),
    getExposure: (id) => api<T.Exposure>('GET', `/api/v1/incidents/${seg(id)}/exposure`),
    exportBundle: (id) => api<T.ProofBundle>('GET', `/api/v1/incidents/${seg(id)}/bundle`),
    closeIncident: (id) => api<T.Incident>('POST', `/api/v1/incidents/${seg(id)}/close`),

    // ---- people ----
    createInvite: (input) => api('POST', '/api/v1/invites', { json: input }),
    async listInvites() {
      return items<T.Invite>(await api('GET', '/api/v1/invites'))
    },
    async cancelInvite(id) {
      await api<null>('DELETE', `/api/v1/invites/${seg(id)}`)
    },

    // ---- changes (SUITE.md 10) ----
    async listChanges(status) {
      return items<T.Change>(await api('GET', '/api/v1/changes', { query: { status } }))
    },
    async requestChange(input) {
      await ready
      requireUnlocked(ctx)
      const post = async (dir: T.Directory) => {
        const change = changeStatement({ ...input, directory_epoch: dir.epoch })
        return api<T.Change>('POST', '/api/v1/changes', { json: { change, signature: signChange(change) } })
      }
      try {
        return await post(await trustedDirectory(ctx))
      } catch (e) {
        if (!(e instanceof QgError) || e.code !== 'QG_STALE_EPOCH') throw e
        return post(await trustedDirectory(ctx))
      }
    },
    async approveChange(id) {
      const c = items<T.Change>(await api('GET', '/api/v1/changes', { query: { status: 'pending', limit: 200 } })).find((x) => x.id === id)
      if (!c) throw new QgError({ code: 'QG_NOT_FOUND', message: 'That change is not pending.' })
      const approval = approvalStatement(await checkedChangeHash(ctx, c), id)
      return api<T.Change>('POST', `/api/v1/changes/${seg(id)}/approve`, { json: { signature: signChange(approval) } })
    },
    rejectChange: (id, reason) => api<T.Change>('POST', `/api/v1/changes/${seg(id)}/reject`, { json: { reason } }),

    // ---- alerts ----
    async listAlerts(params) {
      return items<T.Alert>(await api('GET', '/api/v1/alerts', { query: { status: params?.status, rule_id: params?.rule_id } }))
    },
    getAlert: (id) => api<T.AlertDetail>('GET', `/api/v1/alerts/${seg(id)}`),
    ackAlert: (id, note) => api<T.Alert>('POST', `/api/v1/alerts/${seg(id)}/ack`, { json: note === undefined ? {} : { note } }),
    liftResponse: (id, reason) => api<T.Alert>('POST', `/api/v1/responses/${seg(id)}/lift`, { json: { reason } }),

    // ---- evidence ----
    async listReceipts(params) {
      return page<T.Receipt>(await api('GET', '/api/v1/log/receipts', { query: { ...params } }))
    },
    getReceipt: (id) => api<T.Receipt>('GET', `/api/v1/log/receipts/${seg(id)}`),
    async verifyReceipt(id, onStep?: (s: VerifyStep) => void): Promise<VerifyResult> {
      const receipt = await api<T.Receipt>('GET', `/api/v1/log/receipts/${seg(id)}`)
      if (receipt.id !== id) return { ok: false, checked: 0, failed_index: receipt.leaf_index ?? null, reason: 'receipt_mismatch', checkpoint: null }
      const proof = await api<T.InclusionProof>('GET', `/api/v1/log/proof/${receipt.leaf_index}`)
      const keys = await serverKeys(ctx)
      const result = verifyReceiptProof(receipt, proof, keys, onStep, ctx.prov)
      if (!result.ok) return result
      try {
        await acceptCheckpoint(ctx, proof.checkpoint)
      } catch (e) {
        if (e instanceof QgError && e.code === 'QG_LOCAL_INTEGRITY') return { ...result, ok: false, reason: e.reason, failed_index: receipt.leaf_index }
        throw e
      }
      return result
    },
    async verifyBundle(bundle, onStep) {
      await ready
      return verifyProofBundle(bundle, ctx.stored?.server_keys ?? null, onStep, ctx.prov)
    },

    // ---- services, policy, overview, signals ----
    async listServices() {
      return items<T.Service>(await api('GET', '/api/v1/services'))
    },
    createService: (name) => api<T.Service>('POST', '/api/v1/services', { json: { name } }),
    rotateService: (id, input) => api<T.Service>('POST', `/api/v1/services/${seg(id)}/rotate`, { json: input }),
    async policy() {
      const p = await api<T.Policy>('GET', '/api/v1/policy')
      const check = await verifyPolicy(p, await serverKeys(ctx), ctx.prov)
      if (!check.ok) throw integrity(check.reason, 'The policy the server sent does not match its signed bundle.')
      return p
    },
    overview: () => api<T.Overview>('GET', '/api/v1/overview'),
    async listSignals() {
      return items<T.Signal>(await api('GET', '/api/v1/signals'))
    },

    // ---- messaging (SUITE.md 11) ----
    async listMessages() {
      const raw = items<WireMessage>(await api('GET', '/api/v1/messages'))
      const dir = await trustedDirectory(ctx)
      const out: T.Message[] = []
      for (const m of raw) out.push(await decryptMessage(m, dir))
      return out
    },
    async sendMessage(toUserId, text) {
      await ready
      requireUnlocked(ctx)
      const dir = await trustedDirectory(ctx)
      const devices = activeDevices(dir, [toUserId])
      if (devices.length === 0) throw new QgError({ code: 'QG_INVALID_INPUT', message: 'That person has no active device.', reason: 'no_recipients' })
      const envelopes: MessageEnvelope[] = []
      for (const d of devices) envelopes.push(await sealMessage(fromB64u(d.kem_pk, 1216), d.device_id, toUserId, utf8(text), ctx.prov))
      envelopes.sort((a, b) => (a.device_id < b.device_id ? -1 : a.device_id > b.device_id ? 1 : 0))
      const statement = messageStatement(toUserId, await envelopeDigests(envelopes, ctx.prov))
      const signature = b64u(ctx.prov.mldsaSign(ctx.keyring.sigSeed(), statement, context('message')))
      return api<{ message_id: string }>('POST', '/api/v1/messages', { json: { to_user_id: toUserId, envelopes, signature } })
    },
  }
  return client
}
