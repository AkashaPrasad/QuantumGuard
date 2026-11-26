// End-to-end wiring test of the real client against an in-process fake QG-1 server that uses the
// same crypto modules for the server side (enrol, session, request MAC, files, slots, shares).
import { ed25519 } from '@noble/curves/ed25519.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { describe, expect, it } from 'vitest'
import { QgError, type EnrolStep, type OpenProgress, type ProtectProgress } from '../client'
import type * as T from '../types'
import { b64u, fromB64u } from '../../crypto/b64u'
import { concat, fromUtf8, toHex, utf8 } from '../../crypto/bytes'
import { canon } from '../../crypto/canonical'
import { messageStatement, verifyManifest, verifyShare, type Manifest, type MessageEnvelope, type ShareStatement } from '../../crypto/envelope'
import { memoryDeviceStore } from '../../crypto/keystore'
import { deriveEnrolConfirmKey, deriveSessionKeys, enrolTranscript, macInput, sessionTranscript } from '../../crypto/protocol'
import { getProvider } from '../../crypto/provider'
import { approvalStatement, changeHash } from '../../crypto/statements'
import { context, signingInput, verifyDevice, type ServerPurpose } from '../../crypto/suite'
import { createRealClient } from './client'

const prov = getProvider()
const NOW = '2026-11-26T12:00:00.000Z'
const fastDerive = async (pw: Uint8Array, salt: Uint8Array) => prov.sha256(concat(pw, salt))

class FakeServer {
  edSeed = prov.randomBytes(32)
  mlSeed = prov.randomBytes(32)
  keys = { ed25519_pk: b64u(ed25519.getPublicKey(this.edSeed)), mldsa_pk: b64u(ml_dsa65.keygen(this.mlSeed).publicKey) }
  recovery = prov.xwingKeygen()
  /** null until a recovery kit is issued (spec/API.md 10). */
  recoveryPk: string | null = b64u(this.recovery.publicKey)
  users: T.DirectoryUser[] = [
    { user_id: 'usr_alice', name: 'Alice', roles: ['employee'], status: 'active' },
    { user_id: 'usr_bob', name: 'Bob', roles: ['employee'], status: 'active' },
  ]
  invites = new Map([['code-alice', 'usr_alice'], ['code-bob', 'usr_bob']])
  certs: T.Certificate[] = []
  epoch = 1
  prevHash = b64u(new Uint8Array(32))
  directory: T.Directory = this.publish()
  enrolls = new Map<string, Record<string, unknown>>()
  starts = new Map<string, { device_id: string; ss: Uint8Array; challenge: string; transcript: Uint8Array }>()
  sessions = new Map<string, { mac: Uint8Array; last: number; device_id: string }>()
  files = new Map<string, { name: string; classification: T.Classification; size: number; chunk_count: number; chunks: Map<number, Uint8Array>; manifest?: Manifest; manifest_sig?: string; signer?: string; wraps: Map<string, { xwing_ct: string; wrapped_dek: string; epoch: number }> }>()
  messages: { message_id: string; from: { user_id: string; name: string; device_id: string }; to_user_id: string; envelopes: MessageEnvelope[]; signature: string }[] = []
  changes: (T.Change & { applied?: boolean })[] = []
  commits: Record<string, unknown>[] = []
  seqLog: number[] = []
  tamperChunk = -1
  revokeAll = false
  /** Lease ids handed out; the current one is the only valid one. `expireLeaseAtChunk` invalidates it before that chunk. */
  lease = 'lse_1'
  expireLeaseAtChunk = -1
  staleCommits = 0
  slotsReleased = 0
  n = 0

  sign<X extends Record<string, unknown>>(obj: X, p: ServerPurpose): X & { signatures: T.Signatures } {
    const m = signingInput(obj)
    const ctx = context(p)
    return { ...obj, signatures: { ed25519: b64u(ed25519.sign(concat(ctx, new Uint8Array([0]), m), this.edSeed)), mldsa: b64u(ml_dsa65.sign(m, ml_dsa65.keygen(this.mlSeed).secretKey, { context: ctx })) } }
  }
  publish(): T.Directory {
    const d = this.sign({ suite: 'QG-1' as const, epoch: this.epoch, prev_hash: this.prevHash, issued_at: NOW, users: this.users, devices: [...this.certs].sort((a, b) => (a.device_id < b.device_id ? -1 : 1)), revoked: [], recovery_pk: this.recoveryPk }, 'directory')
    this.directory = d
    return d
  }
  bump() {
    this.prevHash = b64u(prov.sha256Sync(canon(this.directory)))
    this.epoch++
    this.publish()
  }
  id(p: string) {
    return `${p}_${String(++this.n).padStart(22, 'A')}`
  }
  file(f: { name: string; classification: T.Classification; size: number; chunk_count: number; wraps: Map<string, unknown> }, id: string): T.FileItem {
    return { file_id: id, name: f.name, classification: f.classification, size_bytes: f.size, version: 1, chunk_count: f.chunk_count, owner: { user_id: 'usr_alice', name: 'Alice' }, created_at: NOW, updated_at: NOW, recipients: [...f.wraps.keys()].map((d) => ({ device_id: d, user_id: '', user_name: '', device_name: '' })), can_open: true, rekey: 'none' }
  }

  fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const path = String(input)
    const method = (init?.method ?? 'GET').toUpperCase()
    const body = init?.body ? new Uint8Array(init.body as ArrayBuffer) : new Uint8Array(0)
    const headers = new Headers(init?.headers)
    const json = () => JSON.parse(fromUtf8(body)) as Record<string, unknown>
    const ok = (data: unknown, status = 200) => new Response(data === null ? null : JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } })
    const err = (status: number, code: string, reason = '') => ok({ error: { code, message: code, reason, request_id: 'r', receipt_id: null } }, status)
    const u = new URL(path, 'http://x')
    const p = u.pathname

    if (p === '/api/v1/meta') return ok({ suite: 'QG-1', version: '1', commit: 'x', demo: true, server_keys: { ...this.keys, kem_pk: '' }, recovery_pk: this.recoveryPk, policy_bundle_hash: '', limits: { chunk_bytes: 1048576, max_file_bytes: 104857600, max_recipients: 32, lease_seconds: 60, session_ttl_seconds: 600, session_hard_cap_seconds: 3600 }, features: { messaging: true, slhdsa: false } })
    if (p === '/api/v1/directory') return ok(this.directory)
    if (p === '/api/v1/enroll/start') {
      const b = json()
      const user_id = this.invites.get(b.code as string)
      if (!user_id) return err(400, 'QG_INVALID_INPUT', 'invite_invalid')
      const { ct, ss } = prov.xwingEncapsulate(fromB64u(b.kem_pk as string))
      const st = { enroll_id: this.id('enr'), challenge: b64u(prov.randomBytes(32)), xwing_ct: b64u(ct), user: { user_id, name: user_id, roles: ['employee'] }, directory_epoch: this.epoch, server_time: NOW }
      this.enrolls.set(st.enroll_id, { ...b, ...st, ss })
      return ok(st)
    }
    if (p === '/api/v1/enroll/finish') {
      const b = json()
      const e = this.enrolls.get(b.enroll_id as string)!
      const t = enrolTranscript({ challenge: e.challenge as string, device_name: e.device_name as string, directory_epoch: e.directory_epoch as number, enroll_id: e.enroll_id as string, kem_pk: e.kem_pk as string, server_time: NOW, sig_pk: e.sig_pk as string, user_id: (e.user as { user_id: string }).user_id, xwing_ct: e.xwing_ct as string })
      const kec = await deriveEnrolConfirmKey(e.ss as Uint8Array, fromB64u(e.challenge as string))
      const sigOk = verifyDevice(fromB64u(e.sig_pk as string), 'enroll', t, fromB64u(b.signature as string))
      if (!sigOk || b64u(await prov.hmacSha384(kec, t)) !== b.key_confirm) return err(400, 'QG_BAD_SIGNATURE', 'proof_failed')
      this.bump()
      const cert = { suite: 'QG-1' as const, device_id: this.id('dev'), user_id: (e.user as { user_id: string }).user_id, name: e.device_name as string, kem_pk: e.kem_pk as string, sig_pk: e.sig_pk as string, created_at: NOW, expires_at: '2027-11-26T12:00:00.000Z', directory_epoch: this.epoch }
      this.certs.push(cert)
      this.publish()
      return ok({ certificate: this.sign(cert, 'certificate'), directory: this.directory })
    }
    if (p === '/api/v1/session/start') {
      const b = json()
      const cert = this.certs.find((c) => c.device_id === b.device_id)!
      const { ct, ss } = prov.xwingEncapsulate(fromB64u(cert.kem_pk))
      const st = { start_id: this.id('sst'), challenge: b64u(prov.randomBytes(32)), xwing_ct: b64u(ct), directory_epoch: this.epoch, server_time: NOW }
      this.starts.set(st.start_id, { device_id: cert.device_id, ss, challenge: st.challenge, transcript: sessionTranscript({ ...st, device_id: cert.device_id }) })
      return ok(st)
    }
    if (p === '/api/v1/session/finish') {
      const b = json()
      const s = this.starts.get(b.start_id as string)!
      const cert = this.certs.find((c) => c.device_id === s.device_id)!
      const k = await deriveSessionKeys(s.ss, fromB64u(s.challenge))
      if (!verifyDevice(fromB64u(cert.sig_pk), 'session', s.transcript, fromB64u(b.signature as string)) || b64u(await prov.hmacSha384(k.confirm, s.transcript)) !== b.key_confirm) return err(400, 'QG_BAD_SIGNATURE')
      const sid = this.id('ses')
      this.sessions.set(sid, { mac: k.mac, last: 0, device_id: cert.device_id })
      return ok({ session_id: sid, expires_at: NOW, hard_expires_at: NOW, user: { user_id: cert.user_id, name: cert.user_id, roles: ['employee'], status: 'active' }, device: { device_id: cert.device_id, name: cert.name }, directory_epoch: this.epoch, first_session: true })
    }
    if (p === '/healthz') return ok({ status: 'ok' })

    // ---- authenticated (SUITE.md 6 checks in order) ----
    const s = this.sessions.get(headers.get('QG-Session') ?? '')
    if (!s) return err(401, 'QG_NO_SESSION')
    const seq = Number(headers.get('QG-Seq'))
    const expected = b64u(await prov.hmacSha384(s.mac, await macInput(method, path, seq, body)))
    if (expected !== headers.get('QG-MAC')) return err(401, 'QG_BAD_MAC')
    if (!(seq > s.last)) {
      this.sessions.delete(headers.get('QG-Session')!)
      return err(401, 'QG_REPLAY')
    }
    s.last = seq
    if (this.revokeAll) return err(403, 'QG_DENY_REVOKED')
    this.seqLog.push(seq)
    await new Promise((r) => setTimeout(r, Math.random() * 3))

    if (p === '/api/v1/session/end') return ok(null, 204)
    if (p === '/api/v1/files' && method === 'POST') {
      const b = json()
      const id = this.id('fil')
      this.files.set(id, { name: b.name as string, classification: b.classification as T.Classification, size: b.size_bytes as number, chunk_count: b.chunk_count as number, chunks: new Map(), wraps: new Map() })
      return ok({ file_id: id, version: 1 })
    }
    if (p === '/api/v1/files' && method === 'GET') return ok({ items: [...this.files.entries()].map(([id, f]) => this.file(f, id)), next_before: null })
    const m = /^\/api\/v1\/files\/([^/]+)(?:\/(.*))?$/.exec(p)
    if (m) {
      const f = this.files.get(m[1])
      if (!f) return err(404, 'QG_NOT_FOUND')
      const rest = m[2] ?? ''
      let mm: RegExpExecArray | null
      if (!rest && method === 'GET') return ok({ ...this.file(f, m[1]), versions: [], activity: [] })
      if ((mm = /^versions\/1\/chunks\/(\d+)$/.exec(rest))) {
        f.chunks.set(Number(mm[1]), body.slice())
        return ok(null, 204)
      }
      if (rest === 'versions/1/commit' && this.staleCommits > 0) {
        // SUITE.md 8.4: the server moved on; the client refetches the directory and builds again.
        this.staleCommits--
        this.bump()
        return err(409, 'QG_STALE_EPOCH', 'stale_epoch')
      }
      if (rest === 'versions/1/commit') {
        const b = json() as { manifest: Manifest; manifest_sig: string; wraps: { device_id: string; xwing_ct: string; wrapped_dek: string }[]; recovery_wrap?: unknown }
        this.commits.push(b)
        const signer = this.certs.find((c) => c.device_id === s.device_id)!
        if (!verifyManifest(fromB64u(signer.sig_pk), b.manifest, b.manifest_sig)) return err(400, 'QG_BAD_SIGNATURE')
        const h = prov.sha256Stream()
        for (let i = 0; i < f.chunk_count; i++) h.update(f.chunks.get(i)!)
        if (b64u(h.digest()) !== b.manifest.ciphertext_sha256) return err(400, 'QG_INVALID_INPUT', 'ciphertext_mismatch')
        if (JSON.stringify(b.wraps.map((w) => w.device_id).sort()) !== JSON.stringify(b.manifest.recipients) ) return err(400, 'QG_INVALID_INPUT')
        // spec/API.md 6: recovery_wrap required once a recovery_pk is published, absent before.
        if (this.recoveryPk && !b.recovery_wrap) return err(400, 'QG_INVALID_INPUT', 'recovery_wrap_required')
        if (!this.recoveryPk && 'recovery_wrap' in b) return err(400, 'QG_INVALID_INPUT', 'no_recovery_key')
        Object.assign(f, { manifest: b.manifest, manifest_sig: b.manifest_sig, signer: s.device_id })
        for (const w of b.wraps) f.wraps.set(w.device_id, { xwing_ct: w.xwing_ct, wrapped_dek: w.wrapped_dek, epoch: b.manifest.directory_epoch })
        return ok({ file: this.file(f, m[1]), receipt_id: 'rcp_commit' })
      }
      if (rest === 'slot') {
        const w = f.wraps.get(s.device_id)
        if (!w) return err(404, 'QG_NOT_FOUND')
        this.slotsReleased++
        this.lease = `lse_${this.slotsReleased}`
        return ok({ slot_id: 'slt_x', file_id: m[1], version: 1, device_id: s.device_id, wrap_epoch: w.epoch, inner_wrap: { xwing_ct: w.xwing_ct, wrapped_dek: w.wrapped_dek }, manifest: f.manifest, manifest_sig: f.manifest_sig, signer_device_id: f.signer, lease: { lease_id: this.lease, expires_at: NOW }, receipt_id: 'rcp_slot' })
      }
      if ((mm = /^chunks\/(\d+)$/.exec(rest))) {
        if (Number(mm[1]) === this.expireLeaseAtChunk) {
          this.expireLeaseAtChunk = -1
          this.lease = 'lse_expired'
        }
        if (headers.get('QG-Lease') !== this.lease) return err(403, 'QG_LEASE_EXPIRED')
        const c = f.chunks.get(Number(mm[1]))!.slice()
        if (Number(mm[1]) === this.tamperChunk) c[c.length - 1] ^= 1
        return new Response(c, { status: 200 })
      }
      if (rest === 'share') {
        const b = json() as { share: ShareStatement; share_sig: string; wraps: { device_id: string; xwing_ct: string; wrapped_dek: string }[] }
        const signer = this.certs.find((c) => c.device_id === s.device_id)!
        if (!verifyShare(fromB64u(signer.sig_pk), b.share, b.share_sig)) return err(400, 'QG_BAD_SIGNATURE')
        for (const w of b.wraps) f.wraps.set(w.device_id, { xwing_ct: w.xwing_ct, wrapped_dek: w.wrapped_dek, epoch: b.share.directory_epoch })
        return ok({ file: this.file(f, m[1]), receipt_id: 'rcp_share' })
      }
    }
    const me = this.certs.find((c) => c.device_id === s.device_id)!
    if (p === '/api/v1/messages' && method === 'POST') {
      // backend/qg/api/messages.py: signature over the statement of every envelope, recipients active.
      const b = json() as { to_user_id: string; envelopes: MessageEnvelope[]; signature: string }
      if (!verifyDevice(fromB64u(me.sig_pk), 'message', messageStatement(b.to_user_id, b.envelopes), fromB64u(b.signature))) return err(400, 'QG_BAD_SIGNATURE')
      const message_id = this.id('msg')
      this.messages.push({ message_id, from: { user_id: me.user_id, name: me.user_id, device_id: me.device_id }, to_user_id: b.to_user_id, envelopes: b.envelopes, signature: b.signature })
      return ok({ message_id })
    }
    if (p === '/api/v1/messages' && method === 'GET') {
      const items = this.messages.flatMap((m) => {
        const e = m.envelopes.find((x) => x.device_id === s.device_id)
        return e ? [{ message_id: m.message_id, from: m.from, sent_at: NOW, envelope: { xwing_ct: e.xwing_ct, ciphertext: e.ciphertext }, signature: m.signature }] : []
      })
      return ok({ items, next_before: null })
    }
    if (p === '/api/v1/changes' && method === 'POST') {
      // backend/qg/api/changes.py: the requester's signature over canon(change).
      const b = json() as { change: Record<string, unknown>; signature: string }
      if (!verifyDevice(fromB64u(me.sig_pk), 'change', canon(b.change), fromB64u(b.signature))) return err(400, 'QG_BAD_SIGNATURE')
      const c = { id: this.id('chg'), type: b.change.type, target_user: { user_id: b.change.target_user_id, name: '' }, role: b.change.role, file_id: b.change.file_id, reason: b.change.reason, requested_by: { user_id: me.user_id, name: '', device_id: me.device_id }, requested_at: NOW, status: 'pending', approvals: [], approvals_required: 1, change: b.change, change_hash: await changeHash(b.change), signature: b.signature } as T.Change
      this.changes.push(c)
      return ok(c)
    }
    if (p === '/api/v1/changes' && method === 'GET') return ok({ items: this.changes, next_before: null })
    const cm = /^\/api\/v1\/changes\/([^/]+)\/approve$/.exec(p)
    if (cm) {
      const c = this.changes.find((x) => x.id === cm[1])
      if (!c) return err(404, 'QG_NOT_FOUND')
      const b = json() as { signature: string }
      if (!verifyDevice(fromB64u(me.sig_pk), 'change', canon(approvalStatement(c.change_hash!, c.id)), fromB64u(b.signature))) return err(400, 'QG_BAD_SIGNATURE')
      c.status = 'applied'
      return ok(c)
    }
    return err(404, 'QG_NOT_FOUND')
  }
}

function makeFile(bytes: Uint8Array, name: string): File {
  return new File([bytes as Uint8Array<ArrayBuffer>], name)
}

describe('real client against a fake QG-1 server', () => {
  it('enrols, protects, opens, shares, and refuses tampering', async () => {
    const server = new FakeServer()
    const alice = createRealClient({ store: memoryDeviceStore(), fetch: server.fetch, derive: fastDerive })
    const steps: EnrolStep[] = []
    const dev = await alice.enrol({ code: 'code-alice', device_name: 'Alice laptop', passphrase: 'pw' }, (s) => steps.push(s))
    expect(steps).toEqual(['generating_keys', 'proving_possession', 'certificate_issued', 'sealing_keystore', 'session_started'])
    expect(alice.getState().kind).toBe('unlocked')
    expect(dev.user_id).toBe('usr_alice')

    // 2 MiB + 5 bytes: three chunks
    const data = prov.randomBytes(2 * 1048576 + 5)
    const progress: ProtectProgress[] = []
    const res = await alice.protectFile({ file: makeFile(data, 'plan.pdf'), classification: 'restricted', recipient_user_ids: [] }, (p) => progress.push(p))
    expect(res.receipt_id).toBe('rcp_commit')
    expect(progress.filter((p) => p.phase === 'uploading').length).toBe(3)
    expect(progress.at(-1)).toEqual({ phase: 'done', receipt_id: 'rcp_commit' })

    const op: OpenProgress[] = []
    const opened = await alice.openFile(res.file.file_id, (p) => op.push(p))
    expect(opened.verified).toBe(true)
    expect(toHex(new Uint8Array(await opened.blob.arrayBuffer()))).toBe(toHex(data))
    expect(op.map((p) => p.phase)).toEqual(['requesting', 'released', 'unwrapped', 'decrypting', 'decrypting', 'decrypting', 'done'])

    // parallel calls still arrive with strictly increasing QG-Seq
    await Promise.all([alice.listFiles(), alice.listFiles(), alice.getFile(res.file.file_id), alice.listFiles()])
    expect(server.seqLog).toEqual([...server.seqLog].sort((a, b) => a - b))
    expect(new Set(server.seqLog).size).toBe(server.seqLog.length)

    // Bob enrols; Alice shares; Bob opens
    const bob = createRealClient({ store: memoryDeviceStore(), fetch: server.fetch, derive: fastDerive })
    await bob.enrol({ code: 'code-bob', device_name: 'Bob phone', passphrase: 'pw2' })
    await expect(bob.openFile(res.file.file_id)).rejects.toMatchObject({ code: 'QG_NOT_FOUND' })
    const shared = await alice.shareFile(res.file.file_id, ['usr_bob'])
    expect(shared.receipt_id).toBe('rcp_share')
    const bobOpened = await bob.openFile(res.file.file_id)
    expect(toHex(new Uint8Array(await bobOpened.blob.arrayBuffer()))).toBe(toHex(data))

    // a flipped bit in a stored chunk is caught on this device
    server.tamperChunk = 1
    await expect(alice.openFile(res.file.file_id)).rejects.toMatchObject({ code: 'QG_LOCAL_INTEGRITY' })
    server.tamperChunk = -1

    // lock zeroes keys; unlock with the wrong passphrase fails locally; the right one starts a new session
    alice.lock()
    expect(alice.getState().kind).toBe('locked')
    await expect(alice.listFiles()).rejects.toMatchObject({ code: 'QG_NO_SESSION' })
    await expect(alice.unlock('nope')).rejects.toMatchObject({ code: 'QG_LOCAL_PASSPHRASE' })
    await alice.unlock('pw')
    expect(alice.getState().kind).toBe('unlocked')
    expect((await alice.listFiles()).length).toBe(1)
  })

  it('opens a share wrap with the slot wrap_epoch, and sends no recovery wrap before a kit exists', async () => {
    const server = new FakeServer()
    server.recoveryPk = null
    server.publish()
    const alice = createRealClient({ store: memoryDeviceStore(), fetch: server.fetch, derive: fastDerive })
    await alice.enrol({ code: 'code-alice', device_name: 'A', passphrase: 'pw' })
    const res = await alice.protectFile({ file: makeFile(utf8('no kit yet'), 'a.txt'), classification: 'internal', recipient_user_ids: [] })
    expect('recovery_wrap' in server.commits[0]!).toBe(false)
    // several epochs pass before the share: the wrap is bound to the share statement's epoch
    server.bump()
    server.bump()
    const bob = createRealClient({ store: memoryDeviceStore(), fetch: server.fetch, derive: fastDerive })
    await bob.enrol({ code: 'code-bob', device_name: 'B', passphrase: 'pw' })
    await alice.shareFile(res.file.file_id, ['usr_bob'])
    const f = server.files.get(res.file.file_id)!
    const bobDevice = [...f.wraps.entries()].find(([d]) => d !== server.certs[0]!.device_id)!
    expect(bobDevice[1].epoch).toBeGreaterThan(f.manifest!.directory_epoch)
    expect(fromUtf8(new Uint8Array(await (await bob.openFile(res.file.file_id)).blob.arrayBuffer()))).toBe('no kit yet')
    // once a kit is published, commits carry the recovery wrap
    server.recoveryPk = b64u(server.recovery.publicKey)
    server.bump()
    await alice.protectFile({ file: makeFile(utf8('with kit'), 'b.txt'), classification: 'internal', recipient_user_ids: [] })
    expect(server.commits[1]!.recovery_wrap).toBeTruthy()
  })

  it('renews an expired lease mid-download for the same version, and retries a commit once on QG_STALE_EPOCH', async () => {
    const server = new FakeServer()
    const alice = createRealClient({ store: memoryDeviceStore(), fetch: server.fetch, derive: fastDerive })
    await alice.enrol({ code: 'code-alice', device_name: 'A', passphrase: 'pw' })
    server.staleCommits = 1
    const epochBefore = server.epoch
    const data = prov.randomBytes(2 * 1048576 + 9)
    const res = await alice.protectFile({ file: makeFile(data, 'long.bin'), classification: 'internal', recipient_user_ids: [] })
    expect(server.epoch).toBe(epochBefore + 1)
    expect(server.files.get(res.file.file_id)!.manifest!.directory_epoch).toBe(server.epoch)
    server.expireLeaseAtChunk = 2
    const opened = await alice.openFile(res.file.file_id)
    expect(toHex(new Uint8Array(await opened.blob.arrayBuffer()))).toBe(toHex(data))
    expect(server.slotsReleased).toBe(2)
    // a second stale answer in a row is not retried forever
    server.staleCommits = 2
    await expect(alice.protectFile({ file: makeFile(utf8('x'), 'x.txt'), classification: 'internal', recipient_user_ids: [] })).rejects.toMatchObject({ code: 'QG_STALE_EPOCH' })
  })

  it('messages: the recipient decrypts the server-shaped envelope and checks the signature', async () => {
    const server = new FakeServer()
    const alice = createRealClient({ store: memoryDeviceStore(), fetch: server.fetch, derive: fastDerive })
    const bob = createRealClient({ store: memoryDeviceStore(), fetch: server.fetch, derive: fastDerive })
    await alice.enrol({ code: 'code-alice', device_name: 'A', passphrase: 'pw' })
    await bob.enrol({ code: 'code-bob', device_name: 'B', passphrase: 'pw' })
    await alice.sendMessage('usr_bob', 'the freezer alarm is fixed')
    const got = await bob.listMessages()
    expect(got).toHaveLength(1)
    expect(got[0]).toMatchObject({ text: 'the freezer alarm is fixed', verified: true, from: { user_id: 'usr_alice' } })
    // a signature that does not cover the envelope is not marked verified
    server.messages[0]!.signature = server.messages[0]!.signature.slice(0, -4) + 'AAAA'
    expect((await bob.listMessages())[0]).toMatchObject({ text: 'the freezer alarm is fixed', verified: false })
  })

  it('changes: request signs the statement, approval signs the recomputed change_hash', async () => {
    const server = new FakeServer()
    const alice = createRealClient({ store: memoryDeviceStore(), fetch: server.fetch, derive: fastDerive })
    const bob = createRealClient({ store: memoryDeviceStore(), fetch: server.fetch, derive: fastDerive })
    await alice.enrol({ code: 'code-alice', device_name: 'A', passphrase: 'pw' })
    await bob.enrol({ code: 'code-bob', device_name: 'B', passphrase: 'pw' })
    const c = await alice.requestChange({ type: 'role_grant', target_user_id: 'usr_bob', role: 'operator', reason: 'on call' })
    expect(c.change).toMatchObject({ type: 'role_grant', role: 'operator', file_id: null, suite: 'QG-1', directory_epoch: server.epoch })
    // a statement that does not match the change shown is refused before signing
    const real = server.changes[0]!
    server.changes[0] = { ...real, role: 'auditor' }
    await expect(bob.approveChange(c.id)).rejects.toMatchObject({ code: 'QG_LOCAL_INTEGRITY', reason: 'change_mismatch' })
    server.changes[0] = { ...real, change_hash: b64u(new Uint8Array(32)) }
    await expect(bob.approveChange(c.id)).rejects.toMatchObject({ code: 'QG_LOCAL_INTEGRITY', reason: 'change_hash' })
    server.changes[0] = real
    expect((await bob.approveChange(c.id)).status).toBe('applied')
  })

  it('refuses a server that swaps its keys, and locks on QG_NO_SESSION', async () => {
    const server = new FakeServer()
    const store = memoryDeviceStore()
    const c = createRealClient({ store, fetch: server.fetch, derive: fastDerive })
    await c.enrol({ code: 'code-alice', device_name: 'A', passphrase: 'pw' })
    server.sessions.clear()
    await expect(c.listFiles()).rejects.toBeInstanceOf(QgError)
    expect(c.getState().kind).toBe('locked')
    server.edSeed = prov.randomBytes(32)
    server.keys = { ...server.keys, ed25519_pk: b64u(ed25519.getPublicKey(server.edSeed)) }
    await expect(c.unlock('pw')).rejects.toMatchObject({ code: 'QG_LOCAL_INTEGRITY', reason: 'server_key_changed' })
    server.publish()
    await expect(c.directory()).rejects.toMatchObject({ code: 'QG_LOCAL_INTEGRITY' })
  })

  it('cancels before upload and moves to revoked on QG_DENY_REVOKED', async () => {
    const server = new FakeServer()
    const c = createRealClient({ store: memoryDeviceStore(), fetch: server.fetch, derive: fastDerive })
    await c.enrol({ code: 'code-alice', device_name: 'A', passphrase: 'pw' })
    const ac = new AbortController()
    ac.abort()
    await expect(c.protectFile({ file: makeFile(utf8('x'), 'x.txt'), classification: 'internal', recipient_user_ids: [] }, undefined, ac.signal)).rejects.toMatchObject({ code: 'QG_LOCAL_CANCELLED' })
    server.revokeAll = true
    await expect(c.listFiles()).rejects.toMatchObject({ code: 'QG_DENY_REVOKED' })
    await new Promise((r) => setTimeout(r, 0))
    expect(c.getState().kind).toBe('revoked')
    await expect(c.unlock('pw')).rejects.toMatchObject({ code: 'QG_DENY_REVOKED' })
  })
})
