// File flows of the real client: protect (SUITE.md 7.1-7.4), open (7.6), share (7.5) and the
// re-key / catch-up work queue (spec/API.md 6).
import { QgError, type OpenedFile, type OpenProgress, type ProtectProgress, type WorkProgress } from '../client'
import type * as T from '../types'
import { b64u, fromB64u } from '../../crypto/b64u'
import { wipe } from '../../crypto/bytes'
import {
  buildManifest,
  buildShare,
  chunkCount,
  chunkRange,
  decryptChunk,
  encryptChunk,
  signManifest,
  signShare,
  unwrapDekAny,
  verifyManifest,
  wrapBinding,
  wrapDek,
  type InnerWrap,
  type Manifest,
  type WrapBinding,
} from '../../crypto/envelope'
import { RECOVERY_DEVICE_ID } from '../../crypto/suite'
import {
  activeDevices,
  fetchMeta,
  findDevice,
  integrity,
  requireUnlocked,
  seg,
  throwIfAborted,
  trustedDirectory,
  trustedDirectoryAt,
  userName,
  yieldToLoop,
  type Ctx,
} from './context'

interface Slot {
  slot_id: string
  file_id: string
  version: number
  device_id: string
  inner_wrap: InnerWrap
  manifest: Manifest
  manifest_sig: string
  signer_device_id: string
  lease: { lease_id: string; expires_at: string }
  receipt_id: string
}

interface WrapOut {
  device_id: string
  xwing_ct: string
  wrapped_dek: string
}

const filePath = (id: string) => `/api/v1/files/${seg(id)}`

/** Retries `fn` once after refetching the directory when the server answers QG_STALE_EPOCH (SUITE.md 8.4). */
async function withEpochRetry<R>(ctx: Ctx, fn: (dir: T.Directory) => Promise<R>): Promise<R> {
  const dir = await trustedDirectory(ctx)
  try {
    return await fn(dir)
  } catch (e) {
    if (!(e instanceof QgError) || e.code !== 'QG_STALE_EPOCH') throw e
    return fn(await trustedDirectory(ctx))
  }
}

/** SUITE.md 7.2: one inner wrap per recipient device, with progress. */
async function wrapForDevices(ctx: Ctx, dek: Uint8Array, fileId: string, version: number, epoch: number, devices: T.Certificate[], onWrap?: (d: T.Certificate, done: number) => void): Promise<WrapOut[]> {
  const out: WrapOut[] = []
  for (const d of devices) {
    const w = await wrapDek(fromB64u(d.kem_pk, 1216), dek, wrapBinding(fileId, version, d.device_id, epoch), ctx.prov)
    out.push({ device_id: d.device_id, ...w })
    onWrap?.(d, out.length)
  }
  return out
}

/** SUITE.md 7.2: the recovery wrap under the directory's recovery_pk. */
function recoveryWrap(ctx: Ctx, dek: Uint8Array, fileId: string, version: number, dir: T.Directory): Promise<InnerWrap> {
  return wrapDek(fromB64u(dir.recovery_pk, 1216), dek, wrapBinding(fileId, version, RECOVERY_DEVICE_ID, dir.epoch), ctx.prov)
}

/** SUITE.md 7.4: wrap for every recipient, sign the manifest and commit; retried once on a stale epoch. */
async function commitVersion(
  ctx: Ctx,
  x: { fileId: string; version: number; dek: Uint8Array; classification: T.Classification; chunkCount: number; hash: string },
  pickDevices: (dir: T.Directory) => T.Certificate[],
  onProgress?: (p: ProtectProgress) => void,
): Promise<{ file: T.FileItem; receipt_id: string }> {
  return withEpochRetry(ctx, async (dir) => {
    const devices = pickDevices(dir)
    if (devices.length === 0) throw new QgError({ code: 'QG_INVALID_INPUT', message: 'No active device can receive this file.', reason: 'no_recipients' })
    const wraps = await wrapForDevices(ctx, x.dek, x.fileId, x.version, dir.epoch, devices, (d, done) =>
      onProgress?.({ phase: 'wrapping', device_id: d.device_id, device_name: d.name, done, total: devices.length }),
    )
    const recovery = await recoveryWrap(ctx, x.dek, x.fileId, x.version, dir)
    const manifest = buildManifest({
      chunk_count: x.chunkCount, ciphertext_sha256: x.hash, classification: x.classification, directory_epoch: dir.epoch,
      file_id: x.fileId, version: x.version, recipients: devices.map((d) => d.device_id),
    })
    const manifest_sig = signManifest(ctx.keyring.sigSeed(), manifest, ctx.prov)
    onProgress?.({ phase: 'committing' })
    const { data } = await ctx.http.call<{ file: T.FileItem; receipt_id: string }>('POST', `${filePath(x.fileId)}/versions/${x.version}/commit`, {
      json: { manifest, manifest_sig, wraps, recovery_wrap: recovery },
    })
    return data
  })
}

/** Chosen people's active devices plus all of the caller's own active devices (SUITE.md 7.4). */
function protectRecipients(dir: T.Directory, ownUserId: string, userIds: string[], max: number): T.Certificate[] {
  const devices = activeDevices(dir, [ownUserId, ...userIds])
  if (devices.length > max) throw new QgError({ code: 'QG_INVALID_INPUT', message: `At most ${max} devices can hold a file.`, reason: 'too_many_recipients' })
  return devices
}

/** SUITE.md 7.1-7.4: encrypt in 1 MiB chunks, upload, wrap, sign and commit. */
export async function protectFile(
  ctx: Ctx,
  input: { file: File; classification: T.Classification; recipient_user_ids: string[] },
  onProgress?: (p: ProtectProgress) => void,
  signal?: AbortSignal,
): Promise<{ file: T.FileItem; receipt_id: string }> {
  const { stored } = requireUnlocked(ctx)
  const meta = await fetchMeta(ctx)
  const size = input.file.size
  if (size > meta.limits.max_file_bytes) throw new QgError({ code: 'QG_INVALID_INPUT', message: 'This file is larger than the server allows.', reason: 'too_large' })
  throwIfAborted(signal)
  const chunks = chunkCount(size)
  const { data: created } = await ctx.http.call<{ file_id: string; version: number }>('POST', '/api/v1/files', {
    json: { name: input.file.name, classification: input.classification, size_bytes: size, chunk_count: chunks },
    signal,
  })
  const dek = ctx.prov.randomBytes(32)
  try {
    const hash = await uploadChunks(ctx, created.file_id, created.version, chunks, dek, (i) => readSlice(input.file, i), onProgress, signal)
    throwIfAborted(signal)
    const result = await commitVersion(
      ctx,
      { fileId: created.file_id, version: created.version, dek, classification: input.classification, chunkCount: chunks, hash },
      (dir) => protectRecipients(dir, stored.device.user_id, input.recipient_user_ids, meta.limits.max_recipients),
      onProgress,
    )
    onProgress?.({ phase: 'done', receipt_id: result.receipt_id })
    return result
  } catch (e) {
    if (e instanceof QgError && e.code === 'QG_LOCAL_CANCELLED') {
      void ctx.http.call('DELETE', filePath(created.file_id)).catch(() => undefined)
    }
    throw e
  } finally {
    wipe(dek)
  }
}

async function readSlice(file: Blob, i: number): Promise<Uint8Array> {
  const [a, b] = chunkRange(file.size, i)
  return new Uint8Array(await file.slice(a, b).arrayBuffer())
}

/** SUITE.md 7.1: encrypt and PUT each chunk, yielding between chunks; returns ciphertext_sha256. */
async function uploadChunks(
  ctx: Ctx,
  fileId: string,
  version: number,
  chunks: number,
  dek: Uint8Array,
  plaintextOf: (i: number) => Promise<Uint8Array>,
  onProgress?: (p: ProtectProgress) => void,
  signal?: AbortSignal,
): Promise<string> {
  const prefix = ctx.prov.randomBytes(8)
  const hash = ctx.prov.sha256Stream()
  const cc = { dek, fileId, version, chunkCount: chunks }
  for (let i = 0; i < chunks; i++) {
    throwIfAborted(signal)
    const pt = await plaintextOf(i)
    const blob = await encryptChunk(cc, prefix, i, pt, ctx.prov)
    wipe(pt)
    hash.update(blob)
    onProgress?.({ phase: 'encrypting', chunk: i + 1, chunks })
    await ctx.http.call<null>('PUT', `${filePath(fileId)}/versions/${version}/chunks/${i}`, { bytes: blob, signal })
    onProgress?.({ phase: 'uploading', chunk: i + 1, chunks })
    await yieldToLoop()
  }
  return b64u(hash.digest())
}

// ---- opening -----------------------------------------------------------------------------------

/** SUITE.md 7.6: the signer's sig_pk from a directory this client verified (current, else the manifest's epoch). */
async function signerKey(ctx: Ctx, signerId: string, manifestEpoch: number): Promise<Uint8Array> {
  const current = await trustedDirectory(ctx)
  let cert = findDevice(current, signerId)
  if (!cert) cert = findDevice(await trustedDirectoryAt(ctx, manifestEpoch), signerId)
  if (!cert) throw integrity('unknown_signer')
  const rev = current.revoked.find((r) => r.device_id === signerId)
  if (rev && rev.epoch <= manifestEpoch) throw integrity('revoked_signer')
  return fromB64u(cert.sig_pk, 1952)
}

/** SUITE.md 7.2/7.6: bindings to try: the manifest's epoch, then later epochs up to the newest seen (share wraps). */
function wrapCandidates(ctx: Ctx, fileId: string, m: Manifest, deviceId: string): WrapBinding[] {
  const newest = Math.max(ctx.stored?.highest_epoch ?? 0, ...ctx.directories.keys(), m.directory_epoch)
  const out: WrapBinding[] = []
  for (let e = m.directory_epoch; e <= newest && out.length < 4096; e++) out.push(wrapBinding(fileId, m.version, deviceId, e))
  return out
}

/** GET slot, verify the manifest, unwrap the DEK (SUITE.md 7.6). The caller wipes the DEK. */
async function openSlot(ctx: Ctx, fileId: string, signal?: AbortSignal): Promise<{ slot: Slot; dek: Uint8Array }> {
  const { stored } = requireUnlocked(ctx)
  const { data: slot } = await ctx.http.call<Slot>('GET', `${filePath(fileId)}/slot`, { signal })
  const m = slot.manifest
  if (!m || m.file_id !== fileId || m.version !== slot.version || slot.device_id !== stored.device.device_id) throw integrity('slot_mismatch')
  const pk = await signerKey(ctx, slot.signer_device_id, m.directory_epoch)
  if (!verifyManifest(pk, m, slot.manifest_sig, ctx.prov)) throw integrity('manifest_signature')
  try {
    const { dek } = await unwrapDekAny(ctx.keyring.kemSeed(), slot.inner_wrap, wrapCandidates(ctx, fileId, m, stored.device.device_id), ctx.prov)
    return { slot, dek }
  } catch {
    throw integrity('wrap')
  }
}

/** Downloads chunk i with the lease; renews the lease once per chunk if it expired (same version only). */
async function fetchChunk(ctx: Ctx, fileId: string, i: number, lease: { current: Slot }, signal?: AbortSignal): Promise<Uint8Array> {
  const get = () => ctx.http.call<Uint8Array>('GET', `${filePath(fileId)}/chunks/${i}`, { headers: { 'QG-Lease': lease.current.lease.lease_id }, expect: 'bytes', signal })
  try {
    return (await get()).data
  } catch (e) {
    if (!(e instanceof QgError) || e.code !== 'QG_LEASE_EXPIRED') throw e
    const { data: renewed } = await ctx.http.call<Slot>('GET', `${filePath(fileId)}/slot`, { signal })
    if (renewed.version !== lease.current.version || renewed.manifest.ciphertext_sha256 !== lease.current.manifest.ciphertext_sha256) throw e
    lease.current = renewed
    return (await get()).data
  }
}

/** Streams and decrypts every chunk of the slot's version, checking ciphertext_sha256 at the end. */
async function decryptAll(ctx: Ctx, fileId: string, slot: Slot, dek: Uint8Array, onChunk: (pt: Uint8Array, i: number, n: number) => Promise<void> | void, signal?: AbortSignal): Promise<void> {
  const m = slot.manifest
  const cc = { dek, fileId, version: m.version, chunkCount: m.chunk_count }
  const hash = ctx.prov.sha256Stream()
  const lease = { current: slot }
  let prefix: Uint8Array | null = null
  for (let i = 0; i < m.chunk_count; i++) {
    throwIfAborted(signal)
    const blob = await fetchChunk(ctx, fileId, i, lease, signal)
    hash.update(blob)
    let r: { plaintext: Uint8Array; prefix: Uint8Array }
    try {
      r = await decryptChunk(cc, prefix, i, blob, ctx.prov)
    } catch {
      throw integrity('chunk', `Chunk ${i + 1} failed to verify.`)
    }
    prefix = r.prefix
    await onChunk(r.plaintext, i, m.chunk_count)
    await yieldToLoop()
  }
  if (b64u(hash.digest()) !== m.ciphertext_sha256) throw integrity('ciphertext_hash')
}

/** SUITE.md 7.6: slot -> verify manifest -> unwrap -> stream chunks with the lease -> verify -> Blob. */
export async function openFile(ctx: Ctx, fileId: string, onProgress?: (p: OpenProgress) => void, signal?: AbortSignal): Promise<OpenedFile> {
  requireUnlocked(ctx)
  onProgress?.({ phase: 'requesting' })
  const { data: info } = await ctx.http.call<T.FileDetail>('GET', filePath(fileId), { signal })
  const { slot, dek } = await openSlot(ctx, fileId, signal)
  onProgress?.({ phase: 'released', receipt_id: slot.receipt_id })
  onProgress?.({ phase: 'unwrapped' })
  const parts: Uint8Array<ArrayBuffer>[] = []
  try {
    await decryptAll(ctx, fileId, slot, dek, (pt, i, n) => {
      parts.push(pt as Uint8Array<ArrayBuffer>)
      onProgress?.({ phase: 'decrypting', chunk: i + 1, chunks: n })
    }, signal)
  } catch (e) {
    for (const p of parts) wipe(p)
    throw e
  } finally {
    wipe(dek)
  }
  const blob = new Blob(parts, { type: 'application/octet-stream' })
  for (const p of parts) wipe(p)
  onProgress?.({ phase: 'done' })
  return { blob, name: info.name, receipt_id: slot.receipt_id, verified: true }
}

// ---- sharing -----------------------------------------------------------------------------------

/** SUITE.md 7.5: wrap the current version's DEK for new devices, sign the share statement, post it. */
async function shareToDevices(ctx: Ctx, fileId: string, pick: (dir: T.Directory, version: number) => T.Certificate[]): Promise<{ file: T.FileItem; receipt_id: string }> {
  const { slot, dek } = await openSlot(ctx, fileId)
  try {
    return await withEpochRetry(ctx, async (dir) => {
      const devices = pick(dir, slot.version)
      if (devices.length === 0) throw new QgError({ code: 'QG_CONFLICT', message: 'Everyone chosen can already open this file.', reason: 'no_new_devices' })
      const share = buildShare(fileId, slot.version, devices.map((d) => d.device_id), dir.epoch)
      const wraps = await wrapForDevices(ctx, dek, fileId, slot.version, dir.epoch, devices)
      const share_sig = signShare(ctx.keyring.sigSeed(), share, ctx.prov)
      const { data } = await ctx.http.call<{ file: T.FileItem; receipt_id: string }>('POST', `${filePath(fileId)}/share`, { json: { share, share_sig, wraps } })
      return data
    })
  } finally {
    wipe(dek)
  }
}

/** Shares with the active devices of the given people that do not hold a wrap yet. */
export async function shareFile(ctx: Ctx, fileId: string, userIds: string[]): Promise<{ file: T.FileItem; receipt_id: string }> {
  requireUnlocked(ctx)
  const { data: file } = await ctx.http.call<T.FileDetail>('GET', filePath(fileId))
  const have = new Set(file.recipients.map((r) => r.device_id))
  return shareToDevices(ctx, fileId, (dir) => activeDevices(dir, userIds).filter((d) => !have.has(d.device_id)))
}

// ---- pending work ------------------------------------------------------------------------------

type Rekey = T.RekeyPending['rekeys'][number]

/** spec/API.md 6: decrypt the current version and re-encrypt it chunk by chunk under a new DEK for exactly `recipients`. */
async function rekeyOne(ctx: Ctx, r: Rekey, report: (chunk: number, chunks: number) => void, signal?: AbortSignal): Promise<void> {
  const { data: info } = await ctx.http.call<T.FileDetail>('GET', filePath(r.file_id), { signal })
  const { slot, dek: oldDek } = await openSlot(ctx, r.file_id, signal)
  const newDek = ctx.prov.randomBytes(32)
  try {
    const chunks = slot.manifest.chunk_count
    const { data: v } = await ctx.http.call<{ version: number }>('POST', `${filePath(r.file_id)}/versions`, {
      json: { reason: 'rekey', size_bytes: info.size_bytes, chunk_count: chunks },
      signal,
    })
    // Stream: decrypt old chunk i, then encrypt and upload new chunk i.
    const prefix = ctx.prov.randomBytes(8)
    const hash = ctx.prov.sha256Stream()
    const cc = { dek: newDek, fileId: r.file_id, version: v.version, chunkCount: chunks }
    await decryptAll(ctx, r.file_id, slot, oldDek, async (pt, i) => {
      const blob = await encryptChunk(cc, prefix, i, pt, ctx.prov)
      wipe(pt)
      hash.update(blob)
      await ctx.http.call<null>('PUT', `${filePath(r.file_id)}/versions/${v.version}/chunks/${i}`, { bytes: blob, signal })
      report(i + 1, chunks)
    }, signal)
    const wanted = new Set(r.recipients)
    await commitVersion(
      ctx,
      { fileId: r.file_id, version: v.version, dek: newDek, classification: info.classification, chunkCount: chunks, hash: b64u(hash.digest()) },
      (dir) => dir.devices.filter((d) => wanted.has(d.device_id)),
    )
  } finally {
    wipe(oldDek, newDek)
  }
}

/** spec/API.md 6: re-keys first, then catch-up shares for this person's other devices. */
export async function runPendingWork(ctx: Ctx, onProgress?: (p: WorkProgress) => void, signal?: AbortSignal): Promise<{ rekeyed: number; shared: number }> {
  requireUnlocked(ctx)
  const { data: work } = await ctx.http.call<T.RekeyPending>('GET', '/api/v1/rekey/pending', { signal })
  let rekeyed = 0
  let shared = 0
  for (const [index, r] of work.rekeys.entries()) {
    throwIfAborted(signal)
    onProgress?.({ kind: 'rekey', file_id: r.file_id, name: r.name, index, total: work.rekeys.length, chunk: 0, chunks: 0 })
    await rekeyOne(ctx, r, (chunk, chunks) => onProgress?.({ kind: 'rekey', file_id: r.file_id, name: r.name, index, total: work.rekeys.length, chunk, chunks }), signal)
    rekeyed++
  }
  const byFile = new Map<string, { name: string; devices: Set<string> }>()
  for (const s of work.shares) {
    const e = byFile.get(s.file_id) ?? { name: s.name, devices: new Set<string>() }
    e.devices.add(s.device_id)
    byFile.set(s.file_id, e)
  }
  let index = 0
  for (const [fileId, s] of byFile) {
    throwIfAborted(signal)
    onProgress?.({ kind: 'share', file_id: fileId, name: s.name, index, total: byFile.size })
    await shareToDevices(ctx, fileId, (dir) => dir.devices.filter((d) => s.devices.has(d.device_id) && activeDevices(dir, [d.user_id]).includes(d)))
    shared += s.devices.size
    index++
  }
  return { rekeyed, shared }
}

export { userName }
