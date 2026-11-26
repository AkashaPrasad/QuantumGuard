// SUITE.md 7 and 11: chunk encryption, DEK wraps, manifest, share statement and message envelopes.
import { b64u, fromB64u } from './b64u'
import { concat, ctEqual, u32be, utf8 } from './bytes'
import { canon } from './canonical'
import { XWING_CT_BYTES, XWING_PK_BYTES } from './noble'
import { getProvider, type CryptoProvider } from './provider'
import { CHUNK_BYTES, INFO, RECOVERY_DEVICE_ID, SUITE, context } from './suite'

export type Classification = 'internal' | 'confidential' | 'restricted'

export class EnvelopeError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EnvelopeError'
  }
}

const NONCE_LEN = 12
const TAG_LEN = 16
const WRAPPED_DEK_LEN = NONCE_LEN + 32 + TAG_LEN

// ---- 7.1 chunks -----------------------------------------------------------------------------

/** SUITE.md 7.1: chunk_count = max(1, ceil(size / chunk_bytes)). */
export function chunkCount(size: number): number {
  return size === 0 ? 1 : Math.ceil(size / CHUNK_BYTES)
}

/** SUITE.md 7.1: byte range of chunk i in a plaintext of `size` bytes. */
export function chunkRange(size: number, i: number): [number, number] {
  const start = i * CHUNK_BYTES
  return [start, Math.min(size, start + CHUNK_BYTES)]
}

/** SUITE.md 7.1: aad_i. */
export function chunkAad(fileId: string, version: number, index: number, isLast: boolean): Uint8Array {
  return canon({ chunk_index: index, file_id: fileId, is_last: isLast, suite: SUITE, version })
}

/** SUITE.md 7.1: nonce_i = P || u32be(i). */
export function chunkNonce(prefix: Uint8Array, index: number): Uint8Array {
  if (prefix.length !== 8) throw new EnvelopeError('nonce prefix must be 8 bytes')
  return concat(prefix, u32be(index))
}

export interface ChunkContext {
  dek: Uint8Array
  fileId: string
  version: number
  chunkCount: number
}

/** SUITE.md 7.1: C_i = nonce_i || AES-256-GCM(DEK, nonce_i, chunk_i, aad_i). */
export async function encryptChunk(ctx: ChunkContext, prefix: Uint8Array, index: number, chunk: Uint8Array, prov: CryptoProvider = getProvider()): Promise<Uint8Array> {
  if (chunk.length > CHUNK_BYTES) throw new EnvelopeError('chunk too large')
  const nonce = chunkNonce(prefix, index)
  const aad = chunkAad(ctx.fileId, ctx.version, index, index === ctx.chunkCount - 1)
  return concat(nonce, await prov.aesGcmEncrypt(ctx.dek, nonce, chunk, aad))
}

/**
 * SUITE.md 7.1 reader: checks the index suffix, the shared prefix (pass the prefix seen in chunk 0,
 * or null for chunk 0) and the is_last binding, then opens the tag. Throws at the first failure.
 * Returns the plaintext and the prefix to pass for the next chunk.
 */
export async function decryptChunk(ctx: ChunkContext, prefix: Uint8Array | null, index: number, blob: Uint8Array, prov: CryptoProvider = getProvider()): Promise<{ plaintext: Uint8Array; prefix: Uint8Array }> {
  if (index >= ctx.chunkCount || blob.length < NONCE_LEN + TAG_LEN) throw new EnvelopeError('bad chunk framing')
  const nonce = blob.subarray(0, NONCE_LEN)
  if (!ctEqual(nonce.subarray(8, 12), u32be(index))) throw new EnvelopeError('chunk out of order')
  const p = nonce.slice(0, 8)
  if (prefix && !ctEqual(prefix, p)) throw new EnvelopeError('chunk from another file')
  const aad = chunkAad(ctx.fileId, ctx.version, index, index === ctx.chunkCount - 1)
  try {
    const plaintext = await prov.aesGcmDecrypt(ctx.dek, nonce.slice(), blob.subarray(NONCE_LEN), aad)
    return { plaintext, prefix: p }
  } catch {
    throw new EnvelopeError('chunk failed authentication')
  }
}

/** SUITE.md 7.1: encrypt a whole in-memory file (tests and small files). */
export async function encryptFile(dek: Uint8Array, fileId: string, version: number, data: Uint8Array, prefix: Uint8Array, prov: CryptoProvider = getProvider()): Promise<Uint8Array[]> {
  const n = chunkCount(data.length)
  const ctx = { dek, fileId, version, chunkCount: n }
  const out: Uint8Array[] = []
  for (let i = 0; i < n; i++) {
    const [a, b] = chunkRange(data.length, i)
    out.push(await encryptChunk(ctx, prefix, i, data.subarray(a, b), prov))
  }
  return out
}

/** SUITE.md 7.1: decrypt a list of blobs; a short list is truncation and fails. */
export async function decryptFile(dek: Uint8Array, fileId: string, version: number, blobs: Uint8Array[], chunkCountDeclared: number, prov: CryptoProvider = getProvider()): Promise<Uint8Array[]> {
  const ctx = { dek, fileId, version, chunkCount: chunkCountDeclared }
  let prefix: Uint8Array | null = null
  const out: Uint8Array[] = []
  for (let i = 0; i < blobs.length; i++) {
    const r: { plaintext: Uint8Array; prefix: Uint8Array } = await decryptChunk(ctx, prefix, i, blobs[i], prov)
    prefix = r.prefix
    out.push(r.plaintext)
  }
  if (blobs.length !== chunkCountDeclared) throw new EnvelopeError('file truncated')
  return out
}

/** SUITE.md 7.1: ciphertext_sha256 over C_0 || ... || C_{n-1}. */
export function ciphertextSha256(blobs: Uint8Array[], prov: CryptoProvider = getProvider()): string {
  const h = prov.sha256Stream()
  for (const b of blobs) h.update(b)
  return b64u(h.digest())
}

// ---- 7.2 DEK wrap ---------------------------------------------------------------------------

export interface WrapBinding {
  device_id: string
  directory_epoch: number
  file_id: string
  suite: 'QG-1'
  version: number
}

export interface InnerWrap {
  xwing_ct: string
  wrapped_dek: string
}

/** SUITE.md 7.2: the binding object (its canon is the AAD). */
export function wrapBinding(fileId: string, version: number, deviceId: string, directoryEpoch: number): WrapBinding {
  return { device_id: deviceId, directory_epoch: directoryEpoch, file_id: fileId, suite: SUITE, version }
}

/** SUITE.md 3: KEK = HKDF-SHA-384(ss, empty, "QG/v1/wrap", 32). */
export function wrapKey(ss: Uint8Array, prov: CryptoProvider = getProvider()): Promise<Uint8Array> {
  return prov.hkdfSha384(ss, new Uint8Array(0), utf8(INFO.wrap), 32)
}

/** SUITE.md 7.2: wrapped_dek = n || AES-256-GCM(KEK, n, DEK, canon(binding)) from a known ss. */
export async function wrapDekWithSecret(ss: Uint8Array, dek: Uint8Array, binding: WrapBinding, nonce?: Uint8Array, prov: CryptoProvider = getProvider()): Promise<Uint8Array> {
  const n = nonce ?? prov.randomBytes(NONCE_LEN)
  const kek = await wrapKey(ss, prov)
  try {
    return concat(n, await prov.aesGcmEncrypt(kek, n, dek, canon(binding)))
  } finally {
    kek.fill(0)
  }
}

/** SUITE.md 7.2: encapsulate to the recipient and wrap the DEK under its binding. */
export async function wrapDek(kemPk: Uint8Array, dek: Uint8Array, binding: WrapBinding, prov: CryptoProvider = getProvider()): Promise<InnerWrap> {
  if (kemPk.length !== XWING_PK_BYTES) throw new EnvelopeError('bad recipient key')
  const { ct, ss } = prov.xwingEncapsulate(kemPk)
  try {
    return { xwing_ct: b64u(ct), wrapped_dek: b64u(await wrapDekWithSecret(ss, dek, binding, undefined, prov)) }
  } finally {
    ss.fill(0)
  }
}

/** SUITE.md 7.2 / 7.6: decapsulate with this device's seed and open the DEK under the binding. */
export async function unwrapDek(kemSeed: Uint8Array, wrap: InnerWrap, binding: WrapBinding, prov: CryptoProvider = getProvider()): Promise<Uint8Array> {
  let ct: Uint8Array, wrapped: Uint8Array
  try {
    ct = fromB64u(wrap.xwing_ct, XWING_CT_BYTES)
    wrapped = fromB64u(wrap.wrapped_dek, WRAPPED_DEK_LEN)
  } catch {
    throw new EnvelopeError('bad wrap')
  }
  const ss = prov.xwingDecapsulate(ct, kemSeed)
  const kek = await wrapKey(ss, prov)
  try {
    return await prov.aesGcmDecrypt(kek, wrapped.slice(0, NONCE_LEN), wrapped.subarray(NONCE_LEN), canon(binding))
  } catch {
    throw new EnvelopeError('wrap failed authentication')
  } finally {
    ss.fill(0)
    kek.fill(0)
  }
}

// ---- 7.4 manifest ---------------------------------------------------------------------------

export interface Manifest {
  chunk_count: number
  ciphertext_sha256: string
  classification: Classification
  directory_epoch: number
  file_id: string
  recipients: string[]
  suite: 'QG-1'
  version: number
}

/** SUITE.md 7.4: recipients sorted by byte value, unique, never `recovery`. */
export function sortRecipients(ids: Iterable<string>): string[] {
  const out = [...new Set(ids)]
  if (out.includes(RECOVERY_DEVICE_ID)) throw new EnvelopeError('recipients must not contain recovery')
  return out.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
}

function isSortedUnique(ids: unknown): ids is string[] {
  if (!Array.isArray(ids)) return false
  for (let i = 0; i < ids.length; i++) {
    if (typeof ids[i] !== 'string' || ids[i] === RECOVERY_DEVICE_ID) return false
    if (i > 0 && !((ids[i - 1] as string) < (ids[i] as string))) return false
  }
  return true
}

/** SUITE.md 7.4: build the manifest object. */
export function buildManifest(x: Omit<Manifest, 'suite' | 'recipients'> & { recipients: Iterable<string> }): Manifest {
  return {
    chunk_count: x.chunk_count,
    ciphertext_sha256: x.ciphertext_sha256,
    classification: x.classification,
    directory_epoch: x.directory_epoch,
    file_id: x.file_id,
    recipients: sortRecipients(x.recipients),
    suite: SUITE,
    version: x.version,
  }
}

/** SUITE.md 7.4: manifest_sig = b64u(ML-DSA.Sign(sk, canon(manifest), "QG/v1/manifest")). */
export function signManifest(sigSeed: Uint8Array, m: Manifest, prov: CryptoProvider = getProvider()): string {
  return b64u(prov.mldsaSign(sigSeed, canon(m), context('manifest')))
}

/** SUITE.md 7.4 / 7.6: verify suite, recipient ordering and the signature under the signer's sig_pk. */
export function verifyManifest(sigPk: Uint8Array, m: Manifest, sig: string, prov: CryptoProvider = getProvider()): boolean {
  if (!m || m.suite !== SUITE || !isSortedUnique(m.recipients)) return false
  let s: Uint8Array
  try {
    s = fromB64u(sig)
  } catch {
    return false
  }
  try {
    return prov.mldsaVerify(sigPk, canon(m), s, context('manifest'))
  } catch {
    return false
  }
}

// ---- 7.5 share statement --------------------------------------------------------------------

export interface ShareStatement {
  directory_epoch: number
  file_id: string
  recipients: string[]
  suite: 'QG-1'
  version: number
}

/** SUITE.md 7.5: share statement for the devices being added. */
export function buildShare(fileId: string, version: number, recipients: Iterable<string>, directoryEpoch: number): ShareStatement {
  return { directory_epoch: directoryEpoch, file_id: fileId, recipients: sortRecipients(recipients), suite: SUITE, version }
}

/** SUITE.md 7.5: share_sig with purpose share. */
export function signShare(sigSeed: Uint8Array, s: ShareStatement, prov: CryptoProvider = getProvider()): string {
  return b64u(prov.mldsaSign(sigSeed, canon(s), context('share')))
}

/** SUITE.md 7.5: verify a share statement signature. */
export function verifyShare(sigPk: Uint8Array, s: ShareStatement, sig: string, prov: CryptoProvider = getProvider()): boolean {
  if (!s || s.suite !== SUITE || !isSortedUnique(s.recipients)) return false
  try {
    return prov.mldsaVerify(sigPk, canon(s), fromB64u(sig), context('share'))
  } catch {
    return false
  }
}

// ---- 11 messages ----------------------------------------------------------------------------

export interface MessageEnvelope {
  ciphertext: string
  device_id: string
  xwing_ct: string
}

/** SUITE.md 3: message key = HKDF-SHA-384(ss, empty, "QG/v1/message", 32). */
export function messageKey(ss: Uint8Array, prov: CryptoProvider = getProvider()): Promise<Uint8Array> {
  return prov.hkdfSha384(ss, new Uint8Array(0), utf8(INFO.message), 32)
}

/** SUITE.md 11: AAD of one envelope. */
export function messageAad(deviceId: string, toUserId: string): Uint8Array {
  return canon({ device_id: deviceId, suite: SUITE, to_user_id: toUserId })
}

/** SUITE.md 11: one envelope per recipient device. */
export async function sealMessage(kemPk: Uint8Array, deviceId: string, toUserId: string, plaintext: Uint8Array, prov: CryptoProvider = getProvider()): Promise<MessageEnvelope> {
  const { ct, ss } = prov.xwingEncapsulate(kemPk)
  const key = await messageKey(ss, prov)
  const n = prov.randomBytes(NONCE_LEN)
  try {
    const c = concat(n, await prov.aesGcmEncrypt(key, n, plaintext, messageAad(deviceId, toUserId)))
    return { ciphertext: b64u(c), device_id: deviceId, xwing_ct: b64u(ct) }
  } finally {
    ss.fill(0)
    key.fill(0)
  }
}

/**
 * SUITE.md 11: open the envelope addressed to this device. `GET /messages` returns the envelope without
 * its device_id (it is always the caller's), so the AAD is bound to this device's id, passed explicitly.
 */
export async function openMessage(kemSeed: Uint8Array, env: { xwing_ct: string; ciphertext: string }, deviceId: string, toUserId: string, prov: CryptoProvider = getProvider()): Promise<Uint8Array> {
  const ct = fromB64u(env.xwing_ct, XWING_CT_BYTES)
  const c = fromB64u(env.ciphertext)
  if (c.length < NONCE_LEN + TAG_LEN) throw new EnvelopeError('bad message')
  const ss = prov.xwingDecapsulate(ct, kemSeed)
  const key = await messageKey(ss, prov)
  try {
    return await prov.aesGcmDecrypt(key, c.slice(0, NONCE_LEN), c.subarray(NONCE_LEN), messageAad(deviceId, toUserId))
  } catch {
    throw new EnvelopeError('message failed authentication')
  } finally {
    ss.fill(0)
    key.fill(0)
  }
}

export interface EnvelopeDigest {
  device_id: string
  digest: string
}

const byDevice = (a: { device_id: string }, b: { device_id: string }) => (a.device_id < b.device_id ? -1 : a.device_id > b.device_id ? 1 : 0)

/** SUITE.md 11: envelope_digest = b64u(SHA-256(canon({ciphertext, device_id, xwing_ct}))) over the b64u strings as sent. */
export async function envelopeDigest(e: MessageEnvelope, prov: CryptoProvider = getProvider()): Promise<string> {
  return b64u(await prov.sha256(canon({ ciphertext: e.ciphertext, device_id: e.device_id, xwing_ct: e.xwing_ct })))
}

/** SUITE.md 11: one digest per envelope, sorted by device_id. */
export async function envelopeDigests(envelopes: MessageEnvelope[], prov: CryptoProvider = getProvider()): Promise<EnvelopeDigest[]> {
  const out: EnvelopeDigest[] = []
  for (const e of envelopes) out.push({ device_id: e.device_id, digest: await envelopeDigest(e, prov) })
  return out.sort(byDevice)
}

/** SUITE.md 11: the signed statement canon({envelope_digests sorted by device_id, suite, to_user_id}). */
export function messageStatement(toUserId: string, digests: EnvelopeDigest[]): Uint8Array {
  return canon({
    envelope_digests: [...digests].sort(byDevice).map((d) => ({ device_id: d.device_id, digest: d.digest })),
    suite: SUITE,
    to_user_id: toUserId,
  })
}

export interface ReceivedMessage {
  to_user_id: string
  envelope: { xwing_ct: string; ciphertext: string }
  envelope_digests: EnvelopeDigest[]
  signature: string
}

/**
 * SUITE.md 11, recipient side, before decrypting: the message is for this person, this device's
 * envelope digest is listed under its device_id, and the sender's signature (under `senderSigPk` from
 * the current verified directory; null when the sender is not in it) covers the statement rebuilt from
 * `envelope_digests` and this device's own user id.
 */
export async function checkMessage(m: ReceivedMessage, self: { device_id: string; user_id: string }, senderSigPk: Uint8Array | null, prov: CryptoProvider = getProvider()): Promise<boolean> {
  if (!senderSigPk || m.to_user_id !== self.user_id || !Array.isArray(m.envelope_digests) || !m.envelope || typeof m.signature !== 'string') return false
  const ids = m.envelope_digests.map((d) => d?.device_id)
  if (ids.some((d) => typeof d !== 'string') || new Set(ids).size !== ids.length) return false
  const mine = await envelopeDigest({ ciphertext: m.envelope.ciphertext, device_id: self.device_id, xwing_ct: m.envelope.xwing_ct }, prov)
  if (!m.envelope_digests.some((d) => d.device_id === self.device_id && d.digest === mine)) return false
  try {
    return prov.mldsaVerify(senderSigPk, messageStatement(self.user_id, m.envelope_digests), fromB64u(m.signature), context('message'))
  } catch {
    return false
  }
}
