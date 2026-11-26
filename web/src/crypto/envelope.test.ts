import { shake128 } from '@noble/hashes/sha3.js'
import { describe, expect, it } from 'vitest'
import { b64u, fromB64u } from './b64u'
import { fromHex, toHex, utf8 } from './bytes'
import { canon } from './canonical'
import {
  buildManifest,
  buildShare,
  chunkAad,
  ciphertextSha256,
  decryptFile,
  encryptFile,
  messageStatement,
  openMessage,
  sealMessage,
  signManifest,
  unwrapDek,
  verifyManifest,
  verifyShare,
  wrapBinding,
  wrapDek,
  wrapDekWithSecret,
  wrapKey,
  type Manifest,
  type ShareStatement,
  type WrapBinding,
} from './envelope'
import { getProvider } from './provider'
import { describeVector } from './test-vectors'

const prov = getProvider()

interface EnvelopeDoc {
  dek: string
  nonce_prefix: string
  file_id: string
  version: number
  files: {
    plaintext_label: string
    plaintext_len: number
    chunk_count: number
    chunks: { index: number; aad_hex: string; len: number; sha256: string; head_hex: string; tail_hex: string; blob_hex?: string }[]
    ciphertext_sha256_b64u: string
  }[]
  wrap: {
    recipient_kem_seed: string
    recipient_kem_pk_b64u: string
    binding: WrapBinding
    aad_hex: string
    xwing_ct_b64u: string
    ss: string
    kek: string
    nonce: string
    wrapped_dek_b64u: string
    inner_wrap: { xwing_ct: string; wrapped_dek: string }
    must_fail_with_binding: { change: string; binding: WrapBinding; aad_hex: string }[]
  }
  manifest: { signer_sig_seed: string; signer_sig_pk_b64u: string; manifest: Manifest; canonical_hex: string; manifest_sig_b64u: string }
  share: { share: ShareStatement; canonical_hex: string; share_sig_b64u: string }
}

const plaintextFor = (label: string, n: number) => (n === 0 ? new Uint8Array(0) : shake128(utf8(label), { dkLen: n }))

describeVector<EnvelopeDoc>('envelope.json', (doc) => {
  const dek = fromHex(doc.dek)
  const prefix = fromHex(doc.nonce_prefix)

  it.each(doc.files.map((f) => [f.plaintext_label, f] as const))('file %s', async (_l, f) => {
    const pt = plaintextFor(f.plaintext_label, f.plaintext_len)
    const blobs = await encryptFile(dek, doc.file_id, doc.version, pt, prefix)
    expect(blobs.length).toBe(f.chunk_count)
    for (const c of f.chunks) {
      const b = blobs[c.index]
      expect(toHex(chunkAad(doc.file_id, doc.version, c.index, c.index === f.chunk_count - 1))).toBe(c.aad_hex)
      expect(b.length).toBe(c.len)
      expect(toHex(prov.sha256Sync(b))).toBe(c.sha256)
      expect(toHex(b.subarray(0, 48))).toBe(c.head_hex)
      expect(toHex(b.subarray(Math.max(0, b.length - 48)))).toBe(c.tail_hex)
      if (c.blob_hex) expect(toHex(b)).toBe(c.blob_hex)
    }
    expect(ciphertextSha256(blobs)).toBe(f.ciphertext_sha256_b64u)
    const back = await decryptFile(dek, doc.file_id, doc.version, blobs, f.chunk_count)
    expect(toHex(new Uint8Array(await new Blob(back.map((x) => x.slice())).arrayBuffer()))).toBe(toHex(pt))
  })

  it('wrap: ss -> KEK -> wrapped_dek, and unwrap with the recipient seed', async () => {
    const w = doc.wrap
    expect(toHex(canon(w.binding))).toBe(w.aad_hex)
    const seed = fromHex(w.recipient_kem_seed)
    expect(b64u(prov.xwingKeygen(seed).publicKey)).toBe(w.recipient_kem_pk_b64u)
    expect(toHex(prov.xwingDecapsulate(fromB64u(w.xwing_ct_b64u), seed))).toBe(w.ss)
    expect(toHex(await wrapKey(fromHex(w.ss)))).toBe(w.kek)
    expect(b64u(await wrapDekWithSecret(fromHex(w.ss), dek, w.binding, fromHex(w.nonce)))).toBe(w.wrapped_dek_b64u)
    expect(toHex(await unwrapDek(seed, w.inner_wrap, w.binding))).toBe(doc.dek)
  })

  it.each(doc.wrap.must_fail_with_binding.map((n) => [n.change, n] as const))('wrap fails when %s changes', async (_c, n) => {
    expect(toHex(canon(n.binding))).toBe(n.aad_hex)
    await expect(unwrapDek(fromHex(doc.wrap.recipient_kem_seed), doc.wrap.inner_wrap, n.binding)).rejects.toThrow()
  })

  it('manifest canonical bytes and signature', () => {
    const m = doc.manifest
    expect(toHex(canon(m.manifest))).toBe(m.canonical_hex)
    const pk = fromB64u(m.signer_sig_pk_b64u)
    expect(b64u(prov.mldsaKeygen(fromHex(m.signer_sig_seed)).publicKey)).toBe(m.signer_sig_pk_b64u)
    expect(verifyManifest(pk, m.manifest, m.manifest_sig_b64u)).toBe(true)
    expect(verifyManifest(pk, { ...m.manifest, version: 2 }, m.manifest_sig_b64u)).toBe(false)
    expect(verifyShare(pk, doc.share.share, m.manifest_sig_b64u)).toBe(false)
    const rebuilt = buildManifest({ ...m.manifest, recipients: [...m.manifest.recipients].reverse() })
    expect(toHex(canon(rebuilt))).toBe(m.canonical_hex)
    expect(verifyManifest(pk, rebuilt, signManifest(fromHex(m.signer_sig_seed), rebuilt))).toBe(true)
  })

  it('share statement canonical bytes and signature', () => {
    const s = doc.share
    expect(toHex(canon(s.share))).toBe(s.canonical_hex)
    const pk = fromB64u(doc.manifest.signer_sig_pk_b64u)
    expect(verifyShare(pk, s.share, s.share_sig_b64u)).toBe(true)
    expect(verifyManifest(pk, doc.manifest.manifest, s.share_sig_b64u)).toBe(false)
    const rebuilt = buildShare(s.share.file_id, s.share.version, s.share.recipients, s.share.directory_epoch)
    expect(toHex(canon(rebuilt))).toBe(s.canonical_hex)
  })
})

describe('envelope properties (local)', () => {
  const fileId = 'fil_AAAAAAAAAAAAAAAAAAAAAA'
  const size = 2 * 1048576 + 17

  async function sample() {
    const dek = prov.randomBytes(32)
    const prefix = prov.randomBytes(8)
    const pt = prov.randomBytes(size)
    const blobs = await encryptFile(dek, fileId, 3, pt, prefix)
    return { dek, prefix, pt, blobs }
  }

  it('round trips and splits into 1 MiB chunks', async () => {
    const { dek, pt, blobs } = await sample()
    expect(blobs.map((b) => b.length)).toEqual([1048576 + 28, 1048576 + 28, 17 + 28])
    const back = await decryptFile(dek, fileId, 3, blobs, 3)
    expect(back.reduce((n, b) => n + b.length, 0)).toBe(pt.length)
    expect(toHex(back[2])).toBe(toHex(pt.subarray(2 * 1048576)))
  })

  it('a single bit flip anywhere fails', async () => {
    const { dek, blobs } = await sample()
    for (const [ci, pos] of [[0, 0], [0, 11], [0, 12], [1, 500000], [2, blobs[2].length - 1]] as const) {
      const bad = blobs.map((b) => b.slice())
      bad[ci][pos] ^= 0x01
      await expect(decryptFile(dek, fileId, 3, bad, 3)).rejects.toThrow()
    }
  })

  it('reordered, truncated, extended or foreign chunks fail', async () => {
    const { dek, blobs } = await sample()
    await expect(decryptFile(dek, fileId, 3, [blobs[1], blobs[0], blobs[2]], 3)).rejects.toThrow()
    await expect(decryptFile(dek, fileId, 3, blobs.slice(0, 2), 3)).rejects.toThrow()
    await expect(decryptFile(dek, fileId, 3, blobs.slice(0, 2), 2)).rejects.toThrow() // chunk 1 was not last
    await expect(decryptFile(dek, fileId, 3, [...blobs, blobs[2]], 4)).rejects.toThrow()
    const other = await encryptFile(dek, fileId, 3, prov.randomBytes(size), prov.randomBytes(8))
    await expect(decryptFile(dek, fileId, 3, [blobs[0], other[1], blobs[2]], 3)).rejects.toThrow()
    await expect(decryptFile(dek, fileId, 4, blobs, 3)).rejects.toThrow()
    await expect(decryptFile(dek, 'fil_BBBBBBBBBBBBBBBBBBBBBB', 3, blobs, 3)).rejects.toThrow()
  })

  it('empty file is one chunk', async () => {
    const dek = prov.randomBytes(32)
    const blobs = await encryptFile(dek, fileId, 1, new Uint8Array(0), prov.randomBytes(8))
    expect(blobs.length).toBe(1)
    expect((await decryptFile(dek, fileId, 1, blobs, 1))[0].length).toBe(0)
  })

  it('a wrap bound to another file, version, device or epoch fails; wrong device key fails', async () => {
    const dek = prov.randomBytes(32)
    const kp = prov.xwingKeygen()
    const binding = wrapBinding(fileId, 1, 'dev_AAAAAAAAAAAAAAAAAAAAAA', 5)
    const w = await wrapDek(kp.publicKey, dek, binding)
    expect(fromB64u(w.wrapped_dek).length).toBe(60)
    expect(toHex(await unwrapDek(kp.seed, w, binding))).toBe(toHex(dek))
    for (const change of [{ file_id: 'fil_BBBBBBBBBBBBBBBBBBBBBB' }, { version: 2 }, { device_id: 'dev_BBBBBBBBBBBBBBBBBBBBBB' }, { device_id: 'recovery' }, { directory_epoch: 6 }]) {
      await expect(unwrapDek(kp.seed, w, { ...binding, ...change })).rejects.toThrow()
    }
    await expect(unwrapDek(prov.xwingKeygen().seed, w, binding)).rejects.toThrow()
  })

  it('manifest recipients are sorted, unique and never recovery', () => {
    const m = buildManifest({ chunk_count: 1, ciphertext_sha256: 'AA', classification: 'internal', directory_epoch: 1, file_id: fileId, version: 1, recipients: ['dev_b', 'dev_a', 'dev_b'] })
    expect(m.recipients).toEqual(['dev_a', 'dev_b'])
    expect(() => buildManifest({ ...m, recipients: ['recovery'] })).toThrow()
    const kp = prov.mldsaKeygen()
    const sig = signManifest(kp.seed, m)
    expect(verifyManifest(kp.publicKey, { ...m, recipients: ['dev_b', 'dev_a'] }, sig)).toBe(false)
  })

  it('message envelopes round trip and bind device and recipient', async () => {
    const kp = prov.xwingKeygen()
    const env = await sealMessage(kp.publicKey, 'dev_x', 'usr_y', utf8('hi'))
    // GET /messages sends {xwing_ct, ciphertext} only: the opener supplies its own device id.
    const wire = { xwing_ct: env.xwing_ct, ciphertext: env.ciphertext }
    expect(new TextDecoder().decode(await openMessage(kp.seed, wire, 'dev_x', 'usr_y'))).toBe('hi')
    await expect(openMessage(kp.seed, wire, 'dev_x', 'usr_z')).rejects.toThrow()
    await expect(openMessage(kp.seed, wire, 'dev_w', 'usr_y')).rejects.toThrow()
    expect(new TextDecoder().decode(messageStatement('usr_y', [env]))).toContain('"to_user_id":"usr_y"')
  })
})
