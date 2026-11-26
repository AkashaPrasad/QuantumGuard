import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
import { describe, expect, it } from 'vitest'
import { concat, fromHex, toHex, utf8 } from './bytes'
import { createNobleProvider } from './noble'
import { getProvider } from './provider'
import { describeVector } from './test-vectors'

const prov = getProvider()

interface XWingDoc {
  vectors: { seed: string; pk: string; eseed: string; ct: string; ss: string }[]
}

describeVector<XWingDoc>('xwing.json', (doc) => {
  it.each(doc.vectors.map((v, i) => [i, v] as const))('draft-11 Appendix C vector %i', (_i, v) => {
    const kp = prov.xwingKeygen(fromHex(v.seed))
    expect(toHex(kp.publicKey)).toBe(v.pk)
    const enc = prov.xwingEncapsulate(fromHex(v.pk), fromHex(v.eseed))
    expect(toHex(enc.ct)).toBe(v.ct)
    expect(toHex(enc.ss)).toBe(v.ss)
    expect(toHex(prov.xwingDecapsulate(fromHex(v.ct), fromHex(v.seed)))).toBe(v.ss)
  })
})

interface MlKemDoc {
  keygen: { tcId: number; d: string; z: string; ek: string; dk: string }[]
  decaps: { tcId: number; comment: string; seed: string; ek: string; c: string; k: string; result: string }[]
}

describeVector<MlKemDoc>('mlkem768.json', (doc) => {
  it('keyGen (d, z -> ek, dk)', () => {
    for (const t of doc.keygen) {
      const kp = ml_kem768.keygen(concat(fromHex(t.d), fromHex(t.z)))
      expect(toHex(kp.publicKey), `tcId ${t.tcId}`).toBe(t.ek)
      expect(toHex(kp.secretKey), `tcId ${t.tcId}`).toBe(t.dk)
    }
  })
  it('decapsulation (seed, c -> k)', () => {
    for (const t of doc.decaps) {
      const run = () => {
        const seed = fromHex(t.seed)
        if (seed.length !== 64) throw new Error('seed length')
        const kp = ml_kem768.keygen(seed)
        if (t.ek && toHex(kp.publicKey) !== t.ek) throw new Error('ek mismatch')
        return toHex(ml_kem768.decapsulate(fromHex(t.c), kp.secretKey))
      }
      if (t.result === 'invalid') expect(run, `tcId ${t.tcId} ${t.comment}`).toThrow()
      else expect(run(), `tcId ${t.tcId} ${t.comment}`).toBe(t.k)
    }
  })
})

interface MlDsaDoc {
  keygen: { tcId: number; seed: string; pk: string }[]
  sigver: { tcId: number; pk: string; message: string; context: string; signature: string; testPassed: boolean }[]
}

describeVector<MlDsaDoc>('mldsa65.json', (doc) => {
  it('keyGen (seed -> pk)', () => {
    for (const t of doc.keygen) expect(toHex(prov.mldsaKeygen(fromHex(t.seed)).publicKey), `tcId ${t.tcId}`).toBe(t.pk)
  })
  it('sigVer with context', () => {
    for (const t of doc.sigver) {
      const ok = prov.mldsaVerify(fromHex(t.pk), fromHex(t.message), fromHex(t.signature), fromHex(t.context))
      expect(ok, `tcId ${t.tcId}`).toBe(t.testPassed)
    }
  })
})

describe('provider (local)', () => {
  it('Web Crypto and noble paths give identical bytes', async () => {
    const a = createNobleProvider({ useSubtle: true })
    const b = createNobleProvider({ useSubtle: false })
    expect(a.subtle).toBe(true)
    for (const n of [0, 1, 31, 1000]) {
      const key = prov.randomBytes(32)
      const nonce = prov.randomBytes(12)
      const pt = prov.randomBytes(n)
      const aad = prov.randomBytes(n % 17)
      const ca = await a.aesGcmEncrypt(key, nonce, pt, aad)
      expect(toHex(await b.aesGcmEncrypt(key, nonce, pt, aad))).toBe(toHex(ca))
      expect(toHex(await b.aesGcmDecrypt(key, nonce, ca, aad))).toBe(toHex(pt))
      const ikm = prov.randomBytes(32)
      expect(toHex(await a.hkdfSha384(ikm, new Uint8Array(0), utf8('QG/v1/wrap'), 32))).toBe(toHex(await b.hkdfSha384(ikm, new Uint8Array(0), utf8('QG/v1/wrap'), 32)))
      expect(toHex(await a.hkdfSha384(ikm, pt, aad, 48))).toBe(toHex(await b.hkdfSha384(ikm, pt, aad, 48)))
      expect(toHex(await a.hmacSha384(ikm, pt))).toBe(toHex(await b.hmacSha384(ikm, pt)))
      expect(toHex(await a.sha256(pt))).toBe(toHex(await b.sha256(pt)))
      expect(toHex(a.sha256Sync(pt))).toBe(toHex(await b.sha256(pt)))
    }
  })
  it('empty HKDF salt equals 48 zero bytes', async () => {
    const ikm = prov.randomBytes(32)
    expect(toHex(await prov.hkdfSha384(ikm, new Uint8Array(0), utf8('x'), 32))).toBe(toHex(await prov.hkdfSha384(ikm, new Uint8Array(48), utf8('x'), 32)))
  })
  it('AES-GCM rejects a flipped bit and wrong AAD', async () => {
    for (const p of [createNobleProvider({ useSubtle: true }), createNobleProvider({ useSubtle: false })]) {
      const key = prov.randomBytes(32)
      const nonce = prov.randomBytes(12)
      const ct = await p.aesGcmEncrypt(key, nonce, utf8('hello'), utf8('aad'))
      const flipped = ct.slice()
      flipped[2] ^= 1
      await expect(p.aesGcmDecrypt(key, nonce, flipped, utf8('aad'))).rejects.toThrow()
      await expect(p.aesGcmDecrypt(key, nonce, ct, utf8('aae'))).rejects.toThrow()
    }
  })
  it('X-Wing round trip with a random seed', () => {
    const kp = prov.xwingKeygen()
    expect(kp.seed.length).toBe(32)
    expect(kp.publicKey.length).toBe(1216)
    const { ct, ss } = prov.xwingEncapsulate(kp.publicKey)
    expect(ct.length).toBe(1120)
    expect(toHex(prov.xwingDecapsulate(ct, kp.seed))).toBe(toHex(ss))
  })
  it('ML-DSA-65 signatures are bound to their context', () => {
    const kp = prov.mldsaKeygen()
    const msg = utf8('m')
    const sig = prov.mldsaSign(kp.seed, msg, utf8('QG/v1/manifest'))
    expect(sig.length).toBe(3309)
    expect(prov.mldsaVerify(kp.publicKey, msg, sig, utf8('QG/v1/manifest'))).toBe(true)
    expect(prov.mldsaVerify(kp.publicKey, msg, sig, utf8('QG/v1/share'))).toBe(false)
    // pure ML-DSA: same key as the library derives from the seed
    expect(toHex(ml_dsa65.keygen(kp.seed).publicKey)).toBe(toHex(kp.publicKey))
  })
})
