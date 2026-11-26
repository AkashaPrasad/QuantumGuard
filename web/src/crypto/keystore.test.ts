import { describe, expect, it } from 'vitest'
import { fromB64u } from './b64u'
import { fromHex, toHex } from './bytes'
import { canon } from './canonical'
import { deriveKeystoreKey, Keyring, KeystoreError, memoryDeviceStore, openKeystore, relabel, sealKeystore, type KeystoreFile, type KeystoreLabel } from './keystore'
import { getProvider } from './provider'
import { describeVector } from './test-vectors'

const prov = getProvider()

interface KeystoreDoc {
  passphrase: string
  passphrase_nfd: string
  argon2_key: string
  aad_hex: string
  sig_seed: string
  kem_seed: string
  keystore: KeystoreFile
  must_fail: { why: string; passphrase: string; keystore: unknown }[]
}

describeVector<KeystoreDoc>('keystore.json', (doc) => {
  it('derives the Argon2id key and the header AAD', async () => {
    expect(toHex(await deriveKeystoreKey(doc.passphrase, doc.keystore.kdf))).toBe(doc.argon2_key)
    const header: Record<string, unknown> = { ...doc.keystore }
    delete header.ciphertext
    expect(toHex(canon(header))).toBe(doc.aad_hex)
  }, 60_000)

  it('opens with the passphrase and with its NFD form', async () => {
    for (const p of [doc.passphrase, doc.passphrase_nfd]) {
      const { seeds } = await openKeystore(doc.keystore, p)
      expect(toHex(seeds.sig_seed)).toBe(doc.sig_seed)
      expect(toHex(seeds.kem_seed)).toBe(doc.kem_seed)
    }
  }, 60_000)

  it.each(doc.must_fail.map((f) => [f.why, f] as const))('rejects: %s', async (_w, f) => {
    await expect(openKeystore(f.keystore, f.passphrase)).rejects.toBeInstanceOf(KeystoreError)
  }, 60_000)

  it('reseals byte-identically from the same salt and nonce', async () => {
    const seeds = { sig_seed: fromHex(doc.sig_seed), kem_seed: fromHex(doc.kem_seed) }
    const salt = fromB64u(doc.keystore.kdf.salt)
    const nonce = fromB64u(doc.keystore.aead.nonce)
    const { file } = await sealKeystore(seeds, doc.passphrase, doc.keystore.label, { salt, nonce })
    expect(toHex(canon(file))).toBe(toHex(canon(doc.keystore)))
  }, 60_000)
})

describe('keystore (local)', () => {
  const label: KeystoreLabel = { user_id: null, device_id: null, device_name: 'test', server: null, created_at: '2026-11-26T12:00:00.000Z' }

  it('round trips, relabels with a fresh nonce, and rejects tampering', async () => {
    const seeds = { kem_seed: prov.randomBytes(32), sig_seed: prov.randomBytes(32) }
    const { file, key } = await sealKeystore(seeds, 'pass phrase', label)
    const opened = await openKeystore(file, 'pass phrase')
    expect(toHex(opened.seeds.kem_seed)).toBe(toHex(seeds.kem_seed))
    const re = await relabel(file, key, seeds, { ...label, device_id: 'dev_x', user_id: 'usr_y' })
    expect(re.aead.nonce).not.toBe(file.aead.nonce)
    expect(re.kdf.salt).toBe(file.kdf.salt)
    expect(toHex((await openKeystore(re, 'pass phrase')).seeds.sig_seed)).toBe(toHex(seeds.sig_seed))
    await expect(openKeystore({ ...re, label: file.label }, 'pass phrase')).rejects.toBeInstanceOf(KeystoreError)
    await expect(openKeystore({ ...re, extra: 1 }, 'pass phrase')).rejects.toBeInstanceOf(KeystoreError)
    await expect(openKeystore({ ...re, kdf: { ...re.kdf, t: 11 } }, 'pass phrase')).rejects.toBeInstanceOf(KeystoreError)
    await expect(openKeystore({ ...re, kdf: { ...re.kdf, p: 0 } }, 'pass phrase')).rejects.toBeInstanceOf(KeystoreError)
  }, 120_000)

  it('keyring zeroes seeds on lock', () => {
    const k = new Keyring()
    k.load({ kem_seed: new Uint8Array(32).fill(7), sig_seed: new Uint8Array(32).fill(9) })
    const kem = k.kemSeed()
    const sig = k.sigSeed()
    k.lock()
    expect(kem.every((b) => b === 0)).toBe(true)
    expect(sig.every((b) => b === 0)).toBe(true)
    expect(() => k.kemSeed()).toThrow()
  })

  it('memory device store copies records', async () => {
    const s = memoryDeviceStore()
    expect(await s.load()).toBeNull()
    await s.clear()
  })
})
