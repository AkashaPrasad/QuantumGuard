// SUITE.md 1: the QG-1 primitives composed from @noble/*. Web Crypto (crypto.subtle) is used for
// AES-GCM, HKDF, HMAC and SHA-256 when it exists; noble otherwise. Both paths give identical bytes.
import { gcm } from '@noble/ciphers/aes.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { argon2idAsync } from '@noble/hashes/argon2.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256, sha384 } from '@noble/hashes/sha2.js'
import { randomBytes as nobleRandom } from '@noble/hashes/utils.js'
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { own, wipe } from './bytes'
import type { Argon2Params, CryptoProvider, KemKeyPair, SigKeyPair } from './provider'

export const XWING_PK_BYTES = 1216
export const XWING_CT_BYTES = 1120
export const MLDSA_PK_BYTES = 1952
export const MLDSA_SIG_BYTES = 3309
export const ED25519_PK_BYTES = 32

export class AeadError extends Error {
  constructor() {
    super('AES-GCM authentication failed')
    this.name = 'AeadError'
  }
}

function hasSubtle(): boolean {
  const c = (globalThis as { crypto?: Crypto }).crypto
  const secure = (globalThis as { isSecureContext?: boolean }).isSecureContext
  return !!c?.subtle && secure !== false
}

function assertLen(b: Uint8Array, n: number, what: string): void {
  if (!(b instanceof Uint8Array) || b.length !== n) throw new Error(`${what}: expected ${n} bytes`)
}

/** SUITE.md 1.1: X-Wing key generation from the 32-byte seed (SHAKE256 expansion inside noble). */
function xwingKeygen(seed?: Uint8Array): KemKeyPair {
  if (seed) assertLen(seed, 32, 'xwing seed')
  const kp = ml_kem768_x25519.keygen(seed)
  return { seed: kp.secretKey, publicKey: kp.publicKey }
}

/** SUITE.md 1.1 / draft section 5.4: Encapsulate (or EncapsulateDerand with a 64-byte eseed). */
function xwingEncapsulate(publicKey: Uint8Array, eseed?: Uint8Array): { ct: Uint8Array; ss: Uint8Array } {
  assertLen(publicKey, XWING_PK_BYTES, 'xwing pk')
  if (eseed) assertLen(eseed, 64, 'xwing eseed')
  const r = ml_kem768_x25519.encapsulate(publicKey, eseed)
  return { ct: r.cipherText, ss: r.sharedSecret }
}

/** SUITE.md 1.1 / draft section 5.5: Decapsulate with the seed-form key. */
function xwingDecapsulate(ct: Uint8Array, seed: Uint8Array): Uint8Array {
  assertLen(ct, XWING_CT_BYTES, 'xwing ct')
  assertLen(seed, 32, 'xwing seed')
  return ml_kem768_x25519.decapsulate(ct, seed)
}

/** SUITE.md 1.2: ML-DSA-65 KeyGen_internal from the 32-byte seed xi. */
function mldsaKeygen(seed?: Uint8Array): SigKeyPair {
  const xi = seed ?? nobleRandom(32)
  assertLen(xi, 32, 'mldsa seed')
  const kp = ml_dsa65.keygen(xi)
  wipe(kp.secretKey)
  return { seed: xi, publicKey: kp.publicKey }
}

/** SUITE.md 4: hedged pure ML-DSA-65 signature with context string; expanded key wiped after use. */
function mldsaSign(seed: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array {
  assertLen(seed, 32, 'mldsa seed')
  const { secretKey } = ml_dsa65.keygen(seed)
  try {
    return ml_dsa65.sign(msg, secretKey, { context: ctx })
  } finally {
    wipe(secretKey)
  }
}

/** SUITE.md 4: ML-DSA-65 verification with context string; malformed input is a failure. */
function mldsaVerify(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array, ctx: Uint8Array): boolean {
  if (publicKey.length !== MLDSA_PK_BYTES || sig.length !== MLDSA_SIG_BYTES) return false
  try {
    return ml_dsa65.verify(sig, msg, publicKey, { context: ctx })
  } catch {
    return false
  }
}

/** SUITE.md 1 / 4: pure Ed25519 with RFC 8032 (not ZIP-215) decoding rules. */
function ed25519Verify(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
  if (publicKey.length !== ED25519_PK_BYTES || sig.length !== 64) return false
  try {
    return ed25519.verify(sig, msg, publicKey, { zip215: false })
  } catch {
    return false
  }
}

/** SUITE.md 15: Argon2id v0x13 with an explicit memory budget for the declared parameters. */
async function argon2id(password: Uint8Array, salt: Uint8Array, params: Argon2Params): Promise<Uint8Array> {
  return argon2idAsync(password, salt, {
    t: params.t,
    m: params.m_kib,
    p: params.p,
    dkLen: params.dkLen,
    version: 0x13,
    maxmem: params.m_kib * 1024 + 1024 * 1024,
    asyncTick: 20,
  })
}

/** Builds the provider. `useSubtle: false` forces the pure-noble path (tests compare both). */
export function createNobleProvider(opts: { useSubtle?: boolean } = {}): CryptoProvider {
  const subtleOn = opts.useSubtle ?? hasSubtle()
  const subtle = subtleOn ? globalThis.crypto.subtle : null

  async function aesGcmEncrypt(key: Uint8Array, nonce: Uint8Array, pt: Uint8Array, aad: Uint8Array) {
    assertLen(key, 32, 'aes key')
    assertLen(nonce, 12, 'gcm nonce')
    if (!subtle) return gcm(key, nonce, aad).encrypt(pt)
    const k = await subtle.importKey('raw', own(key), 'AES-GCM', false, ['encrypt'])
    const out = await subtle.encrypt({ name: 'AES-GCM', iv: own(nonce), additionalData: own(aad), tagLength: 128 }, k, own(pt))
    return new Uint8Array(out)
  }

  async function aesGcmDecrypt(key: Uint8Array, nonce: Uint8Array, ct: Uint8Array, aad: Uint8Array) {
    assertLen(key, 32, 'aes key')
    assertLen(nonce, 12, 'gcm nonce')
    if (ct.length < 16) throw new AeadError()
    try {
      if (!subtle) return gcm(key, nonce, aad).decrypt(ct)
      const k = await subtle.importKey('raw', own(key), 'AES-GCM', false, ['decrypt'])
      const out = await subtle.decrypt({ name: 'AES-GCM', iv: own(nonce), additionalData: own(aad), tagLength: 128 }, k, own(ct))
      return new Uint8Array(out)
    } catch {
      throw new AeadError()
    }
  }

  async function hkdfSha384(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number) {
    if (!subtle) return hkdf(sha384, ikm, salt, info, length)
    const k = await subtle.importKey('raw', own(ikm), 'HKDF', false, ['deriveBits'])
    const bits = await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-384', salt: own(salt), info: own(info) }, k, length * 8)
    return new Uint8Array(bits)
  }

  async function hmacSha384(key: Uint8Array, msg: Uint8Array) {
    if (!subtle || key.length === 0) return hmac(sha384, key, msg)
    const k = await subtle.importKey('raw', own(key), { name: 'HMAC', hash: 'SHA-384' }, false, ['sign'])
    return new Uint8Array(await subtle.sign('HMAC', k, own(msg)))
  }

  async function sha256Async(data: Uint8Array) {
    if (!subtle) return sha256(data)
    return new Uint8Array(await subtle.digest('SHA-256', own(data)))
  }

  /** CSPRNG bytes, drawn in 64 KiB pieces (the getRandomValues limit). */
  function randomBytes(n: number): Uint8Array {
    if (n <= 65536) return nobleRandom(n)
    const out = new Uint8Array(n)
    for (let o = 0; o < n; o += 65536) out.set(nobleRandom(Math.min(65536, n - o)), o)
    return out
  }

  return {
    name: 'noble',
    subtle: subtleOn,
    xwingKeygen,
    xwingEncapsulate,
    xwingDecapsulate,
    mldsaKeygen,
    mldsaSign,
    mldsaVerify,
    ed25519Verify,
    aesGcmEncrypt,
    aesGcmDecrypt,
    hkdfSha384,
    hmacSha384,
    sha256: sha256Async,
    sha256Sync: (d) => sha256(d),
    sha256Stream: () => {
      const h = sha256.create()
      return {
        update: (d: Uint8Array) => void h.update(d),
        digest: () => h.digest(),
      }
    },
    argon2id,
    randomBytes,
  }
}
