// The single interface for every QG-1 primitive (SUITE.md 1). Everything above this file composes
// these calls; nothing above it imports a crypto library directly.
import { createNobleProvider } from './noble'

export interface KemKeyPair {
  /** SUITE.md 1.1: the 32-byte X-Wing decapsulation seed `sk`. */
  seed: Uint8Array
  /** 1216-byte X-Wing encapsulation key. */
  publicKey: Uint8Array
}

export interface SigKeyPair {
  /** SUITE.md 1.2: the 32-byte ML-DSA-65 seed `xi`. */
  seed: Uint8Array
  /** 1952-byte ML-DSA-65 public key. */
  publicKey: Uint8Array
}

export interface Argon2Params {
  t: number
  m_kib: number
  p: number
  dkLen: number
}

export interface CryptoProvider {
  readonly name: 'noble'
  /** True when AES-GCM, HKDF, HMAC and SHA run on `crypto.subtle`. */
  readonly subtle: boolean

  // SUITE.md 1.1 X-Wing (draft-connolly-cfrg-xwing-kem-11)
  xwingKeygen(seed?: Uint8Array): KemKeyPair
  xwingEncapsulate(publicKey: Uint8Array, eseed?: Uint8Array): { ct: Uint8Array; ss: Uint8Array }
  xwingDecapsulate(ct: Uint8Array, seed: Uint8Array): Uint8Array

  // SUITE.md 1.2 ML-DSA-65, pure, hedged, always with a context string
  mldsaKeygen(seed?: Uint8Array): SigKeyPair
  mldsaSign(seed: Uint8Array, msg: Uint8Array, ctx: Uint8Array): Uint8Array
  mldsaVerify(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array, ctx: Uint8Array): boolean

  // SUITE.md 1 pure Ed25519 (RFC 8032), verification only on clients
  ed25519Verify(publicKey: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean

  // SUITE.md 1 AES-256-GCM, 12-byte nonce, tag appended. Decrypt throws on any failure.
  aesGcmEncrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array>
  aesGcmDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Promise<Uint8Array>

  // SUITE.md 3 HKDF-SHA-384, SUITE.md 1 HMAC-SHA-384 and SHA-256
  hkdfSha384(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array>
  hmacSha384(key: Uint8Array, msg: Uint8Array): Promise<Uint8Array>
  sha256(data: Uint8Array): Promise<Uint8Array>
  /** Synchronous SHA-256 (noble) for hot loops such as Merkle walks. Same output as `sha256`. */
  sha256Sync(data: Uint8Array): Uint8Array
  /** Incremental SHA-256 for ciphertext_sha256 over many chunks (SUITE.md 7.1). */
  sha256Stream(): { update(data: Uint8Array): void; digest(): Uint8Array }

  // SUITE.md 15 Argon2id v0x13
  argon2id(password: Uint8Array, salt: Uint8Array, params: Argon2Params): Promise<Uint8Array>

  randomBytes(n: number): Uint8Array
}

let current: CryptoProvider | null = null

/** The provider used for device keys and every QG-1 operation in this browser. */
export function getProvider(): CryptoProvider {
  if (!current) current = createNobleProvider()
  return current
}
