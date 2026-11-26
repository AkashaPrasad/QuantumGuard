// SUITE.md 1, 3 and 4: suite constants, signature contexts and the dual-signature rule.
import { fromB64u } from './b64u'
import { utf8 } from './bytes'
import { canon } from './canonical'
import { ED25519_PK_BYTES, MLDSA_PK_BYTES } from './noble'
import { getProvider, type CryptoProvider } from './provider'

export const SUITE = 'QG-1'
export const CHUNK_BYTES = 1048576
export const RECOVERY_DEVICE_ID = 'recovery'

/** SUITE.md 3: HKDF info labels. */
export const INFO = {
  enrollConfirm: 'QG/v1/enroll/confirm',
  sessionConfirm: 'QG/v1/session/confirm',
  sessionMac: 'QG/v1/session/mac',
  wrap: 'QG/v1/wrap',
  message: 'QG/v1/message',
} as const

export type DevicePurpose = 'enroll' | 'session' | 'manifest' | 'share' | 'change' | 'message'
export type ServerPurpose = 'certificate' | 'directory' | 'checkpoint' | 'keyset' | 'policy' | 'report'
export type Purpose = DevicePurpose | ServerPurpose

export interface ServerKeys {
  ed25519_pk: string
  mldsa_pk: string
}

export class SuiteError extends Error {
  readonly code: string
  constructor(code: string, message: string) {
    super(message)
    this.name = 'SuiteError'
    this.code = code
  }
}

/** SUITE.md 4: ctx = ascii("QG/v1/" + p). */
export function context(p: Purpose): Uint8Array {
  return utf8('QG/v1/' + p)
}

/** SUITE.md 1: reject anything that is not "suite": "QG-1". */
export function assertSuite(obj: unknown): void {
  if (!obj || typeof obj !== 'object' || (obj as { suite?: unknown }).suite !== SUITE) {
    throw new SuiteError('QG_BAD_SUITE', 'suite is not QG-1')
  }
}

/** SUITE.md 4: signing input M = canon(object without its signature field). */
export function signingInput(obj: Record<string, unknown>, sigField = 'signatures'): Uint8Array {
  const rest: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(obj)) if (k !== sigField) rest[k] = v
  return canon(rest)
}

/** SUITE.md 4: device ML-DSA signature over canon(obj) with purpose p, returned as raw bytes. */
export function signDevice(sigSeed: Uint8Array, p: DevicePurpose, message: Uint8Array, prov: CryptoProvider = getProvider()): Uint8Array {
  return prov.mldsaSign(sigSeed, message, context(p))
}

/** SUITE.md 4: verify a device ML-DSA signature with purpose p. */
export function verifyDevice(sigPk: Uint8Array, p: DevicePurpose, message: Uint8Array, sig: Uint8Array, prov: CryptoProvider = getProvider()): boolean {
  return prov.mldsaVerify(sigPk, message, sig, context(p))
}

export interface DualResult {
  ed25519: boolean
  mldsa: boolean
  ok: boolean
}

/**
 * SUITE.md 4 dual-signature rule: both Ed25519 over ctx || 0x00 || M and ML-DSA over M with ctx
 * must verify under the server keys; missing, malformed or extra members fail.
 */
export function verifyDual(obj: unknown, keys: ServerKeys, p: ServerPurpose, prov: CryptoProvider = getProvider()): DualResult {
  const fail = { ed25519: false, mldsa: false, ok: false }
  if (!obj || typeof obj !== 'object') return fail
  const o = obj as Record<string, unknown>
  const sigs = o.signatures as Record<string, unknown> | undefined
  if (!sigs || typeof sigs !== 'object' || Array.isArray(sigs)) return fail
  const names = Object.keys(sigs).sort()
  if (names.length !== 2 || names[0] !== 'ed25519' || names[1] !== 'mldsa') return fail
  if (typeof sigs.ed25519 !== 'string' || typeof sigs.mldsa !== 'string') return fail
  let m: Uint8Array
  let edPk: Uint8Array, mlPk: Uint8Array, edSig: Uint8Array, mlSig: Uint8Array
  try {
    m = signingInput(o)
    edPk = fromB64u(keys.ed25519_pk, ED25519_PK_BYTES)
    mlPk = fromB64u(keys.mldsa_pk, MLDSA_PK_BYTES)
    edSig = fromB64u(sigs.ed25519)
    mlSig = fromB64u(sigs.mldsa)
  } catch {
    return fail
  }
  const ctx = context(p)
  const edMsg = new Uint8Array(ctx.length + 1 + m.length)
  edMsg.set(ctx, 0)
  edMsg[ctx.length] = 0
  edMsg.set(m, ctx.length + 1)
  const ed = prov.ed25519Verify(edPk, edMsg, edSig)
  const ml = prov.mldsaVerify(mlPk, m, mlSig, ctx)
  return { ed25519: ed, mldsa: ml, ok: ed && ml }
}
