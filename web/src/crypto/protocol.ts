// SUITE.md 3, 5 and 6: enrolment and session transcripts, derived keys, key confirmation and the
// request MAC. Pure functions over bytes; no network.
import { b64u } from './b64u'
import { concat, toHex, utf8 } from './bytes'
import { canon } from './canonical'
import { getProvider, type CryptoProvider } from './provider'
import { INFO, SUITE } from './suite'

export interface EnrolTranscriptInput {
  challenge: string
  device_name: string
  directory_epoch: number
  enroll_id: string
  kem_pk: string
  server_time: string
  sig_pk: string
  user_id: string
  xwing_ct: string
}

export interface SessionTranscriptInput {
  challenge: string
  device_id: string
  directory_epoch: number
  server_time: string
  start_id: string
  xwing_ct: string
}

/** SUITE.md 5.1 step 3: T_e. */
export function enrolTranscript(x: EnrolTranscriptInput): Uint8Array {
  return canon({
    challenge: x.challenge,
    device_name: x.device_name,
    directory_epoch: x.directory_epoch,
    enroll_id: x.enroll_id,
    kem_pk: x.kem_pk,
    purpose: 'enroll',
    server_time: x.server_time,
    sig_pk: x.sig_pk,
    suite: SUITE,
    user_id: x.user_id,
    xwing_ct: x.xwing_ct,
  })
}

/** SUITE.md 5.2 step 2: T_s. */
export function sessionTranscript(x: SessionTranscriptInput): Uint8Array {
  return canon({
    challenge: x.challenge,
    device_id: x.device_id,
    directory_epoch: x.directory_epoch,
    purpose: 'session',
    server_time: x.server_time,
    start_id: x.start_id,
    suite: SUITE,
    xwing_ct: x.xwing_ct,
  })
}

/** SUITE.md 3: K_ec = HKDF(ss, salt=challenge, "QG/v1/enroll/confirm", 48). */
export function deriveEnrolConfirmKey(ss: Uint8Array, challenge: Uint8Array, prov: CryptoProvider = getProvider()) {
  return prov.hkdfSha384(ss, challenge, utf8(INFO.enrollConfirm), 48)
}

/** SUITE.md 3: K_sc and K_mac from the session ss and challenge. */
export async function deriveSessionKeys(ss: Uint8Array, challenge: Uint8Array, prov: CryptoProvider = getProvider()) {
  const confirm = await prov.hkdfSha384(ss, challenge, utf8(INFO.sessionConfirm), 48)
  const mac = await prov.hkdfSha384(ss, challenge, utf8(INFO.sessionMac), 48)
  return { confirm, mac }
}

/** SUITE.md 5.1 step 4 / 5.2 step 3: key_confirm = HMAC-SHA-384(K, T). */
export function keyConfirm(key: Uint8Array, transcript: Uint8Array, prov: CryptoProvider = getProvider()) {
  return prov.hmacSha384(key, transcript)
}

/** SUITE.md 6: SEQ is decimal, no sign, no leading zeros, 1 <= SEQ <= 2^53-1 (0 for public hashes). */
function seqString(seq: number): string {
  if (!Number.isSafeInteger(seq) || seq < 0) throw new RangeError('bad sequence number')
  return String(seq)
}

/** SUITE.md 6: mac_input = METHOD \n PATH \n SEQ \n hex(SHA-256(body)). */
export async function macInput(method: string, path: string, seq: number, body: Uint8Array, prov: CryptoProvider = getProvider()): Promise<Uint8Array> {
  if (!path.startsWith('/api/v1/')) throw new Error('MAC path must start with /api/v1/')
  const bodyHash = toHex(await prov.sha256(body))
  const nl = new Uint8Array([0x0a])
  return concat(utf8(method.toUpperCase()), nl, utf8(path), nl, utf8(seqString(seq)), nl, utf8(bodyHash))
}

/** SUITE.md 6: QG-MAC = b64u(HMAC-SHA-384(K_mac, mac_input)). */
export async function requestMac(kMac: Uint8Array, method: string, path: string, seq: number, body: Uint8Array, prov: CryptoProvider = getProvider()): Promise<string> {
  if (seq < 1) throw new RangeError('QG-Seq must be >= 1')
  const input = await macInput(method, path, seq, body, prov)
  return b64u(await prov.hmacSha384(kMac, input))
}

/** SUITE.md 6: request_hash = b64u(SHA-256(mac_input)); public routes use SEQ = 0. */
export async function requestHash(method: string, path: string, seq: number, body: Uint8Array, prov: CryptoProvider = getProvider()): Promise<string> {
  return b64u(await prov.sha256(await macInput(method, path, seq, body, prov)))
}
