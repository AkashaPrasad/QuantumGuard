// Enrolment (SUITE.md 5.1), keystore sealing (15) and sessions (5.2) for the real client.
import { QgError, type EnrolStep, type LocalDevice, type SessionInfo } from '../client'
import type * as T from '../types'
import { b64u, fromB64u } from '../../crypto/b64u'
import { wipe } from '../../crypto/bytes'
import { KeystoreError, openKeystore, sealKeystore, type DeviceSeeds, type StoredDevice } from '../../crypto/keystore'
import { deriveEnrolConfirmKey, deriveSessionKeys, enrolTranscript, keyConfirm, sessionTranscript } from '../../crypto/protocol'
import { SUITE, context, verifyDual, type ServerKeys } from '../../crypto/suite'
import { acceptDirectory, fetchMeta, findDevice, integrity, localDevice, setState, touch, type Ctx } from './context'

interface EnrollStartResponse {
  enroll_id: string
  challenge: string
  xwing_ct: string
  user: { user_id: string; name: string; roles: T.Role[] }
  directory_epoch: number
  server_time: string
}

interface SessionStartResponse {
  start_id: string
  challenge: string
  xwing_ct: string
  directory_epoch: number
  server_time: string
}

interface SessionFinishResponse {
  session_id: string
  expires_at: string
  hard_expires_at: string
  user: { user_id: string; name: string; roles: T.Role[]; status: string }
  device: { device_id: string; name: string }
  directory_epoch: number
  first_session: boolean
}

type SignedCertificate = T.Certificate & { signatures: T.Signatures }

/** SUITE.md 8.2: the issued certificate is dual-signed and carries exactly the keys we generated. */
function checkCertificate(cert: SignedCertificate, keys: ServerKeys, expect: { kem_pk: string; sig_pk: string; user_id: string }, ctx: Ctx): void {
  if (!cert || cert.suite !== SUITE || !verifyDual(cert, keys, 'certificate', ctx.prov).ok) throw integrity('certificate_signature')
  if (cert.kem_pk !== expect.kem_pk || cert.sig_pk !== expect.sig_pk || cert.user_id !== expect.user_id) {
    throw integrity('certificate_mismatch')
  }
}

/** SUITE.md 5.1: generate keys, prove possession, receive the certificate, seal the keystore, start a session. */
export async function enrol(ctx: Ctx, input: { code: string; device_name: string; passphrase: string }, onStep?: (s: EnrolStep) => void): Promise<LocalDevice> {
  if (ctx.stored) throw new QgError({ code: 'QG_CONFLICT', message: 'This browser is already enrolled.', reason: 'already_enrolled' })
  onStep?.('generating_keys')
  const kem = ctx.prov.xwingKeygen()
  const sig = ctx.prov.mldsaKeygen()
  const seeds: DeviceSeeds = { kem_seed: kem.seed, sig_seed: sig.seed }
  try {
    const meta = await fetchMeta(ctx)
    const keys: ServerKeys = { ed25519_pk: meta.server_keys.ed25519_pk, mldsa_pk: meta.server_keys.mldsa_pk }
    const kemPk = b64u(kem.publicKey)
    const sigPk = b64u(sig.publicKey)
    const { data: st } = await ctx.http.public<EnrollStartResponse>('POST', '/api/v1/enroll/start', {
      json: { suite: SUITE, code: input.code, device_name: input.device_name, kem_pk: kemPk, sig_pk: sigPk },
    })

    onStep?.('proving_possession')
    const transcript = enrolTranscript({
      challenge: st.challenge, device_name: input.device_name, directory_epoch: st.directory_epoch, enroll_id: st.enroll_id,
      kem_pk: kemPk, server_time: st.server_time, sig_pk: sigPk, user_id: st.user.user_id, xwing_ct: st.xwing_ct,
    })
    const ss = ctx.prov.xwingDecapsulate(fromB64u(st.xwing_ct, 1120), kem.seed)
    const kec = await deriveEnrolConfirmKey(ss, fromB64u(st.challenge, 32), ctx.prov)
    const confirm = await keyConfirm(kec, transcript, ctx.prov)
    wipe(ss, kec)
    const signature = ctx.prov.mldsaSign(sig.seed, transcript, context('enroll'))
    const { data: fin } = await ctx.http.public<{ certificate: SignedCertificate; directory: T.Directory }>('POST', '/api/v1/enroll/finish', {
      json: { enroll_id: st.enroll_id, signature: b64u(signature), key_confirm: b64u(confirm) },
    })

    checkCertificate(fin.certificate, keys, { kem_pk: kemPk, sig_pk: sigPk, user_id: st.user.user_id }, ctx)
    const dir = await acceptDirectory(ctx, fin.directory, keys, { current: true })
    if (!findDevice(dir, fin.certificate.device_id)) throw integrity('device_not_in_directory')
    onStep?.('certificate_issued')

    onStep?.('sealing_keystore')
    const label = {
      user_id: st.user.user_id,
      device_id: fin.certificate.device_id,
      device_name: input.device_name,
      server: typeof location !== 'undefined' ? location.origin : null,
      created_at: fin.certificate.created_at,
    }
    const { file, key } = await sealKeystore(seeds, input.passphrase, label, { derive: ctx.derive }, ctx.prov)
    wipe(key)
    const stored: StoredDevice = {
      keystore: file,
      device: {
        device_id: fin.certificate.device_id,
        device_name: input.device_name,
        user_id: st.user.user_id,
        user_name: st.user.name,
        roles: st.user.roles,
        enrolled_at: fin.certificate.created_at,
      },
      server_keys: keys,
      highest_epoch: dir.epoch,
    }
    await ctx.store.save(stored)
    ctx.stored = stored
    ctx.keyring.load(seeds)
    setState(ctx, { kind: 'locked', device: localDevice(stored) })

    await startSession(ctx)
    onStep?.('session_started')
    return localDevice(ctx.stored)
  } finally {
    wipe(seeds.kem_seed, seeds.sig_seed)
  }
}

/** SUITE.md 15 + 5.2: open the keystore with the passphrase, then start a session. */
export async function unlock(ctx: Ctx, passphrase: string): Promise<SessionInfo> {
  const stored = ctx.stored
  if (!stored) throw new QgError({ code: 'QG_NO_SESSION', message: 'This browser is not enrolled.' })
  if (stored.revoked) throw new QgError({ code: 'QG_DENY_REVOKED', message: 'This device was revoked.' })
  let seeds: DeviceSeeds
  try {
    const opened = await openKeystore(stored.keystore, passphrase, ctx.derive, ctx.prov)
    wipe(opened.key)
    seeds = opened.seeds
  } catch (e) {
    if (e instanceof KeystoreError) throw new QgError({ code: 'QG_LOCAL_PASSPHRASE', message: 'That passphrase did not open this device’s keys.' })
    throw e
  }
  ctx.keyring.load(seeds)
  wipe(seeds.kem_seed, seeds.sig_seed)
  try {
    await fetchMeta(ctx)
    return await startSession(ctx)
  } catch (e) {
    ctx.keyring.lock()
    throw e
  }
}

/** SUITE.md 5.2: session start/finish with both proofs; K_mac kept in memory only. */
export async function startSession(ctx: Ctx): Promise<SessionInfo> {
  const stored = ctx.stored
  if (!stored) throw new QgError({ code: 'QG_NO_SESSION', message: 'This browser is not enrolled.' })
  const deviceId = stored.device.device_id
  const { data: st } = await ctx.http.public<SessionStartResponse>('POST', '/api/v1/session/start', { json: { suite: SUITE, device_id: deviceId } })
  const transcript = sessionTranscript({
    challenge: st.challenge, device_id: deviceId, directory_epoch: st.directory_epoch, server_time: st.server_time, start_id: st.start_id, xwing_ct: st.xwing_ct,
  })
  const ss = ctx.prov.xwingDecapsulate(fromB64u(st.xwing_ct, 1120), ctx.keyring.kemSeed())
  const keys = await deriveSessionKeys(ss, fromB64u(st.challenge, 32), ctx.prov)
  wipe(ss)
  const confirm = await keyConfirm(keys.confirm, transcript, ctx.prov)
  wipe(keys.confirm)
  const signature = ctx.prov.mldsaSign(ctx.keyring.sigSeed(), transcript, context('session'))
  let fin: SessionFinishResponse
  try {
    fin = (await ctx.http.public<SessionFinishResponse>('POST', '/api/v1/session/finish', {
      json: { start_id: st.start_id, signature: b64u(signature), key_confirm: b64u(confirm) },
    })).data
  } catch (e) {
    wipe(keys.mac)
    throw e
  }
  ctx.http.setSession({ sessionId: fin.session_id, macKey: keys.mac, seq: 0 })
  wipe(keys.mac)
  const updated: StoredDevice = {
    ...stored,
    device: { ...stored.device, device_name: fin.device?.name ?? stored.device.device_name, user_name: fin.user?.name ?? stored.device.user_name, roles: fin.user?.roles ?? stored.device.roles },
  }
  ctx.stored = updated
  await ctx.store.save(updated)
  const session: SessionInfo = { session_id: fin.session_id, expires_at: fin.expires_at, hard_expires_at: fin.hard_expires_at, first_session: fin.first_session }
  setState(ctx, { kind: 'unlocked', device: localDevice(updated), session })
  touch(ctx)
  return session
}

/** Zeroes the private keys at once; ends the server session and zeroes K_mac behind queued requests. */
export function lock(ctx: Ctx): void {
  ctx.keyring.lock()
  if (ctx.idleTimer) clearTimeout(ctx.idleTimer)
  ctx.idleTimer = null
  void ctx.http.endSession()
  if (ctx.stored && ctx.state.kind === 'unlocked') setState(ctx, { kind: 'locked', device: localDevice(ctx.stored) })
}

/** Marks this device revoked locally (server answered QG_DENY_REVOKED). */
export async function markRevoked(ctx: Ctx): Promise<void> {
  ctx.keyring.lock()
  ctx.http.clearSession()
  if (!ctx.stored) return
  ctx.stored = { ...ctx.stored, revoked: true }
  setState(ctx, { kind: 'revoked', device: localDevice(ctx.stored) })
  await ctx.store.save(ctx.stored)
}

/** Removes the wrapped keystore from this browser. */
export async function forgetDevice(ctx: Ctx): Promise<void> {
  ctx.keyring.lock()
  await ctx.http.endSession()
  ctx.http.clearSession()
  await ctx.store.clear()
  ctx.stored = null
  ctx.directories.clear()
  ctx.lastCheckpoint = null
  setState(ctx, { kind: 'none' })
}
