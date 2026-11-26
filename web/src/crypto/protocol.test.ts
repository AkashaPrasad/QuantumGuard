import { expect, it } from 'vitest'
import { b64u, fromB64u } from './b64u'
import { fromHex, toHex, utf8 } from './bytes'
import { getProvider } from './provider'
import { deriveEnrolConfirmKey, deriveSessionKeys, enrolTranscript, keyConfirm, macInput, requestHash, requestMac, sessionTranscript, type EnrolTranscriptInput, type SessionTranscriptInput } from './protocol'
import { context, verifyDevice } from './suite'
import { describeVector } from './test-vectors'

const prov = getProvider()

interface TranscriptDoc {
  device: { kem_seed: string; sig_seed: string; kem_pk_b64u: string; sig_pk_b64u: string }
  enroll: { fields: EnrolTranscriptInput; ss: string; transcript_hex: string; k_ec: string; key_confirm_b64u: string; signature_b64u: string }
  session: { fields: SessionTranscriptInput; ss: string; transcript_hex: string; k_sc: string; k_mac: string; key_confirm_b64u: string; signature_b64u: string }
}

describeVector<TranscriptDoc>('transcripts.json', (doc) => {
  const kemSeed = fromHex(doc.device.kem_seed)
  const sigPk = fromB64u(doc.device.sig_pk_b64u)

  it('device keys derive from the seeds', () => {
    expect(b64u(prov.xwingKeygen(kemSeed).publicKey)).toBe(doc.device.kem_pk_b64u)
    expect(b64u(prov.mldsaKeygen(fromHex(doc.device.sig_seed)).publicKey)).toBe(doc.device.sig_pk_b64u)
  })

  it('enrolment: decapsulate, transcript, K_ec, key_confirm, signature', async () => {
    const e = doc.enroll
    const ss = prov.xwingDecapsulate(fromB64u(e.fields.xwing_ct), kemSeed)
    expect(toHex(ss)).toBe(e.ss)
    const t = enrolTranscript(e.fields)
    expect(toHex(t)).toBe(e.transcript_hex)
    const kec = await deriveEnrolConfirmKey(ss, fromB64u(e.fields.challenge))
    expect(toHex(kec)).toBe(e.k_ec)
    expect(b64u(await keyConfirm(kec, t))).toBe(e.key_confirm_b64u)
    expect(verifyDevice(sigPk, 'enroll', t, fromB64u(e.signature_b64u))).toBe(true)
    expect(verifyDevice(sigPk, 'session', t, fromB64u(e.signature_b64u))).toBe(false)
    // our own hedged signature verifies under the same rule
    const mine = prov.mldsaSign(fromHex(doc.device.sig_seed), t, context('enroll'))
    expect(verifyDevice(sigPk, 'enroll', t, mine)).toBe(true)
  })

  it('session: decapsulate, transcript, K_sc, K_mac, key_confirm, signature', async () => {
    const s = doc.session
    const ss = prov.xwingDecapsulate(fromB64u(s.fields.xwing_ct), kemSeed)
    expect(toHex(ss)).toBe(s.ss)
    const t = sessionTranscript(s.fields)
    expect(toHex(t)).toBe(s.transcript_hex)
    const k = await deriveSessionKeys(ss, fromB64u(s.fields.challenge))
    expect(toHex(k.confirm)).toBe(s.k_sc)
    expect(toHex(k.mac)).toBe(s.k_mac)
    expect(b64u(await keyConfirm(k.confirm, t))).toBe(s.key_confirm_b64u)
    expect(verifyDevice(sigPk, 'session', t, fromB64u(s.signature_b64u))).toBe(true)
    expect(verifyDevice(sigPk, 'enroll', t, fromB64u(s.signature_b64u))).toBe(false)
  })
})

interface MacDoc {
  k_mac: string
  cases: { method: string; path: string; seq: number; body_hex: string; mac_input_hex: string; mac_b64u: string; request_hash_b64u: string }[]
}

describeVector<MacDoc>('request_mac.json', (doc) => {
  const k = fromHex(doc.k_mac)
  it.each(doc.cases.map((c) => [`${c.method} ${c.path}`, c] as const))('%s', async (_n, c) => {
    const body = fromHex(c.body_hex)
    expect(toHex(await macInput(c.method, c.path, c.seq, body))).toBe(c.mac_input_hex)
    expect(await requestMac(k, c.method, c.path, c.seq, body)).toBe(c.mac_b64u)
    expect(await requestHash(c.method, c.path, c.seq, body)).toBe(c.request_hash_b64u)
    // any change to the path, sequence or body changes the tag
    expect(await requestMac(k, c.method, c.path + 'x', c.seq, body)).not.toBe(c.mac_b64u)
    expect(await requestMac(k, c.method, c.path, c.seq === 1 ? 2 : c.seq - 1, body)).not.toBe(c.mac_b64u)
    expect(await requestMac(k, c.method, c.path, c.seq, utf8('x'))).not.toBe(c.mac_b64u)
  })
})
