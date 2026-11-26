// SUITE.md 11 replayed from spec/vectors/messages.json: two recipient devices, each holding only its own
// envelope plus every envelope's digest, open their envelope and verify the sender's signature.
import { expect, it } from 'vitest'
import { b64u, fromB64u } from './b64u'
import { fromHex, toHex } from './bytes'
import { checkMessage, envelopeDigest, envelopeDigests, messageAad, messageKey, messageStatement, openMessage, type EnvelopeDigest, type MessageEnvelope } from './envelope'
import { getProvider } from './provider'
import { context } from './suite'
import { describeVector } from './test-vectors'

const prov = getProvider()

interface MessagesDoc {
  sender_sig_seed: string
  sender_sig_pk_b64u: string
  to_user_id: string
  plaintext_hex: string
  devices: { device_id: string; kem_seed: string; ss: string; aead_input: string; aad_hex: string; envelope_digest_b64u: string }[]
  envelopes: MessageEnvelope[]
  envelope_digests: EnvelopeDigest[]
  statement_hex: string
  signature_b64u: string
}

describeVector<MessagesDoc>('messages.json', (doc) => {
  const senderPk = fromB64u(doc.sender_sig_pk_b64u)

  it('sender key, digests and statement bytes', async () => {
    expect(b64u(prov.mldsaKeygen(fromHex(doc.sender_sig_seed)).publicKey)).toBe(doc.sender_sig_pk_b64u)
    expect(await envelopeDigests(doc.envelopes)).toEqual(doc.envelope_digests)
    expect(toHex(messageStatement(doc.to_user_id, doc.envelope_digests))).toBe(doc.statement_hex)
    expect(prov.mldsaVerify(senderPk, fromHex(doc.statement_hex), fromB64u(doc.signature_b64u), context('message'))).toBe(true)
  })

  it.each(doc.devices.map((d) => [d.device_id, d] as const))('device %s opens its envelope with only the digests', async (_id, d) => {
    const env = doc.envelopes.find((e) => e.device_id === d.device_id)!
    expect(await envelopeDigest(env)).toBe(d.envelope_digest_b64u)
    expect(toHex(prov.xwingDecapsulate(fromB64u(env.xwing_ct), fromHex(d.kem_seed)))).toBe(d.ss)
    expect(toHex(await messageKey(fromHex(d.ss)))).toBe(d.aead_input)
    expect(toHex(messageAad(d.device_id, doc.to_user_id))).toBe(d.aad_hex)
    // What GET /messages gives this device.
    const received = { to_user_id: doc.to_user_id, envelope: { xwing_ct: env.xwing_ct, ciphertext: env.ciphertext }, envelope_digests: doc.envelope_digests, signature: doc.signature_b64u }
    const self = { device_id: d.device_id, user_id: doc.to_user_id }
    expect(await checkMessage(received, self, senderPk)).toBe(true)
    expect(toHex(await openMessage(fromHex(d.kem_seed), received.envelope, d.device_id, doc.to_user_id))).toBe(doc.plaintext_hex)

    // Each of these is refused before decrypting.
    const other = doc.envelopes.find((e) => e.device_id !== d.device_id)!
    expect(await checkMessage({ ...received, envelope: { xwing_ct: other.xwing_ct, ciphertext: other.ciphertext } }, self, senderPk)).toBe(false)
    expect(await checkMessage(received, { ...self, user_id: 'usr_AAAAAAAAAAAAAAAAAAAAAA' }, senderPk)).toBe(false)
    expect(await checkMessage({ ...received, to_user_id: 'usr_AAAAAAAAAAAAAAAAAAAAAA' }, self, senderPk)).toBe(false)
    expect(await checkMessage({ ...received, envelope_digests: received.envelope_digests.filter((x) => x.device_id === d.device_id) }, self, senderPk)).toBe(false)
    expect(await checkMessage(received, self, null)).toBe(false)
    expect(await checkMessage(received, self, prov.mldsaKeygen().publicKey)).toBe(false)
  })
})
