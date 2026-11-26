// Byte-for-byte checks of the change, approval, message and policy statements. The expected strings
// were produced by the server's own code (backend/qg/api/changes.py, backend/qg/api/messages.py
// `statement`, backend/qg/crypto/encoding.py `canon`), so a drift on either side fails here.
import { ed25519 } from '@noble/curves/ed25519.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { describe, expect, it } from 'vitest'
import { b64u } from './b64u'
import { concat, fromUtf8, utf8 } from './bytes'
import { canon } from './canonical'
import { messageStatement, openMessage, sealMessage } from './envelope'
import { getProvider } from './provider'
import { approvalStatement, changeHash, changeStatement, isChangeStatement, verifyPolicy } from './statements'
import { context, verifyDualBytes } from './suite'

const prov = getProvider()

describe('change statement (SUITE.md 10)', () => {
  const change = changeStatement({
    type: 'role_grant',
    target_user_id: 'usr_DDDDDDDDDDDDDDDDDDDDDD',
    role: 'auditor',
    reason: 'Daniel joins the quarterly review — ü',
    directory_epoch: 7,
  })

  it('canonical bytes and change_hash match the server', async () => {
    expect(fromUtf8(canon(change))).toBe(
      '{"directory_epoch":7,"file_id":null,"reason":"Daniel joins the quarterly review — ü","role":"auditor","suite":"QG-1","target_user_id":"usr_DDDDDDDDDDDDDDDDDDDDDD","type":"role_grant"}',
    )
    expect(await changeHash(change)).toBe('1WBNzSd8DBnI_12moeF0sjyzR2_hcl3EfvnBRrhaqeM')
  })

  it('approval statement bytes match the server', async () => {
    const a = approvalStatement(await changeHash(change), 'chg_EEEEEEEEEEEEEEEEEEEEEE')
    expect(fromUtf8(canon(a))).toBe(
      '{"change_hash":"1WBNzSd8DBnI_12moeF0sjyzR2_hcl3EfvnBRrhaqeM","change_id":"chg_EEEEEEEEEEEEEEEEEEEEEE","decision":"approve","purpose":"approve","suite":"QG-1"}',
    )
  })

  it('accepts only exact statements', () => {
    expect(isChangeStatement(change)).toBe(true)
    expect(isChangeStatement({ ...change, roles: ['admin'] })).toBe(false)
    expect(isChangeStatement({ ...change, suite: 'QG-2' })).toBe(false)
    const { reason: _r, ...missing } = change
    expect(isChangeStatement(missing)).toBe(false)
  })

  it('a requester signature covers canon(change) with purpose change', () => {
    const kp = prov.mldsaKeygen()
    const sig = prov.mldsaSign(kp.seed, canon(change), context('change'))
    expect(prov.mldsaVerify(kp.publicKey, canon(change), sig, context('change'))).toBe(true)
    expect(prov.mldsaVerify(kp.publicKey, canon({ ...change, role: 'admin' }), sig, context('change'))).toBe(false)
  })
})

describe('message statement and envelope (SUITE.md 11)', () => {
  it('statement bytes match the server (envelopes sorted by device_id)', () => {
    const envs = [
      { device_id: 'dev_BBBBBBBBBBBBBBBBBBBBBB', xwing_ct: 'Y3Qy', ciphertext: 'Ym9keTI' },
      { device_id: 'dev_AAAAAAAAAAAAAAAAAAAAAA', xwing_ct: 'Y3Qx', ciphertext: 'Ym9keTE' },
    ]
    expect(fromUtf8(messageStatement('usr_CCCCCCCCCCCCCCCCCCCCCC', envs))).toBe(
      '{"envelopes":[{"ciphertext":"Ym9keTE","device_id":"dev_AAAAAAAAAAAAAAAAAAAAAA","xwing_ct":"Y3Qx"},{"ciphertext":"Ym9keTI","device_id":"dev_BBBBBBBBBBBBBBBBBBBBBB","xwing_ct":"Y3Qy"}],"suite":"QG-1","to_user_id":"usr_CCCCCCCCCCCCCCCCCCCCCC"}',
    )
  })

  it('a recipient with one device opens the server-shaped envelope and checks the signature', async () => {
    const recipient = prov.xwingKeygen()
    const sender = prov.mldsaKeygen()
    const env = await sealMessage(recipient.publicKey, 'dev_R', 'usr_R', utf8('meet at 3'))
    const signature = prov.mldsaSign(sender.seed, messageStatement('usr_R', [env]), context('message'))
    // What GET /messages returns: no device_id in the envelope.
    const wire = { xwing_ct: env.xwing_ct, ciphertext: env.ciphertext }
    expect(fromUtf8(await openMessage(recipient.seed, wire, 'dev_R', 'usr_R'))).toBe('meet at 3')
    const rebuilt = messageStatement('usr_R', [{ ...wire, device_id: 'dev_R' }])
    expect(prov.mldsaVerify(sender.publicKey, rebuilt, signature, context('message'))).toBe(true)
  })
})

describe('policy bundle (SUITE.md 13)', () => {
  const edSeed = prov.randomBytes(32)
  const mlSeed = prov.randomBytes(32)
  const keys = { ed25519_pk: b64u(ed25519.getPublicKey(edSeed)), mldsa_pk: b64u(ml_dsa65.keygen(mlSeed).publicKey) }
  const rules = [{ actions: ['file.open'], conditions: { decoy: false }, description: 'Owners and recipients open', effect: 'allow', id: 'P-OPEN', roles: ['*'] }]
  const doc = { rules, suite: 'QG-1', version: 3 }
  const bytes = canon(doc)
  const ctx = context('policy')
  const signatures = {
    ed25519: b64u(ed25519.sign(concat(ctx, new Uint8Array([0]), bytes), edSeed)),
    mldsa: b64u(ml_dsa65.sign(bytes, ml_dsa65.keygen(mlSeed).secretKey, { context: ctx })),
  }
  const view = { bundle_hash: b64u(prov.sha256Sync(bytes)), version: 3, signed_at: '2026-11-26T12:00:00.000Z', signatures, document: b64u(bytes), rules }

  it('accepts the signed document and the rules shown from it', async () => {
    expect(verifyDualBytes(bytes, signatures, keys, 'policy').ok).toBe(true)
    const r = await verifyPolicy(view, keys)
    expect(r.ok).toBe(true)
  })

  it('refuses a missing document, a wrong hash, a bad signature or rules that differ', async () => {
    const reason = async (v: Parameters<typeof verifyPolicy>[0]) => {
      const r = await verifyPolicy(v, keys)
      return r.ok ? 'ok' : r.reason
    }
    expect(await reason({ ...view, document: undefined })).toBe('policy_document_missing')
    expect(await reason({ ...view, bundle_hash: b64u(new Uint8Array(32)) })).toBe('policy_hash')
    expect(await reason({ ...view, signatures: { ...signatures, ed25519: signatures.mldsa.slice(0, 86) } })).toBe('policy_signature')
    expect(await reason({ ...view, signatures: { mldsa: signatures.mldsa } })).toBe('policy_signature')
    expect(await reason({ ...view, rules: [{ ...rules[0], effect: 'deny' }] })).toBe('policy_rules_mismatch')
    expect(await reason({ ...view, version: 4 })).toBe('policy_rules_mismatch')
    const other = canon({ ...doc, version: 9 })
    expect(await reason({ ...view, document: b64u(other), bundle_hash: b64u(prov.sha256Sync(other)) })).toBe('policy_signature')
  })
})
