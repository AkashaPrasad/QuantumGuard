import { ed25519 } from '@noble/curves/ed25519.js'
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { describe, expect, it } from 'vitest'
import type { VerifyStep } from '../client/client'
import type { Checkpoint, Receipt } from '../client/types'
import { b64u, fromB64u } from './b64u'
import { concat, fromHex, toHex, utf8 } from './bytes'
import { canon } from './canonical'
import { leafHash, nodeHash, rootFromLeafHashes, verifyConsistency, verifyInclusion } from './merkle'
import { context, signingInput, verifyDual, type ServerKeys, type ServerPurpose } from './suite'
import { describeVector, loadVector } from './test-vectors'
import { receiptLeafHash, verifyCheckpoint, verifyProofBundle, verifyReceiptProof } from './verify'

interface MerkleDoc {
  leaves_hex: string[]
  leaf_hashes_b64u: string[]
  roots: { tree_size: number; root_b64u: string }[]
  inclusion: { leaf_index: number; tree_size: number; audit_path_b64u: string[] }[]
  consistency: { from: number; to: number; proof_b64u: string[] }[]
  receipt_leaf: { receipt: Receipt; leaf_hex: string; leaf_hash_b64u: string }
}

interface CheckpointDoc {
  server_keys: { ed25519_seed: string; mldsa_seed: string; ed25519_pk: string; mldsa_pk: string }
  ed25519_signing_input_hex: string
  checkpoint: Checkpoint
  must_fail: { why: string; checkpoint: unknown }[]
}

describeVector<MerkleDoc>('merkle.json', (doc) => {
  const hashes = doc.leaves_hex.map((h) => leafHash(fromHex(h)))
  const rootOf = (n: number) => fromB64u(doc.roots.find((r) => r.tree_size === n)!.root_b64u)

  it('leaf hashes', () => {
    expect(hashes.map(b64u)).toEqual(doc.leaf_hashes_b64u)
  })
  it('roots for sizes 0..9', () => {
    for (const r of doc.roots) expect(b64u(rootFromLeafHashes(hashes.slice(0, r.tree_size))), `size ${r.tree_size}`).toBe(r.root_b64u)
  })
  it('every inclusion proof verifies, and fails for another leaf or a changed path', () => {
    for (const p of doc.inclusion) {
      const path = p.audit_path_b64u.map((x) => fromB64u(x))
      const root = rootOf(p.tree_size)
      expect(verifyInclusion(p.leaf_index, p.tree_size, hashes[p.leaf_index], path, root), `${p.leaf_index}/${p.tree_size}`).toBe(true)
      if (p.tree_size > 1) {
        const other = hashes[(p.leaf_index + 1) % p.tree_size]
        expect(verifyInclusion(p.leaf_index, p.tree_size, other, path, root)).toBe(false)
        const bad = path.map((x, i) => (i === 0 ? leafHash(utf8('x')) : x))
        expect(verifyInclusion(p.leaf_index, p.tree_size, hashes[p.leaf_index], bad, root)).toBe(false)
        expect(verifyInclusion(p.leaf_index + p.tree_size, p.tree_size, hashes[p.leaf_index], path, root)).toBe(false)
      }
    }
  })
  it('every consistency proof verifies, and fails with a wrong old root', () => {
    for (const c of doc.consistency) {
      const proof = c.proof_b64u.map((x) => fromB64u(x))
      expect(verifyConsistency(c.from, c.to, rootOf(c.from), rootOf(c.to), proof), `${c.from}->${c.to}`).toBe(true)
      if (c.from !== c.to) expect(verifyConsistency(c.from, c.to, rootOf(c.to), rootOf(c.to), proof)).toBe(false)
    }
  })
  it('receipt leaf is canon(receipt)', () => {
    const r = doc.receipt_leaf
    expect(toHex(canon(r.receipt))).toBe(r.leaf_hex)
    expect(receiptLeafHash(r.receipt)).toBe(r.leaf_hash_b64u)
  })
})

describeVector<CheckpointDoc>('checkpoint.json', (doc) => {
  const keys: ServerKeys = { ed25519_pk: doc.server_keys.ed25519_pk, mldsa_pk: doc.server_keys.mldsa_pk }
  it('server keys derive from their seeds', () => {
    expect(b64u(ed25519.getPublicKey(fromHex(doc.server_keys.ed25519_seed)))).toBe(keys.ed25519_pk)
    expect(b64u(ml_dsa65.keygen(fromHex(doc.server_keys.mldsa_seed)).publicKey)).toBe(keys.mldsa_pk)
  })
  it('Ed25519 signing input is ctx || 0x00 || canon(body)', () => {
    expect(toHex(concat(context('checkpoint'), new Uint8Array([0]), signingInput(doc.checkpoint as unknown as Record<string, unknown>)))).toBe(doc.ed25519_signing_input_hex)
  })
  it('checkpoint verifies under the dual-signature rule', () => {
    const steps: VerifyStep[] = []
    expect(verifyCheckpoint(doc.checkpoint, keys, (s) => steps.push(s))).toBe(true)
    expect(steps).toEqual([
      { kind: 'signature', alg: 'ed25519', ok: true },
      { kind: 'signature', alg: 'mldsa', ok: true },
    ])
  })
  it.each(doc.must_fail.map((f) => [f.why, f] as const))('rejects: %s', (_w, f) => {
    expect(verifyCheckpoint(f.checkpoint, keys)).toBe(false)
  })
})

// ---- proof bundles, signed locally with the checkpoint vector's throwaway server keys --------

const cpDoc = loadVector<CheckpointDoc>('checkpoint.json')

describe.skipIf(!cpDoc)(`proof bundle verification (local, uses checkpoint.json keys${cpDoc ? '' : '; MISSING'})`, () => {
  if (!cpDoc) return
  const sk = cpDoc.server_keys
  const keys: ServerKeys = { ed25519_pk: sk.ed25519_pk, mldsa_pk: sk.mldsa_pk }

  function dualSign<T extends Record<string, unknown>>(obj: T, p: ServerPurpose): T & { signatures: { ed25519: string; mldsa: string } } {
    const m = signingInput(obj)
    const ctx = context(p)
    return {
      ...obj,
      signatures: {
        ed25519: b64u(ed25519.sign(concat(ctx, new Uint8Array([0]), m), fromHex(sk.ed25519_seed))),
        mldsa: b64u(ml_dsa65.sign(m, ml_dsa65.keygen(fromHex(sk.mldsa_seed)).secretKey, { context: ctx })),
      },
    }
  }

  function receipt(i: number): Receipt {
    return {
      suite: 'QG-1',
      id: `rcp_${String(i).padStart(22, 'A')}`,
      ts: '2026-11-26T12:00:00.000Z',
      request_hash: b64u(new Uint8Array(32).fill(i)),
      subject: { user_id: 'usr_x', device_id: 'dev_x', session_id: null },
      action: i === 0 ? 'device.revoke' : 'slot.release',
      resource: 'fil_x',
      policy_bundle_hash: b64u(new Uint8Array(32)),
      matched_rules: ['R'],
      decision: i % 2 ? 'deny' : 'allow',
      reason_code: 'ok',
      key_epoch: 1,
      directory_epoch: 3,
      leaf_index: i,
    }
  }

  // RFC 6962 inclusion path for leaf m in hashes (test oracle)
  function path(m: number, hs: Uint8Array[]): Uint8Array[] {
    if (hs.length <= 1) return []
    let k = 1
    while (k * 2 < hs.length) k *= 2
    return m < k ? [...path(m, hs.slice(0, k)), rootFromLeafHashes(hs.slice(k))] : [...path(m - k, hs.slice(k)), rootFromLeafHashes(hs.slice(0, k))]
  }
  function subproof(m: number, hs: Uint8Array[], b: boolean): Uint8Array[] {
    const n = hs.length
    if (m === n) return b ? [] : [rootFromLeafHashes(hs)]
    let k = 1
    while (k * 2 < n) k *= 2
    return m <= k ? [...subproof(m, hs.slice(0, k), b), rootFromLeafHashes(hs.slice(k))] : [...subproof(m - k, hs.slice(k), false), rootFromLeafHashes(hs.slice(0, k))]
  }

  function makeBundle(n = 7, revAt = 4) {
    const receipts = Array.from({ length: n }, (_, i) => receipt(i))
    const hs = receipts.map((r) => leafHash(canon(r)))
    const cp = dualSign({ root_hash: b64u(rootFromLeafHashes(hs)), suite: 'QG-1' as const, tree_size: n, ts: '2026-11-26T12:00:09.000Z' }, 'checkpoint')
    const rcp = dualSign({ root_hash: b64u(rootFromLeafHashes(hs.slice(0, revAt))), suite: 'QG-1' as const, tree_size: revAt, ts: '2026-11-26T12:00:05.000Z' }, 'checkpoint')
    const body = {
      format: 'qg-proof-bundle/1',
      suite: 'QG-1',
      incident_id: 'inc_x',
      generated_at: '2026-11-26T12:00:10.000Z',
      server_keys: keys,
      checkpoint: cp,
      revocation_checkpoint: rcp,
      consistency: subproof(revAt, hs, true).map(b64u),
      directory: dualSign({ suite: 'QG-1', epoch: 3 }, 'directory'),
      exposure: { incident_id: 'inc_x' },
      entries: receipts.map((r, i) => ({ leaf_index: i, leaf_hash: b64u(hs[i]), receipt: r, audit_path: path(i, hs).map(b64u) })),
    }
    return { bundle: dualSign(body, 'report'), body, receipts, hs, cp }
  }

  it('a correct bundle verifies with pinned keys and emits every step', () => {
    const { bundle } = makeBundle()
    const steps: VerifyStep[] = []
    const r = verifyProofBundle(bundle, keys, (s) => steps.push(s))
    expect(r).toMatchObject({ ok: true, checked: 7, failed_index: null, reason: null })
    expect(steps.filter((s) => s.kind === 'receipt').length).toBe(7)
    expect(steps.filter((s) => s.kind === 'root').every((s) => s.kind === 'root' && s.ok)).toBe(true)
    expect(steps.filter((s) => s.kind === 'signature').length).toBe(6)
  })

  it('without pinned keys it verifies but says so', () => {
    expect(verifyProofBundle(makeBundle().bundle, null)).toMatchObject({ ok: true, reason: 'keys_from_bundle_only' })
  })

  it('a tampered receipt reports its leaf index (report re-signed so only the leaf is wrong)', () => {
    for (const bad of [0, 3, 6]) {
      const { body } = makeBundle()
      const entries = body.entries.map((e) => ({ ...e, receipt: { ...e.receipt } }))
      entries[bad].receipt.decision = entries[bad].receipt.decision === 'allow' ? 'deny' : 'allow'
      const r = verifyProofBundle(dualSign({ ...body, entries }, 'report'), keys)
      expect(r).toMatchObject({ ok: false, failed_index: bad, checked: bad, reason: 'leaf_hash_mismatch' })
    }
  })

  it('a tampered leaf hash with a matching receipt fails inclusion at the right index', () => {
    const { body } = makeBundle()
    const entries = body.entries.map((e) => ({ ...e }))
    const forged = { ...entries[5].receipt, reason_code: 'forged' }
    entries[5] = { ...entries[5], receipt: forged, leaf_hash: receiptLeafHash(forged) }
    expect(verifyProofBundle(dualSign({ ...body, entries }, 'report'), keys)).toMatchObject({ ok: false, failed_index: 5, reason: 'inclusion_failed' })
  })

  it('a tampered receipt without re-signing is still reported by its index (entries before the report signature, SUITE.md 9.4)', () => {
    const { bundle } = makeBundle()
    const entries = bundle.entries.map((e) => ({ ...e, receipt: { ...e.receipt } }))
    entries[2]!.receipt.decision = entries[2]!.receipt.decision === 'allow' ? 'deny' : 'allow'
    expect(verifyProofBundle({ ...bundle, entries }, keys)).toMatchObject({ ok: false, failed_index: 2, checked: 2, reason: 'leaf_hash_mismatch' })
  })

  it('an unsigned or re-signed-by-someone-else directory fails after everything else', () => {
    const { body } = makeBundle()
    expect(verifyProofBundle(dualSign({ ...body, directory: { suite: 'QG-1', epoch: 3 } }, 'report'), keys)).toMatchObject({ ok: false, reason: 'directory_signature', checked: 7 })
  })

  it('a changed bundle without re-signing fails the report signature', () => {
    const { bundle } = makeBundle()
    expect(verifyProofBundle({ ...bundle, incident_id: 'inc_y' }, keys)).toMatchObject({ ok: false, reason: 'report_signature' })
  })

  it('foreign server keys are refused when keys are pinned', () => {
    const { bundle } = makeBundle()
    const other = { ...keys, ed25519_pk: b64u(ed25519.getPublicKey(new Uint8Array(32).fill(1))) }
    expect(verifyProofBundle(bundle, other)).toMatchObject({ ok: false, reason: 'server_key_mismatch' })
  })

  it('a wrong consistency proof fails', () => {
    const { body } = makeBundle()
    const consistency = [b64u(leafHash(utf8('x'))), ...body.consistency.slice(1)]
    expect(verifyProofBundle(dualSign({ ...body, consistency }, 'report'), keys)).toMatchObject({ ok: false, reason: 'consistency_failed' })
  })

  it('bad format and suite', () => {
    expect(verifyProofBundle({ format: 'x' }, keys).reason).toBe('bad_format')
    expect(verifyProofBundle({ ...makeBundle().bundle, suite: 'QG-2' }, keys).reason).toBe('bad_suite')
  })

  it('single receipt proof verification emits node steps and checks the checkpoint', () => {
    const { receipts, hs, cp } = makeBundle()
    const proof = { leaf_index: 2, tree_size: 7, leaf_hash: b64u(hs[2]), audit_path: path(2, hs).map(b64u), checkpoint: cp }
    const steps: VerifyStep[] = []
    expect(verifyReceiptProof(receipts[2], proof, keys, (s) => steps.push(s)).ok).toBe(true)
    expect(steps.filter((s) => s.kind === 'node').length).toBe(proof.audit_path.length)
    expect(verifyReceiptProof({ ...receipts[2], action: 'x' }, proof, keys)).toMatchObject({ ok: false, failed_index: 2 })
    expect(verifyReceiptProof(receipts[2], { ...proof, checkpoint: { ...cp, tree_size: 6 } }, keys).reason).toBe('checkpoint_signature')
    expect(verifyDual(cp, keys, 'directory').ok).toBe(false)
  })

  it('node hashing uses the 0x01 prefix', () => {
    const a = leafHash(utf8('a'))
    const b = leafHash(utf8('b'))
    expect(toHex(nodeHash(a, b))).toBe(toHex(rootFromLeafHashes([a, b])))
  })
})
