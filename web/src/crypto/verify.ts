// SUITE.md 4, 8.3, 9.3-9.5: verification of dual-signed trust records, receipts with inclusion
// proofs, and offline proof bundles. Emits VerifyStep events as each check runs.
import type { VerifyResult, VerifyStep } from '../client/client'
import type { Checkpoint, InclusionProof, Receipt } from '../client/types'
import { b64u, fromB64u } from './b64u'
import { ctEqual } from './bytes'
import { canon } from './canonical'
import { leafHash, rootFromInclusion, verifyConsistency } from './merkle'
import { getProvider, type CryptoProvider } from './provider'
import { SUITE, verifyDual, type ServerKeys, type ServerPurpose } from './suite'

export const BUNDLE_FORMAT = 'qg-proof-bundle/1'

type Emit = ((s: VerifyStep) => void) | undefined

function result(ok: boolean, checked: number, failedIndex: number | null, reason: string | null, checkpoint: Checkpoint | null): VerifyResult {
  return { ok, checked, failed_index: failedIndex, reason, checkpoint }
}

/** SUITE.md 4: verify a dual-signed object and emit one `signature` step per algorithm. */
export function verifyDualWithSteps(obj: unknown, keys: ServerKeys, purpose: ServerPurpose, emit: Emit, prov: CryptoProvider = getProvider()): boolean {
  const r = verifyDual(obj, keys, purpose, prov)
  emit?.({ kind: 'signature', alg: 'ed25519', ok: r.ed25519 })
  emit?.({ kind: 'signature', alg: 'mldsa', ok: r.mldsa })
  return r.ok
}

/** SUITE.md 9.3: checkpoint suite, shape and dual signature (purpose checkpoint). */
export function verifyCheckpoint(cp: unknown, keys: ServerKeys, emit?: Emit, prov: CryptoProvider = getProvider()): cp is Checkpoint {
  if (!cp || typeof cp !== 'object') return false
  const c = cp as Partial<Checkpoint>
  if (c.suite !== SUITE || !Number.isSafeInteger(c.tree_size) || typeof c.root_hash !== 'string') return false
  return verifyDualWithSteps(cp, keys, 'checkpoint', emit, prov)
}

/** SUITE.md 8.3: a directory is trusted only if suite and both signatures verify. */
export function verifyDirectorySignature(dir: unknown, keys: ServerKeys, prov: CryptoProvider = getProvider()): boolean {
  if (!dir || typeof dir !== 'object' || (dir as { suite?: unknown }).suite !== SUITE) return false
  return verifyDual(dir, keys, 'directory', prov).ok
}

/** SUITE.md 9.1: leaf_hash(canon(receipt)) as b64u. */
export function receiptLeafHash(receipt: Receipt, prov: CryptoProvider = getProvider()): string {
  return b64u(leafHash(canon(receipt), prov))
}

/**
 * SUITE.md 9.1/9.2: walk one receipt's audit path to the checkpoint root, emitting `receipt`,
 * `node` and `root` steps. Returns a failure reason or null.
 */
export function checkReceiptInclusion(receipt: Receipt, leafIndex: number, claimedLeafHash: string, auditPath: string[], cp: Checkpoint, emit: Emit, prov: CryptoProvider = getProvider()): string | null {
  if (!receipt || receipt.suite !== SUITE) return 'bad_suite'
  if (receipt.leaf_index !== leafIndex) return 'leaf_index_mismatch'
  let computed: Uint8Array
  try {
    computed = leafHash(canon(receipt), prov)
  } catch {
    return 'bad_receipt'
  }
  emit?.({ kind: 'receipt', receipt, leaf_hash: b64u(computed) })
  let claimed: Uint8Array, path: Uint8Array[], root: Uint8Array
  try {
    claimed = fromB64u(claimedLeafHash, 32)
    path = auditPath.map((p) => fromB64u(p, 32))
    root = fromB64u(cp.root_hash, 32)
  } catch {
    return 'bad_encoding'
  }
  if (!ctEqual(computed, claimed)) return 'leaf_hash_mismatch'
  const r = rootFromInclusion(leafIndex, cp.tree_size, computed, path, (s) =>
    emit?.({ kind: 'node', level: s.level, hash: b64u(s.hash), sibling: b64u(s.sibling), side: s.side }),
  prov)
  const ok = r !== null && ctEqual(r, root)
  emit?.({ kind: 'root', computed: r ? b64u(r) : '', signed: cp.root_hash, ok })
  return ok ? null : 'inclusion_failed'
}

/** SUITE.md 9.2/9.3: a receipt, its inclusion proof and the dual-signed checkpoint it names. */
export function verifyReceiptProof(receipt: Receipt, proof: InclusionProof, keys: ServerKeys, emit?: Emit, prov: CryptoProvider = getProvider()): VerifyResult {
  const cp = proof.checkpoint
  if (!verifyCheckpoint(cp, keys, emit, prov)) return result(false, 0, receipt.leaf_index, 'checkpoint_signature', null)
  if (proof.tree_size !== cp.tree_size) return result(false, 0, receipt.leaf_index, 'tree_size_mismatch', cp)
  if (proof.leaf_index !== receipt.leaf_index) return result(false, 0, receipt.leaf_index, 'leaf_index_mismatch', cp)
  const reason = checkReceiptInclusion(receipt, proof.leaf_index, proof.leaf_hash, proof.audit_path, cp, emit, prov)
  return reason ? result(false, 1, receipt.leaf_index, reason, cp) : result(true, 1, null, null, cp)
}

interface BundleEntry {
  leaf_index: number
  leaf_hash: string
  receipt: Receipt
  audit_path: string[]
}

function isServerKeys(k: unknown): k is ServerKeys {
  return !!k && typeof k === 'object' && typeof (k as ServerKeys).ed25519_pk === 'string' && typeof (k as ServerKeys).mldsa_pk === 'string'
}

/**
 * SUITE.md 9.4: offline proof bundle verification, stopping at the first failure, in the order the
 * spec fixes: format and suite; checkpoint dual signature; each entry's leaf hash and inclusion path
 * in leaf_index order (before the bundle signature, so a modified receipt is reported by its index);
 * the bundle's own dual signature (purpose report); revocation checkpoint signature and consistency
 * to the newest checkpoint; the directory's dual signature.
 * `pinned` keys are preferred; without them the bundle's own keys are used and `reason` says so.
 */
export function verifyProofBundle(bundle: unknown, pinned: ServerKeys | null, emit?: Emit, prov: CryptoProvider = getProvider()): VerifyResult {
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) return result(false, 0, null, 'bad_format', null)
  const b = bundle as Record<string, unknown>
  if (b.format !== BUNDLE_FORMAT) return result(false, 0, null, 'bad_format', null)
  if (b.suite !== SUITE) return result(false, 0, null, 'bad_suite', null)
  if (!isServerKeys(b.server_keys)) return result(false, 0, null, 'bad_format', null)
  if (pinned && (b.server_keys.ed25519_pk !== pinned.ed25519_pk || b.server_keys.mldsa_pk !== pinned.mldsa_pk)) {
    return result(false, 0, null, 'server_key_mismatch', null)
  }
  const keys = pinned ?? b.server_keys
  const cp = b.checkpoint
  if (!verifyCheckpoint(cp, keys, emit, prov)) return result(false, 0, null, 'checkpoint_signature', null)
  if (!Array.isArray(b.entries)) return result(false, 0, null, 'bad_format', cp)
  const entries = b.entries as BundleEntry[]
  let checked = 0
  let prev = -1
  for (const e of entries) {
    const idx = e && typeof e.leaf_index === 'number' ? e.leaf_index : null
    if (idx === null || idx <= prev || !Array.isArray(e.audit_path)) return result(false, checked, idx, 'bad_entry', cp)
    prev = idx
    const reason = checkReceiptInclusion(e.receipt, idx, e.leaf_hash, e.audit_path, cp, emit, prov)
    if (reason) return result(false, checked, idx, reason, cp)
    checked++
  }
  if (!verifyDualWithSteps(bundle, keys, 'report', emit, prov)) return result(false, checked, null, 'report_signature', cp)
  const rcp = b.revocation_checkpoint
  if (rcp !== undefined && rcp !== null) {
    if (!verifyCheckpoint(rcp, keys, emit, prov)) return result(false, checked, null, 'revocation_checkpoint_signature', cp)
    if (!Array.isArray(b.consistency)) return result(false, checked, null, 'bad_format', cp)
    let ok = false
    try {
      ok = verifyConsistency(rcp.tree_size, cp.tree_size, fromB64u(rcp.root_hash, 32), fromB64u(cp.root_hash, 32), (b.consistency as string[]).map((p) => fromB64u(p, 32)), prov)
    } catch {
      ok = false
    }
    if (rcp.tree_size > 0 && !ok) return result(false, checked, null, 'consistency_failed', cp)
  }
  if (b.directory !== undefined && b.directory !== null && !verifyDual(b.directory, keys, 'directory', prov).ok) {
    return result(false, checked, null, 'directory_signature', cp)
  }
  return result(true, checked, null, pinned ? null : 'keys_from_bundle_only', cp)
}
