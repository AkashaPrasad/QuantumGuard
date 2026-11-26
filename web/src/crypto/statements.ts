// SUITE.md 10 (change and approval statements) and 13 (policy bundle): the exact bytes a device signs
// or checks. Byte layouts follow backend/qg/api/changes.py and backend/qg/policy/engine.py.
import { b64u, fromB64u } from './b64u'
import { ctEqual, fromUtf8 } from './bytes'
import { canon } from './canonical'
import { getProvider, type CryptoProvider } from './provider'
import { SUITE, verifyDualBytes, type ServerKeys } from './suite'

export type ChangeType = 'role_grant' | 'role_revoke' | 'recovery_release'

/** SUITE.md 10: the statement the requester signs with purpose `change`. */
export interface ChangeStatement {
  directory_epoch: number
  file_id: string | null
  reason: string
  role: string | null
  suite: 'QG-1'
  target_user_id: string
  type: ChangeType
}

/** SUITE.md 10: approval statement, signed with purpose `change` over canon(approval). */
export interface ApprovalStatement {
  change_hash: string
  change_id: string
  decision: 'approve'
  purpose: 'approve'
  suite: 'QG-1'
}

export function changeStatement(x: { type: ChangeType; target_user_id: string; role?: string | null; file_id?: string | null; reason: string; directory_epoch: number }): ChangeStatement {
  return {
    directory_epoch: x.directory_epoch,
    file_id: x.file_id ?? null,
    reason: x.reason,
    role: x.role ?? null,
    suite: SUITE,
    target_user_id: x.target_user_id,
    type: x.type,
  }
}

/** SUITE.md 10: change_hash = b64u(SHA-256(canon(change))). */
export async function changeHash(change: unknown, prov: CryptoProvider = getProvider()): Promise<string> {
  return b64u(await prov.sha256(canon(change)))
}

export function approvalStatement(changeHashB64u: string, changeId: string): ApprovalStatement {
  return { change_hash: changeHashB64u, change_id: changeId, decision: 'approve', purpose: 'approve', suite: SUITE }
}

const CHANGE_KEYS = ['directory_epoch', 'file_id', 'reason', 'role', 'suite', 'target_user_id', 'type'] as const

/** True when `x` has exactly the members of a change statement with the right types and suite. */
export function isChangeStatement(x: unknown): x is ChangeStatement {
  if (!x || typeof x !== 'object' || Array.isArray(x)) return false
  const o = x as Record<string, unknown>
  const keys = Object.keys(o).sort()
  if (keys.length !== CHANGE_KEYS.length || keys.some((k, i) => k !== CHANGE_KEYS[i])) return false
  return (
    o.suite === SUITE &&
    Number.isSafeInteger(o.directory_epoch) &&
    (o.file_id === null || typeof o.file_id === 'string') &&
    (o.role === null || typeof o.role === 'string') &&
    typeof o.reason === 'string' &&
    typeof o.target_user_id === 'string' &&
    (o.type === 'role_grant' || o.type === 'role_revoke' || o.type === 'recovery_release')
  )
}

// ---- 13 policy bundle --------------------------------------------------------------------------

export interface PolicyView {
  bundle_hash: string
  version: number
  signatures: unknown
  document?: string
  rules: unknown[]
}

export type PolicyCheck = { ok: true; document: { rules: unknown[]; suite: 'QG-1'; version: number } } | { ok: false; reason: string }

/**
 * SUITE.md 13: `document` is b64u(canon(document)); its SHA-256 must be `bundle_hash`, both server
 * signatures (purpose `policy`) must cover exactly those bytes, and the rules and version shown beside
 * it must be the ones inside it.
 */
export async function verifyPolicy(p: PolicyView, keys: ServerKeys, prov: CryptoProvider = getProvider()): Promise<PolicyCheck> {
  if (typeof p.document !== 'string') return { ok: false, reason: 'policy_document_missing' }
  let bytes: Uint8Array
  let hash: Uint8Array
  try {
    bytes = fromB64u(p.document)
    hash = fromB64u(p.bundle_hash, 32)
  } catch {
    return { ok: false, reason: 'policy_document_encoding' }
  }
  if (!ctEqual(await prov.sha256(bytes), hash)) return { ok: false, reason: 'policy_hash' }
  if (!verifyDualBytes(bytes, p.signatures, keys, 'policy', prov).ok) return { ok: false, reason: 'policy_signature' }
  let doc: unknown
  try {
    doc = JSON.parse(fromUtf8(bytes))
  } catch {
    return { ok: false, reason: 'policy_document_encoding' }
  }
  const d = doc as { rules?: unknown; suite?: unknown; version?: unknown }
  if (!d || typeof d !== 'object' || d.suite !== SUITE || !Array.isArray(d.rules) || !Number.isSafeInteger(d.version)) {
    return { ok: false, reason: 'policy_document_shape' }
  }
  // The signed bytes must be canonical, so the parsed document is exactly what was signed.
  if (!ctEqual(canon(doc), bytes)) return { ok: false, reason: 'policy_document_encoding' }
  if (d.version !== p.version || !ctEqual(canon(d.rules), canon(p.rules))) return { ok: false, reason: 'policy_rules_mismatch' }
  return { ok: true, document: { rules: d.rules, suite: SUITE, version: d.version as number } }
}
