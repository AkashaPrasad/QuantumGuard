// Wire types for the QuantumGuard API. Field names match spec/API.md exactly
// (snake_case, as sent), so there is no mapping layer to get wrong.

export type Role = 'employee' | 'admin' | 'operator' | 'auditor'
export type Classification = 'internal' | 'confidential' | 'restricted'
export type Decision = 'allow' | 'deny'
export type Severity = 'critical' | 'high' | 'medium'

export type QgCode =
  | 'QG_INVALID_INPUT'
  | 'QG_BAD_SUITE'
  | 'QG_BAD_SIGNATURE'
  | 'QG_NO_SESSION'
  | 'QG_BAD_MAC'
  | 'QG_REPLAY'
  | 'QG_DENY_REVOKED'
  | 'QG_DENY_POLICY'
  | 'QG_QUARANTINED'
  | 'QG_STALE_EPOCH'
  | 'QG_LEASE_EXPIRED'
  | 'QG_NOT_FOUND'
  | 'QG_CONFLICT'
  | 'QG_RATE_LIMITED'
  | 'QG_UNAVAILABLE_FAIL_CLOSED'
  // Raised by the client itself, never by the server:
  | 'QG_OFFLINE' // the request never reached the server
  | 'QG_LOCAL_PASSPHRASE' // the passphrase did not open the keystore
  | 'QG_LOCAL_INTEGRITY' // a signature, hash or tag failed to verify on this device
  | 'QG_LOCAL_CANCELLED' // the person cancelled

export interface Signatures {
  ed25519: string
  mldsa: string
}

export interface Meta {
  suite: 'QG-1'
  version: string
  commit: string
  demo: boolean
  server_keys: { ed25519_pk: string; mldsa_pk: string; kem_pk: string }
  recovery_pk: string
  policy_bundle_hash: string
  limits: {
    chunk_bytes: number
    max_file_bytes: number
    max_recipients: number
    lease_seconds: number
    session_ttl_seconds: number
    session_hard_cap_seconds: number
  }
  features: { messaging: boolean; slhdsa: boolean }
}

export interface DirectoryUser {
  user_id: string
  name: string
  roles: Role[]
  status: 'active' | 'quarantined' | 'disabled'
}

export interface Certificate {
  suite: 'QG-1'
  device_id: string
  user_id: string
  name: string
  kem_pk: string
  sig_pk: string
  created_at: string
  expires_at: string
  directory_epoch: number
}

export interface Directory {
  suite: 'QG-1'
  epoch: number
  prev_hash: string
  issued_at: string
  users: DirectoryUser[]
  devices: Certificate[]
  revoked: { device_id: string; revoked_at: string; epoch: number }[]
  recovery_pk: string
  signatures: Signatures
}

export interface Checkpoint {
  suite: 'QG-1'
  tree_size: number
  root_hash: string
  ts: string
  signatures: Signatures
}

export interface Device {
  device_id: string
  user_id: string
  user_name: string
  name: string
  status: 'active' | 'revoked' | 'quarantined'
  created_at: string
  last_seen_at: string | null
  is_current: boolean
  open_incident_id: string | null
}

export interface FileRecipient {
  device_id: string
  user_id: string
  user_name: string
  device_name: string
}

export interface FileItem {
  file_id: string
  name: string
  classification: Classification
  size_bytes: number
  version: number
  chunk_count: number
  owner: { user_id: string; name: string }
  created_at: string
  updated_at: string
  recipients: FileRecipient[]
  can_open: boolean
  rekey: 'none' | 'pending' | 'in_progress'
}

export interface FileDetail extends FileItem {
  versions: { version: number; committed_at: string; committed_by_device: string; reason: string }[]
  activity: Receipt[]
}

export interface Receipt {
  suite: 'QG-1'
  id: string
  ts: string
  request_hash: string
  subject: { user_id: string | null; device_id: string | null; session_id: string | null }
  action: string
  resource: string
  policy_bundle_hash: string
  matched_rules: string[]
  decision: Decision
  reason_code: string
  key_epoch: number
  directory_epoch: number
  leaf_index: number
}

export type ResponseAction =
  | 'deny'
  | 'end_session'
  | 'quarantine_device'
  | 'quarantine_identity'
  | 'throttle'
  | 'require_fresh_session'
  | 'hold_enrolment'
  | 'freeze_key_release'
  | 'none'

export interface AlertResponse {
  id: string
  action: ResponseAction
  scope: { kind: 'session' | 'device' | 'identity' | 'credential' | 'global'; id: string }
  expires_at: string | null
  lifted_at: string | null
  lifted_by: string | null
}

export interface Alert {
  id: string
  ts: string
  rule_id: string
  severity: Severity
  status: 'open' | 'acknowledged'
  subject: { user_id: string | null; device_id: string | null; session_id: string | null }
  summary: string
  explanation: { condition: string; receipt_ids: string[] }
  response: AlertResponse | null
  incident_id: string | null
  acknowledged_by: string | null
}

export interface AlertDetail extends Alert {
  receipts: Receipt[]
  path?: { from: string; to: string; relation: string }[]
}

export interface RevokeResult {
  incident_id: string
  device_id: string
  status: 'revoked'
  directory_epoch: number
  time_to_enforce_ms: number
  sessions_ended: number
  slots_deleted: number
  checkpoint: Checkpoint
  receipt_id: string
}

export type IncidentStatus = 'open' | 'rekeying' | 'contained' | 'closed'

export interface IncidentSummary {
  id: string
  device_id: string
  device_name: string
  user_id: string
  user_name: string
  status: IncidentStatus
  reported_at: string
  compromise_time: string
  counts: { exposed: number; held: number; never_released: number; rekeyed: number; pending: number }
  denied_attempts: number
}

export type TimelineStep =
  | 'reported'
  | 'revoked'
  | 'scoped'
  | 'rekey_started'
  | 'rekey_progress'
  | 'rekey_done'
  | 'denied_attempt'
  | 'rescoped'
  | 'bundle_exported'
  | 'closed'

export interface Incident extends IncidentSummary {
  reported_by: { user_id: string; name: string }
  note: string | null
  time_to_enforce_ms: number
  directory_epoch: number
  timeline: { step: TimelineStep; ts: string; receipt_id: string | null; detail: string }[]
  alert_ids: string[]
}

export interface ExposedFile {
  file_id: string
  name: string
  classification: Classification
  releases: { ts: string; receipt_id: string }[]
  rekey: 'pending' | 'done' | 'not_needed'
  new_version: number | null
}

export interface Exposure {
  incident_id: string
  compromise_time: string
  exposed: ExposedFile[]
  held: ExposedFile[]
  never_released: ExposedFile[]
  suspect_decisions: Receipt[]
}

export interface Invite {
  invite_id: string
  user_id: string
  user_name: string
  created_by: string
  expires_at: string
  status: 'pending' | 'used' | 'expired' | 'cancelled'
}

export type ChangeType = 'role_grant' | 'role_revoke' | 'recovery_release'

export interface Change {
  id: string
  type: ChangeType
  target_user: { user_id: string; name: string }
  role: Role | null
  file_id: string | null
  reason: string
  requested_by: { user_id: string; name: string; device_id: string }
  requested_at: string
  status: 'pending' | 'applied' | 'rejected'
  approvals: { user_id: string; name: string; device_id: string; at: string }[]
  approvals_required: number
}

export interface ServiceKey {
  key_id: string
  alg: string
  status: 'active' | 'retiring' | 'retired'
  created_at: string
  retired_at: string | null
}

export interface Service {
  service_id: string
  name: string
  status: string
  keys: ServiceKey[]
}

export interface KeySet {
  suite: 'QG-1'
  epoch: number
  keys: { service_id: string; key_id: string; alg: string; public_key: string; status: string }[]
  signatures: Signatures
}

export interface PolicyRule {
  id: string
  effect: Decision
  description: string
  roles: Role[]
  actions: string[]
  conditions: Record<string, unknown>
}

export interface Policy {
  bundle_hash: string
  version: number
  signed_at: string
  signatures: Signatures
  rules: PolicyRule[]
}

export interface Overview {
  active_devices: number
  revoked_devices: number
  pending_rekeys: number
  open_alerts: number
  open_incidents: number
  last_time_to_enforce_ms: number | null
  directory_epoch: number
  tree_size: number
  decisions_by_hour: { hour: string; allow: number; deny: number }[]
}

export interface RekeyPending {
  rekeys: {
    file_id: string
    name: string
    version: number
    reason: 'exposed' | 'held' | 'unshare'
    incident_id: string | null
    recipients: string[]
  }[]
  shares: { file_id: string; name: string; version: number; device_id: string; device_name: string }[]
}

export interface Signal {
  signal_id: string
  received_at: string
  event_type: string
  subject: string
  duplicate: boolean
}

export interface Message {
  message_id: string
  from: { user_id: string; name: string; device_id: string }
  sent_at: string
  text: string // decrypted on this device
  verified: boolean
}

export interface InclusionProof {
  leaf_index: number
  tree_size: number
  leaf_hash: string
  audit_path: string[]
  checkpoint: Checkpoint
}

/** Opaque here; its format is defined in spec/SUITE.md and checked by the verifier. */
export type ProofBundle = Record<string, unknown>

export interface Page<T> {
  items: T[]
  next_before: string | null
}
