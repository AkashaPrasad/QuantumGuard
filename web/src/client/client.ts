// The one boundary between screens and everything below them (HTTP, crypto,
// keystore, session). Screens never call fetch or touch key material.
//
// Two implementations satisfy this interface:
//   real/  talks to the API and runs the QG-1 client crypto
//   mock/  an in-memory stand-in for development and state tests, never bundled in production
import type * as T from './types'

export class QgError extends Error {
  readonly code: T.QgCode
  readonly reason: string | null
  readonly requestId: string | null
  readonly receiptId: string | null
  readonly status: number | null

  constructor(init: {
    code: T.QgCode
    message: string
    reason?: string | null
    requestId?: string | null
    receiptId?: string | null
    status?: number | null
  }) {
    super(init.message)
    this.name = 'QgError'
    this.code = init.code
    this.reason = init.reason ?? null
    this.requestId = init.requestId ?? null
    this.receiptId = init.receiptId ?? null
    this.status = init.status ?? null
  }
}

/** What this browser knows about itself as a device. Never contains key bytes. */
export interface LocalDevice {
  device_id: string
  device_name: string
  user_id: string
  user_name: string
  roles: T.Role[]
  provider: 'native' | 'noble'
  enrolled_at: string
}

export interface SessionInfo {
  session_id: string
  expires_at: string
  hard_expires_at: string
  first_session: boolean
}

export type DeviceState =
  | { kind: 'none' } // this browser has never been enrolled
  | { kind: 'locked'; device: LocalDevice } // keystore present, keys not in memory
  | { kind: 'unlocked'; device: LocalDevice; session: SessionInfo }
  | { kind: 'revoked'; device: LocalDevice } // the server refused this device as revoked

// Progress events mirror real work. Animations subscribe to these and to nothing else.
export type EnrolStep =
  | 'generating_keys' // two key pairs being created on this device
  | 'proving_possession' // challenge answered with both private keys
  | 'certificate_issued' // server signed the certificate and published a new directory epoch
  | 'sealing_keystore' // private keys wrapped under the passphrase
  | 'session_started'

export type ProtectProgress =
  | { phase: 'encrypting'; chunk: number; chunks: number }
  | { phase: 'uploading'; chunk: number; chunks: number }
  | { phase: 'wrapping'; device_id: string; device_name: string; done: number; total: number }
  | { phase: 'committing' }
  | { phase: 'done'; receipt_id: string }

export type OpenProgress =
  | { phase: 'requesting' }
  | { phase: 'released'; receipt_id: string } // policy said allow; outer seal removed by the server
  | { phase: 'unwrapped' } // inner wrap opened with this device's key
  | { phase: 'decrypting'; chunk: number; chunks: number }
  | { phase: 'done' }

export type WorkProgress =
  | { kind: 'rekey'; file_id: string; name: string; index: number; total: number; chunk: number; chunks: number }
  | { kind: 'share'; file_id: string; name: string; index: number; total: number }

export type VerifyStep =
  | { kind: 'receipt'; receipt: T.Receipt; leaf_hash: string }
  | { kind: 'node'; level: number; hash: string; sibling: string; side: 'left' | 'right' }
  | { kind: 'root'; computed: string; signed: string; ok: boolean }
  | { kind: 'signature'; alg: 'ed25519' | 'mldsa'; ok: boolean }

export interface VerifyResult {
  ok: boolean
  checked: number // receipts checked
  failed_index: number | null // first leaf that did not verify
  reason: string | null
  checkpoint: T.Checkpoint | null
}

export interface OpenedFile {
  blob: Blob
  name: string
  receipt_id: string
  /** Manifest signature and every chunk tag verified on this device. */
  verified: boolean
}

export interface QgClient {
  // State
  getState(): DeviceState
  subscribe(listener: (s: DeviceState) => void): () => void

  // Public, no session
  meta(): Promise<T.Meta>
  directory(): Promise<T.Directory>
  checkpoint(): Promise<T.Checkpoint>
  health(): Promise<{ status: string }>
  bench(): Promise<Record<string, unknown> | null>
  keySet(): Promise<T.KeySet>

  // This device
  enrol(
    input: { code: string; device_name: string; passphrase: string },
    onStep?: (step: EnrolStep) => void,
  ): Promise<LocalDevice>
  unlock(passphrase: string): Promise<SessionInfo>
  lock(): void
  /** Removes the local keystore. Used after this device was revoked. */
  forgetDevice(): Promise<void>

  // Files
  listFiles(params?: { q?: string; classification?: T.Classification }): Promise<T.FileItem[]>
  getFile(fileId: string): Promise<T.FileDetail>
  protectFile(
    input: { file: File; classification: T.Classification; recipient_user_ids: string[] },
    onProgress?: (p: ProtectProgress) => void,
    signal?: AbortSignal,
  ): Promise<{ file: T.FileItem; receipt_id: string }>
  openFile(fileId: string, onProgress?: (p: OpenProgress) => void, signal?: AbortSignal): Promise<OpenedFile>
  shareFile(fileId: string, userIds: string[]): Promise<{ file: T.FileItem; receipt_id: string }>
  unshareFile(fileId: string, userId: string): Promise<{ file: T.FileItem; receipt_id: string }>
  deleteFile(fileId: string): Promise<void>

  /** Re-keys and catch-up shares waiting for this device. */
  pendingWork(): Promise<T.RekeyPending>
  runPendingWork(
    onProgress?: (p: WorkProgress) => void,
    signal?: AbortSignal,
  ): Promise<{ rekeyed: number; shared: number }>

  // Devices and incidents
  listDevices(scope?: 'mine' | 'all'): Promise<T.Device[]>
  renameDevice(deviceId: string, name: string): Promise<T.Device>
  reportLost(deviceId: string, input: { lost_at: string; note?: string }): Promise<T.RevokeResult>
  revokeDevice(deviceId: string, input: { compromise_time: string; reason: string }): Promise<T.RevokeResult>
  listIncidents(status?: T.IncidentStatus): Promise<T.IncidentSummary[]>
  getIncident(id: string): Promise<T.Incident>
  getExposure(id: string): Promise<T.Exposure>
  exportBundle(id: string): Promise<T.ProofBundle>
  closeIncident(id: string): Promise<T.Incident>

  // People
  createInvite(
    input: { user_id: string } | { name: string; roles: T.Role[] },
  ): Promise<{ invite_id: string; code: string; user_id: string; expires_at: string } | { change_id: string }>
  listInvites(): Promise<T.Invite[]>
  cancelInvite(id: string): Promise<void>

  // Changes that need a second person
  listChanges(status?: T.Change['status']): Promise<T.Change[]>
  requestChange(input: {
    type: T.ChangeType
    target_user_id: string
    role?: T.Role
    file_id?: string
    reason: string
  }): Promise<T.Change>
  approveChange(id: string): Promise<T.Change>
  rejectChange(id: string, reason: string): Promise<T.Change>

  // Alerts
  listAlerts(params?: { status?: T.Alert['status']; rule_id?: string }): Promise<T.Alert[]>
  getAlert(id: string): Promise<T.AlertDetail>
  ackAlert(id: string, note?: string): Promise<T.Alert>
  liftResponse(responseId: string, reason: string): Promise<T.Alert>

  // Evidence
  listReceipts(params?: {
    user_id?: string
    device_id?: string
    resource?: string
    action?: string
    decision?: T.Decision
    before?: string
    limit?: number
  }): Promise<T.Page<T.Receipt>>
  getReceipt(id: string): Promise<T.Receipt>
  /** Fetches the inclusion proof and checks it on this device against the dual-signed checkpoint. */
  verifyReceipt(id: string, onStep?: (s: VerifyStep) => void): Promise<VerifyResult>
  /** Verifies an exported proof bundle with no network access. */
  verifyBundle(bundle: unknown, onStep?: (s: VerifyStep) => void): Promise<VerifyResult>

  // Services, policy, overview, signals
  listServices(): Promise<T.Service[]>
  createService(name: string): Promise<T.Service>
  rotateService(id: string, input: { reason: string; emergency: boolean }): Promise<T.Service>
  policy(): Promise<T.Policy>
  overview(): Promise<T.Overview>
  listSignals(): Promise<T.Signal[]>

  // Messaging (only when meta.features.messaging)
  listMessages(): Promise<T.Message[]>
  sendMessage(toUserId: string, text: string): Promise<{ message_id: string }>
}
