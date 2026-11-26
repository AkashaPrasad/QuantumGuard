// HTTP transport for the real client: same-origin relative URLs, one authenticated request at a
// time per session (so QG-Seq arrives strictly increasing), the SUITE.md 6 request MAC, and
// mapping of error bodies to QgError (spec/API.md 1.2).
import { QgError } from '../client'
import type { QgCode } from '../types'
import { wipe } from '../../crypto/bytes'
import { requestMac } from '../../crypto/protocol'

export interface SessionAuth {
  sessionId: string
  macKey: Uint8Array
  seq: number
}

export type AuthEvent = 'locked' | 'revoked'

export type Query = Record<string, string | number | boolean | null | undefined>

export interface RequestOptions {
  query?: Query
  json?: unknown
  bytes?: Uint8Array
  headers?: Record<string, string>
  signal?: AbortSignal
  /** How to read a successful body. Default `json` (204 gives null). */
  expect?: 'json' | 'bytes'
}

export interface HttpResult<T> {
  data: T
  status: number
  receiptId: string | null
  requestId: string | null
}

const LOCKING: QgCode[] = ['QG_NO_SESSION', 'QG_REPLAY', 'QG_BAD_MAC']
const KNOWN: ReadonlySet<string> = new Set<QgCode>([
  'QG_INVALID_INPUT', 'QG_BAD_SUITE', 'QG_BAD_SIGNATURE', 'QG_NO_SESSION', 'QG_BAD_MAC', 'QG_REPLAY',
  'QG_DENY_REVOKED', 'QG_DENY_POLICY', 'QG_QUARANTINED', 'QG_STALE_EPOCH', 'QG_LEASE_EXPIRED',
  'QG_NOT_FOUND', 'QG_CONFLICT', 'QG_RATE_LIMITED', 'QG_UNAVAILABLE_FAIL_CLOSED',
])

/** spec/API.md 1: build `/api/v1/...` plus a percent-encoded query (exactly what goes on the wire). */
export function buildPath(path: string, query?: Query): string {
  if (!path.startsWith('/api/v1/') && path !== '/healthz') throw new Error('relative /api/v1/ paths only')
  const parts: string[] = []
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v === undefined || v === null || v === '') continue
    parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
  }
  return parts.length ? `${path}?${parts.join('&')}` : path
}

/** Encodes one path segment (ids are b64u, but names never reach a path unencoded). */
export function seg(s: string): string {
  return encodeURIComponent(s)
}

function statusCode(status: number): QgCode {
  if (status === 401) return 'QG_NO_SESSION'
  if (status === 403) return 'QG_DENY_POLICY'
  if (status === 404) return 'QG_NOT_FOUND'
  if (status === 409) return 'QG_CONFLICT'
  if (status === 429) return 'QG_RATE_LIMITED'
  if (status >= 500) return 'QG_UNAVAILABLE_FAIL_CLOSED'
  return 'QG_INVALID_INPUT'
}

/** spec/API.md 1.2: error body -> QgError (unknown shapes fall back on the HTTP status). */
async function toError(res: Response): Promise<QgError> {
  let body: unknown = null
  try {
    body = await res.json()
  } catch {
    body = null
  }
  const e = (body && typeof body === 'object' ? (body as { error?: Record<string, unknown> }).error : undefined) ?? {}
  const code = typeof e.code === 'string' && KNOWN.has(e.code) ? (e.code as QgCode) : statusCode(res.status)
  return new QgError({
    code,
    message: typeof e.message === 'string' ? e.message : `Request failed (${res.status})`,
    reason: typeof e.reason === 'string' ? e.reason : null,
    requestId: typeof e.request_id === 'string' ? e.request_id : res.headers.get('QG-Request-Id'),
    receiptId: typeof e.receipt_id === 'string' ? e.receipt_id : res.headers.get('QG-Receipt'),
    status: res.status,
  })
}

function cancelled(): QgError {
  return new QgError({ code: 'QG_LOCAL_CANCELLED', message: 'Cancelled.' })
}

function offline(): QgError {
  return new QgError({ code: 'QG_OFFLINE', message: 'The server could not be reached.' })
}

export class Http {
  private session: SessionAuth | null = null
  private queue: Promise<unknown> = Promise.resolve()
  private readonly fetchImpl: typeof fetch
  /** Called when the server ends the session (locked) or refuses the device (revoked). */
  onAuthEvent: ((e: AuthEvent, err: QgError) => void) | null = null
  /** Called after every authenticated request that reached the server (idle timer). */
  onActivity: (() => void) | null = null

  constructor(fetchImpl?: typeof fetch) {
    this.fetchImpl = fetchImpl ?? ((input, init) => globalThis.fetch(input, init))
  }

  get hasSession(): boolean {
    return this.session !== null
  }

  setSession(s: SessionAuth): void {
    this.clearSession()
    this.session = { sessionId: s.sessionId, macKey: s.macKey.slice(), seq: s.seq }
  }

  /** Forgets the session and zeroes K_mac. */
  clearSession(): void {
    if (this.session) wipe(this.session.macKey)
    this.session = null
  }

  /** Queues `/session/end` behind in-flight requests, then zeroes K_mac. */
  endSession(): Promise<void> {
    if (!this.session) return Promise.resolve()
    const sid = this.session.sessionId
    const p = this.call<null>('POST', '/api/v1/session/end')
      .then(() => undefined, () => undefined)
      .then(() => {
        if (this.session?.sessionId === sid) this.clearSession()
      })
    return p
  }

  /** A public route (spec/API.md 2): no session headers, not queued. */
  async public<T>(method: string, path: string, opts: RequestOptions = {}): Promise<HttpResult<T>> {
    const wire = buildPath(path, opts.query)
    const { body, contentType } = encodeBody(opts)
    const headers: Record<string, string> = { ...(opts.headers ?? {}) }
    if (contentType) headers['Content-Type'] = contentType
    return this.send<T>(method, wire, body, headers, opts)
  }

  /** An authenticated route: queued so QG-Seq is strictly increasing, MAC over the exact bytes sent. */
  call<T>(method: string, path: string, opts: RequestOptions = {}): Promise<HttpResult<T>> {
    const run = () => this.callNow<T>(method, path, opts)
    const p = this.queue.then(run, run)
    this.queue = p.catch(() => undefined)
    return p
  }

  private async callNow<T>(method: string, path: string, opts: RequestOptions): Promise<HttpResult<T>> {
    if (opts.signal?.aborted) throw cancelled()
    const s = this.session
    if (!s) throw new QgError({ code: 'QG_NO_SESSION', message: 'This device is locked.' })
    const wire = buildPath(path, opts.query)
    const { body, contentType } = encodeBody(opts)
    s.seq += 1
    const seq = s.seq
    const mac = await requestMac(s.macKey, method, wire, seq, body)
    const headers: Record<string, string> = {
      ...(opts.headers ?? {}),
      'QG-Session': s.sessionId,
      'QG-Seq': String(seq),
      'QG-MAC': mac,
    }
    if (contentType) headers['Content-Type'] = contentType
    const r = await this.send<T>(method, wire, body, headers, opts)
    this.onActivity?.()
    return r
  }

  private async send<T>(method: string, wire: string, body: Uint8Array, headers: Record<string, string>, opts: RequestOptions): Promise<HttpResult<T>> {
    let res: Response
    try {
      res = await this.fetchImpl(wire, {
        method: method.toUpperCase(),
        headers,
        body: body.length ? toArrayBuffer(body) : undefined,
        signal: opts.signal,
        credentials: 'same-origin',
        cache: 'no-store',
      })
    } catch (e) {
      if (opts.signal?.aborted || (e instanceof DOMException && e.name === 'AbortError')) throw cancelled()
      throw offline()
    }
    if (!res.ok) {
      const err = await toError(res)
      if (LOCKING.includes(err.code)) {
        this.clearSession()
        this.onAuthEvent?.('locked', err)
      } else if (err.code === 'QG_DENY_REVOKED') {
        this.clearSession()
        this.onAuthEvent?.('revoked', err)
      }
      throw err
    }
    const meta = { status: res.status, receiptId: res.headers.get('QG-Receipt'), requestId: res.headers.get('QG-Request-Id') }
    try {
      if (opts.expect === 'bytes') return { ...meta, data: new Uint8Array(await res.arrayBuffer()) as T }
      if (res.status === 204) return { ...meta, data: null as T }
      const text = await res.text()
      return { ...meta, data: (text ? JSON.parse(text) : null) as T }
    } catch (e) {
      if (opts.signal?.aborted) throw cancelled()
      if (e instanceof SyntaxError) throw new QgError({ code: 'QG_INVALID_INPUT', message: 'The server sent a malformed response.', status: res.status })
      throw offline()
    }
  }
}

function encodeBody(opts: RequestOptions): { body: Uint8Array; contentType: string | null } {
  if (opts.bytes) return { body: opts.bytes, contentType: 'application/octet-stream' }
  if (opts.json !== undefined) return { body: new TextEncoder().encode(JSON.stringify(opts.json)), contentType: 'application/json' }
  return { body: new Uint8Array(0), contentType: null }
}

function toArrayBuffer(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.length)
  new Uint8Array(out).set(b)
  return out
}
