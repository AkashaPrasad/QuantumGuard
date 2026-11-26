// Module Web Worker: runs Argon2id (SUITE.md 15) off the main thread. It holds no state between
// requests and never logs; the derived key is transferred back and the inputs are zeroed.
import { argon2idAsync } from '@noble/hashes/argon2.js'

export interface ArgonRequest {
  id: number
  password: Uint8Array
  salt: Uint8Array
  params: { t: number; m_kib: number; p: number; dkLen: number }
}

export type ArgonResponse = { id: number; key: Uint8Array } | { id: number; error: string }

const ctx = self as unknown as {
  onmessage: ((e: MessageEvent<ArgonRequest>) => void) | null
  postMessage(msg: ArgonResponse, transfer?: Transferable[]): void
}

ctx.onmessage = (e) => {
  const { id, password, salt, params } = e.data
  argon2idAsync(password, salt, {
    t: params.t,
    m: params.m_kib,
    p: params.p,
    dkLen: params.dkLen,
    version: 0x13,
    maxmem: params.m_kib * 1024 + 1024 * 1024,
  })
    .then((key) => ctx.postMessage({ id, key }, [key.buffer as ArrayBuffer]))
    .catch(() => ctx.postMessage({ id, error: 'argon2id failed' }))
    .finally(() => password.fill(0))
}
