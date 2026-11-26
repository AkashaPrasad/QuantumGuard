// Argon2id off the main thread (SUITE.md 15 parameters take several hundred ms in JS). Falls back to
// the same-thread provider where module workers do not exist (tests, old browsers).
import type { DeriveFn } from '../../crypto/keystore'
import { getProvider } from '../../crypto/provider'
import type { ArgonRequest, ArgonResponse } from './worker'

let worker: Worker | null = null
let nextId = 1
const pending = new Map<number, { resolve: (k: Uint8Array) => void; reject: (e: Error) => void }>()

function getWorker(): Worker | null {
  if (typeof Worker === 'undefined') return null
  if (worker) return worker
  try {
    worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' })
  } catch {
    return null
  }
  worker.onmessage = (e: MessageEvent<ArgonResponse>) => {
    const p = pending.get(e.data.id)
    if (!p) return
    pending.delete(e.data.id)
    if ('key' in e.data) p.resolve(e.data.key)
    else p.reject(new Error(e.data.error))
  }
  worker.onerror = () => {
    for (const p of pending.values()) p.reject(new Error('argon2id worker failed'))
    pending.clear()
    worker?.terminate()
    worker = null
  }
  return worker
}

/** Argon2id in a module Web Worker, or on this thread when no worker is available. */
export const deriveArgon2id: DeriveFn = (password, salt, params) => {
  const w = getWorker()
  if (!w) return getProvider().argon2id(password, salt, params)
  const id = nextId++
  const msg: ArgonRequest = { id, password: password.slice(), salt: salt.slice(), params }
  return new Promise<Uint8Array>((resolve, reject) => {
    pending.set(id, { resolve, reject })
    w.postMessage(msg, [msg.password.buffer as ArrayBuffer])
  })
}
