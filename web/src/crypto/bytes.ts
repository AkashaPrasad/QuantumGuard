// Small byte helpers shared by the QG-1 code. Encodings only; no primitives.
import { equalBytes } from '@noble/ciphers/utils.js'

const enc = new TextEncoder()
const dec = new TextDecoder('utf-8', { fatal: true })

/** SUITE.md 0: utf8(s). */
export function utf8(s: string): Uint8Array {
  return enc.encode(s)
}

/** Strict UTF-8 decoding (throws on malformed input). */
export function fromUtf8(b: Uint8Array): string {
  return dec.decode(b)
}

/** SUITE.md 0: a || b || ... */
export function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

/** SUITE.md 0: u32be(n). */
export function u32be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new RangeError('u32be out of range')
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, n, false)
  return out
}

/** Lower-case hex (SUITE.md 6 and the vector files). */
export function toHex(b: Uint8Array): string {
  let s = ''
  for (const x of b) s += x.toString(16).padStart(2, '0')
  return s
}

export function fromHex(h: string): Uint8Array {
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('bad hex')
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16)
  return out
}

/** Constant-time equality for tags, MACs and hashes (library helper). */
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  return equalBytes(a, b)
}

/** Overwrites secret bytes in place. */
export function wipe(...arrays: (Uint8Array | null | undefined)[]): void {
  for (const a of arrays) if (a) a.fill(0)
}

/** A copy whose buffer is a plain ArrayBuffer of exactly its length (for Web Crypto and Blob). */
export function own(b: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(b.length))
  out.set(b)
  return out
}
