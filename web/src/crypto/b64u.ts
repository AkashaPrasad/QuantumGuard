// SUITE.md 2.1: base64url without padding, strict canonical decoding.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
const LOOKUP: Record<string, number> = {}
for (let i = 0; i < ALPHABET.length; i++) LOOKUP[ALPHABET[i]] = i

export class B64uError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'B64uError'
  }
}

/** SUITE.md 2.1: b64u(bytes). */
export function b64u(bytes: Uint8Array): string {
  let out = ''
  let i = 0
  for (; i + 3 <= bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2]
    out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63] + ALPHABET[n & 63]
  }
  const rest = bytes.length - i
  if (rest === 1) {
    const n = bytes[i] << 16
    out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63]
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8)
    out += ALPHABET[(n >> 18) & 63] + ALPHABET[(n >> 12) & 63] + ALPHABET[(n >> 6) & 63]
  }
  return out
}

/** SUITE.md 2.1: decode, rejecting padding, foreign characters, length % 4 == 1 and non-canonical tails. */
export function fromB64u(s: string, expectedLength?: number): Uint8Array {
  if (typeof s !== 'string') throw new B64uError('b64u: not a string')
  if (s.length % 4 === 1) throw new B64uError('b64u: bad length')
  const vals = new Array<number>(s.length)
  for (let i = 0; i < s.length; i++) {
    const v = LOOKUP[s[i]]
    if (v === undefined) throw new B64uError('b64u: bad character')
    vals[i] = v
  }
  const out = new Uint8Array(Math.floor((s.length * 3) / 4))
  let o = 0
  let i = 0
  for (; i + 4 <= s.length; i += 4) {
    const n = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6) | vals[i + 3]
    out[o++] = (n >> 16) & 255
    out[o++] = (n >> 8) & 255
    out[o++] = n & 255
  }
  const rest = s.length - i
  if (rest === 2) {
    if (vals[i + 1] & 15) throw new B64uError('b64u: non-canonical')
    out[o++] = ((vals[i] << 2) | (vals[i + 1] >> 4)) & 255
  } else if (rest === 3) {
    if (vals[i + 2] & 3) throw new B64uError('b64u: non-canonical')
    const n = (vals[i] << 18) | (vals[i + 1] << 12) | (vals[i + 2] << 6)
    out[o++] = (n >> 16) & 255
    out[o++] = (n >> 8) & 255
  }
  if (expectedLength !== undefined && out.length !== expectedLength) {
    throw new B64uError(`b64u: expected ${expectedLength} bytes, got ${out.length}`)
  }
  return out
}
