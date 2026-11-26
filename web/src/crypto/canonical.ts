// SUITE.md 2.2: canonical JSON (RFC 8785 restricted to integers, ASCII keys, no floats).
import { utf8 } from './bytes'

export type CanonValue = null | boolean | number | string | CanonValue[] | { [k: string]: CanonValue }

export class CanonError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CanonError'
  }
}

const MAX_SAFE = 2 ** 53 - 1

/** SUITE.md 2.2: canon(x) as bytes. */
export function canon(value: unknown): Uint8Array {
  return utf8(canonString(value))
}

/** SUITE.md 2.2: canon(x) as a string (before UTF-8 encoding). */
export function canonString(value: unknown): string {
  return write(value, 0)
}

function write(v: unknown, depth: number): string {
  if (depth > 64) throw new CanonError('canon: too deep')
  if (v === null) return 'null'
  if (v === true) return 'true'
  if (v === false) return 'false'
  if (typeof v === 'number') return writeInt(v)
  if (typeof v === 'string') return writeString(v)
  if (Array.isArray(v)) return '[' + v.map((x) => write(x, depth + 1)).join(',') + ']'
  if (typeof v === 'object' && isPlainObject(v)) return writeObject(v as Record<string, unknown>, depth)
  throw new CanonError(`canon: unsupported value of type ${typeof v}`)
}

function isPlainObject(v: object): boolean {
  const proto: unknown = Object.getPrototypeOf(v)
  return proto === Object.prototype || proto === null
}

/** SUITE.md 2.2: integers only, shortest form, no -0. */
function writeInt(n: number): string {
  if (!Number.isInteger(n)) throw new CanonError('canon: not an integer')
  if (Object.is(n, -0)) throw new CanonError('canon: -0')
  if (n > MAX_SAFE || n < -MAX_SAFE) throw new CanonError('canon: integer out of range')
  return String(n)
}

/** SUITE.md 2.2: string escaping; JSON.stringify matches the rules once lone surrogates are excluded. */
function writeString(s: string): string {
  assertWellFormed(s)
  return JSON.stringify(s)
}

function assertWellFormed(s: string): void {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0
      if (d < 0xdc00 || d > 0xdfff) throw new CanonError('canon: lone surrogate')
      i++
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new CanonError('canon: lone surrogate')
    }
  }
}

/** SUITE.md 2.2: ASCII keys sorted by byte value, undefined members rejected. */
function writeObject(o: Record<string, unknown>, depth: number): string {
  const keys = Object.keys(o)
  for (const k of keys) {
    // oxlint-disable-next-line no-control-regex -- the ASCII/control ranges are the rule
    if (!/^[\x00-\x7f]*$/.test(k)) throw new CanonError('canon: non-ASCII key')
    if (o[k] === undefined) throw new CanonError(`canon: undefined member ${k}`)
  }
  keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
  return '{' + keys.map((k) => writeString(k) + ':' + write(o[k], depth + 1)).join(',') + '}'
}

/**
 * Strict JSON parser for SUITE.md 2.2 inputs: rejects floats, exponents, -0, unsafe integers,
 * duplicate keys, non-ASCII keys and lone surrogates instead of silently normalising them.
 */
export function parseStrict(text: string): CanonValue {
  const p = new StrictParser(text)
  p.ws()
  const v = p.value(0)
  p.ws()
  if (p.i !== text.length) throw new CanonError('json: trailing data')
  return v
}

class StrictParser {
  readonly s: string
  i = 0
  constructor(s: string) {
    this.s = s
  }
  ws(): void {
    while (this.i < this.s.length && ' \t\n\r'.includes(this.s[this.i])) this.i++
  }
  value(depth: number): CanonValue {
    if (depth > 64) throw new CanonError('json: too deep')
    const c = this.s[this.i]
    if (c === '{') return this.object(depth)
    if (c === '[') return this.array(depth)
    if (c === '"') return this.string()
    if (c === '-' || (c >= '0' && c <= '9')) return this.number()
    for (const [lit, val] of [
      ['true', true],
      ['false', false],
      ['null', null],
    ] as const) {
      if (this.s.startsWith(lit, this.i)) {
        this.i += lit.length
        return val
      }
    }
    throw new CanonError('json: unexpected token')
  }
  object(depth: number): CanonValue {
    this.i++
    const out: Record<string, CanonValue> = Object.create(null) as Record<string, CanonValue>
    const seen = new Set<string>()
    this.ws()
    if (this.s[this.i] === '}') {
      this.i++
      return { ...out }
    }
    for (;;) {
      this.ws()
      if (this.s[this.i] !== '"') throw new CanonError('json: expected key')
      const k = this.string()
      // oxlint-disable-next-line no-control-regex -- the ASCII/control ranges are the rule
      if (!/^[\x00-\x7f]*$/.test(k)) throw new CanonError('json: non-ASCII key')
      if (seen.has(k)) throw new CanonError('json: duplicate key')
      seen.add(k)
      this.ws()
      if (this.s[this.i++] !== ':') throw new CanonError('json: expected colon')
      this.ws()
      out[k] = this.value(depth + 1)
      this.ws()
      const c = this.s[this.i++]
      if (c === '}') break
      if (c !== ',') throw new CanonError('json: expected comma')
    }
    return { ...out }
  }
  array(depth: number): CanonValue {
    this.i++
    const out: CanonValue[] = []
    this.ws()
    if (this.s[this.i] === ']') {
      this.i++
      return out
    }
    for (;;) {
      this.ws()
      out.push(this.value(depth + 1))
      this.ws()
      const c = this.s[this.i++]
      if (c === ']') break
      if (c !== ',') throw new CanonError('json: expected comma')
    }
    return out
  }
  string(): string {
    // oxlint-disable-next-line no-control-regex -- the ASCII/control ranges are the rule
    const m = /^"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*"/.exec(this.s.slice(this.i))
    if (!m) throw new CanonError('json: bad string')
    this.i += m[0].length
    const v = JSON.parse(m[0]) as string
    assertWellFormed(v)
    return v
  }
  number(): number {
    const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(this.s.slice(this.i))
    if (!m) throw new CanonError('json: bad number')
    const t = m[0]
    if (/[.eE]/.test(t)) throw new CanonError('json: floating-point number')
    if (t === '-0') throw new CanonError('json: -0')
    this.i += t.length
    const n = Number(t)
    if (!Number.isSafeInteger(n)) throw new CanonError('json: integer out of range')
    return n
  }
}
