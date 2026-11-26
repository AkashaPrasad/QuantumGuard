import { describe, expect, it } from 'vitest'
import { b64u, fromB64u } from './b64u'
import { fromHex, toHex } from './bytes'
import { canon, parseStrict } from './canonical'
import { describeVector } from './test-vectors'

interface CanonDoc {
  valid: { input: unknown; output: string; output_hex: string }[]
  invalid: { json: string; why: string }[]
  b64u?: { valid: { hex: string; b64u: string }[]; invalid: string[] }
}

describeVector<CanonDoc>('canonical_json.json', (doc) => {
  it.each(doc.valid.map((v, i) => [i, v] as const))('valid case %i', (_i, v) => {
    expect(toHex(canon(v.input))).toBe(v.output_hex)
    expect(toHex(canon(parseStrict(v.output)))).toBe(v.output_hex)
  })
  it.each(doc.invalid.map((v) => [v.why, v.json] as const))('rejects %s', (_why, json) => {
    expect(() => canon(parseStrict(json))).toThrow()
  })
  if (doc.b64u) {
    const b = doc.b64u
    it('b64u valid', () => {
      for (const v of b.valid) {
        expect(b64u(fromHex(v.hex))).toBe(v.b64u)
        expect(toHex(fromB64u(v.b64u))).toBe(v.hex)
      }
    })
    it.each(b.invalid)('b64u rejects %j', (s) => {
      expect(() => fromB64u(s)).toThrow()
    })
  }
})

describe('canonical JSON (local)', () => {
  it('rejects values outside the restriction', () => {
    expect(() => canon({ a: 1.5 })).toThrow()
    expect(() => canon(-0)).toThrow()
    expect(() => canon(2 ** 53)).toThrow()
    expect(() => canon({ 'é': 1 })).toThrow()
    expect(() => canon('\ud800')).toThrow()
    expect(() => canon({ a: undefined })).toThrow()
    expect(() => canon(new Uint8Array(1))).toThrow()
  })
  it('escapes per SUITE.md 2.2', () => {
    expect(new TextDecoder().decode(canon({ s: '\u0001/\u007f\b' }))).toBe('{"s":"\\u0001/\u007f\\b"}')
  })
  it('b64u round trips every length', () => {
    for (let n = 0; n < 40; n++) {
      const x = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 255)
      expect(fromB64u(b64u(x))).toEqual(x)
    }
  })
})
