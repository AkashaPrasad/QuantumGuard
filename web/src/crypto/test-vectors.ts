/// <reference types="node" />
// Test helper (imported only by *.test.ts): locates spec/vectors via QG_VECTORS_DIR or the repo,
// and exposes a describe() that skips visibly when a vector file is absent.
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe } from 'vitest'

export const VECTORS_DIR = process.env.QG_VECTORS_DIR ?? fileURLToPath(new URL('../../../spec/vectors/', import.meta.url))

/** Parsed vector file, or null when missing. */
export function loadVector<T = Record<string, unknown>>(name: string): T | null {
  const p = join(VECTORS_DIR, name)
  if (!existsSync(p)) return null
  return JSON.parse(readFileSync(p, 'utf8')) as T
}

/** describe() for a vector file: runs `fn(doc)` or skips with a visible reason. */
export function describeVector<T = Record<string, unknown>>(name: string, fn: (doc: T) => void): void {
  const doc = loadVector<T>(name)
  if (!doc) {
    console.warn(`[vectors] ${name} not found in ${VECTORS_DIR}; skipping`)
    describe.skip(`vectors/${name} (MISSING in ${VECTORS_DIR})`, () => {})
    return
  }
  describe(`vectors/${name}`, () => fn(doc))
}
