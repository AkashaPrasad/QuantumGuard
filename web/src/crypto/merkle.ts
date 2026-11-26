// SUITE.md 9.1: RFC 6962 hashing; inclusion and consistency verification per RFC 9162
// sections 2.1.3.2 and 2.1.4.2. Sizes are handled with arithmetic, not 32-bit bit operators.
import { concat, ctEqual } from './bytes'
import { getProvider, type CryptoProvider } from './provider'

export interface NodeStep {
  level: number
  hash: Uint8Array
  sibling: Uint8Array
  side: 'left' | 'right'
}

const LEAF = new Uint8Array([0x00])
const NODE = new Uint8Array([0x01])

/** SUITE.md 9.1: leaf_hash = SHA-256(0x00 || leaf). */
export function leafHash(leaf: Uint8Array, prov: CryptoProvider = getProvider()): Uint8Array {
  return prov.sha256Sync(concat(LEAF, leaf))
}

/** SUITE.md 9.1: node(l, r) = SHA-256(0x01 || l || r). */
export function nodeHash(l: Uint8Array, r: Uint8Array, prov: CryptoProvider = getProvider()): Uint8Array {
  return prov.sha256Sync(concat(NODE, l, r))
}

function largestPow2Below(n: number): number {
  let k = 1
  while (k * 2 < n) k *= 2
  return k
}

/** SUITE.md 9.1: MTH over leaf hashes (used by tests and the bundle self-check). */
export function rootFromLeafHashes(hashes: Uint8Array[], prov: CryptoProvider = getProvider()): Uint8Array {
  if (hashes.length === 0) return prov.sha256Sync(new Uint8Array(0))
  if (hashes.length === 1) return hashes[0]
  const k = largestPow2Below(hashes.length)
  return nodeHash(rootFromLeafHashes(hashes.slice(0, k), prov), rootFromLeafHashes(hashes.slice(k), prov), prov)
}

const odd = (x: number) => x % 2 === 1
const half = (x: number) => Math.floor(x / 2)

/** RFC 9162 2.1.3.2: compute the root implied by an inclusion proof, or null if malformed. */
export function rootFromInclusion(index: number, treeSize: number, leaf: Uint8Array, path: Uint8Array[], onNode?: (s: NodeStep) => void, prov: CryptoProvider = getProvider()): Uint8Array | null {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(treeSize) || index < 0 || index >= treeSize) return null
  let fn = index
  let sn = treeSize - 1
  let r = leaf
  let level = 0
  for (const p of path) {
    if (sn === 0) return null
    if (odd(fn) || fn === sn) {
      r = nodeHash(p, r, prov)
      onNode?.({ level: level + 1, hash: r, sibling: p, side: 'left' })
      if (!odd(fn)) {
        while (!odd(fn) && fn !== 0) {
          fn = half(fn)
          sn = half(sn)
          level++
        }
      }
    } else {
      r = nodeHash(r, p, prov)
      onNode?.({ level: level + 1, hash: r, sibling: p, side: 'right' })
    }
    fn = half(fn)
    sn = half(sn)
    level++
  }
  return sn === 0 ? r : null
}

/** RFC 9162 2.1.3.2: verify that `leaf` sits at `index` in the tree with `root`. */
export function verifyInclusion(index: number, treeSize: number, leaf: Uint8Array, path: Uint8Array[], root: Uint8Array, onNode?: (s: NodeStep) => void, prov: CryptoProvider = getProvider()): boolean {
  const r = rootFromInclusion(index, treeSize, leaf, path, onNode, prov)
  return r !== null && ctEqual(r, root)
}

/** RFC 9162 2.1.4.2: verify a consistency proof between two tree heads. */
export function verifyConsistency(first: number, second: number, firstRoot: Uint8Array, secondRoot: Uint8Array, proof: Uint8Array[], prov: CryptoProvider = getProvider()): boolean {
  if (!Number.isSafeInteger(first) || !Number.isSafeInteger(second) || first < 0 || second < first) return false
  if (first === second) return proof.length === 0 && ctEqual(firstRoot, secondRoot)
  if (first === 0) return proof.length === 0
  if (proof.length === 0) return false
  let path = proof
  if (isPow2(first)) path = [firstRoot, ...proof]
  let fn = first - 1
  let sn = second - 1
  while (odd(fn)) {
    fn = half(fn)
    sn = half(sn)
  }
  let fr = path[0]
  let sr = path[0]
  for (const c of path.slice(1)) {
    if (sn === 0) return false
    if (odd(fn) || fn === sn) {
      fr = nodeHash(c, fr, prov)
      sr = nodeHash(c, sr, prov)
      if (!odd(fn)) {
        while (!odd(fn) && fn !== 0) {
          fn = half(fn)
          sn = half(sn)
        }
      }
    } else {
      sr = nodeHash(sr, c, prov)
    }
    fn = half(fn)
    sn = half(sn)
  }
  return sn === 0 && ctEqual(fr, firstRoot) && ctEqual(sr, secondRoot)
}

function isPow2(n: number): boolean {
  let k = 1
  while (k < n) k *= 2
  return k === n
}
