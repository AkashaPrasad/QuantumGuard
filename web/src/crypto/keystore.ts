// SUITE.md 15: the passphrase-protected keystore (*.qgkeystore), its IndexedDB record and the
// in-memory key ring. Unlocked seeds live only in the Keyring; lock() zeroes them.
import { createStore, del, get, set, type UseStore } from 'idb-keyval'
import { b64u, fromB64u } from './b64u'
import { fromUtf8, utf8, wipe } from './bytes'
import { canon, parseStrict } from './canonical'
import { getProvider, type Argon2Params, type CryptoProvider } from './provider'
import { SUITE, type ServerKeys } from './suite'

export const KEYSTORE_FORMAT = 'qg-keystore/1'
export const DEFAULT_KDF = { alg: 'argon2id', version: 19, m_kib: 19456, t: 2, p: 1 } as const
const BOUNDS = { m_kib: [19456, 1048576], t: [2, 10], p: [1, 4] } as const

export interface KeystoreLabel {
  user_id: string | null
  device_id: string | null
  device_name: string
  server: string | null
  created_at: string
}

export interface KeystoreKdf {
  alg: 'argon2id'
  version: 19
  m_kib: number
  t: number
  p: number
  salt: string
}

export interface KeystoreFile {
  format: typeof KEYSTORE_FORMAT
  suite: 'QG-1'
  kdf: KeystoreKdf
  aead: { alg: 'AES-256-GCM'; nonce: string }
  label: KeystoreLabel
  ciphertext: string
}

export interface DeviceSeeds {
  kem_seed: Uint8Array
  sig_seed: Uint8Array
}

/** Argon2id implementation hook (the client passes a Web Worker; tests use the provider). */
export type DeriveFn = (password: Uint8Array, salt: Uint8Array, params: Argon2Params) => Promise<Uint8Array>

export class KeystoreError extends Error {
  constructor() {
    super('wrong passphrase or damaged keystore')
    this.name = 'KeystoreError'
  }
}

function sameKeys(o: unknown, keys: string[]): o is Record<string, unknown> {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return false
  const k = Object.keys(o).sort()
  const want = [...keys].sort()
  return k.length === want.length && k.every((x, i) => x === want[i])
}

/** SUITE.md 15: header shape, algorithms and parameter bounds (checked before any derivation). */
export function checkHeader(h: unknown): asserts h is Omit<KeystoreFile, 'ciphertext'> {
  if (!sameKeys(h, ['aead', 'format', 'kdf', 'label', 'suite'])) throw new KeystoreError()
  if (h.format !== KEYSTORE_FORMAT || h.suite !== SUITE) throw new KeystoreError()
  const kdf = h.kdf
  if (!sameKeys(kdf, ['alg', 'version', 'm_kib', 't', 'p', 'salt'])) throw new KeystoreError()
  if (kdf.alg !== 'argon2id' || kdf.version !== 19 || typeof kdf.salt !== 'string') throw new KeystoreError()
  for (const [name, [lo, hi]] of Object.entries(BOUNDS)) {
    const v = kdf[name]
    if (typeof v !== 'number' || !Number.isInteger(v) || v < lo || v > hi) throw new KeystoreError()
  }
  const aead = h.aead
  if (!sameKeys(aead, ['alg', 'nonce']) || aead.alg !== 'AES-256-GCM' || typeof aead.nonce !== 'string') throw new KeystoreError()
  if (!h.label || typeof h.label !== 'object' || Array.isArray(h.label)) throw new KeystoreError()
}

/** SUITE.md 15: key = Argon2id(utf8(NFC(passphrase)), salt, t, m_kib, p, 32). */
export async function deriveKeystoreKey(passphrase: string, kdf: KeystoreKdf, derive?: DeriveFn, prov: CryptoProvider = getProvider()): Promise<Uint8Array> {
  const salt = fromB64u(kdf.salt, 16)
  const pw = utf8(passphrase.normalize('NFC'))
  const params = { t: kdf.t, m_kib: kdf.m_kib, p: kdf.p, dkLen: 32 }
  try {
    return await (derive ? derive(pw, salt, params) : prov.argon2id(pw, salt, params))
  } finally {
    wipe(pw)
  }
}

/** SUITE.md 15: encrypt the seeds under an already derived key (fresh nonce unless given). */
export async function sealWithKey(key: Uint8Array, kdf: KeystoreKdf, seeds: DeviceSeeds, label: KeystoreLabel, nonce?: Uint8Array, prov: CryptoProvider = getProvider()): Promise<KeystoreFile> {
  const n = nonce ?? prov.randomBytes(12)
  const header = {
    aead: { alg: 'AES-256-GCM' as const, nonce: b64u(n) },
    format: KEYSTORE_FORMAT,
    kdf,
    label,
    suite: SUITE,
  } as const
  checkHeader(header)
  const plaintext = canon({ kem_seed: b64u(seeds.kem_seed), sig_seed: b64u(seeds.sig_seed) })
  try {
    const ct = await prov.aesGcmEncrypt(key, n, plaintext, canon(header))
    return { ...header, ciphertext: b64u(ct) }
  } finally {
    wipe(plaintext)
  }
}

/** SUITE.md 15: create a keystore from a passphrase. Returns the file and the derived key. */
export async function sealKeystore(
  seeds: DeviceSeeds,
  passphrase: string,
  label: KeystoreLabel,
  opts: { salt?: Uint8Array; nonce?: Uint8Array; kdf?: { m_kib: number; t: number; p: number }; derive?: DeriveFn } = {},
  prov: CryptoProvider = getProvider(),
): Promise<{ file: KeystoreFile; key: Uint8Array }> {
  const kdf: KeystoreKdf = {
    alg: 'argon2id',
    version: 19,
    m_kib: opts.kdf?.m_kib ?? DEFAULT_KDF.m_kib,
    t: opts.kdf?.t ?? DEFAULT_KDF.t,
    p: opts.kdf?.p ?? DEFAULT_KDF.p,
    salt: b64u(opts.salt ?? prov.randomBytes(16)),
  }
  const key = await deriveKeystoreKey(passphrase, kdf, opts.derive, prov)
  const file = await sealWithKey(key, kdf, seeds, label, opts.nonce, prov)
  return { file, key }
}

/** SUITE.md 15: open a keystore; every failure is the same KeystoreError. */
export async function openKeystore(doc: unknown, passphrase: string, derive?: DeriveFn, prov: CryptoProvider = getProvider()): Promise<{ seeds: DeviceSeeds; key: Uint8Array; file: KeystoreFile }> {
  if (!sameKeys(doc, ['aead', 'ciphertext', 'format', 'kdf', 'label', 'suite'])) throw new KeystoreError()
  const { ciphertext, ...header } = doc
  checkHeader(header)
  let key: Uint8Array | null = null
  let pt: Uint8Array | null = null
  try {
    const nonce = fromB64u(header.aead.nonce, 12)
    const ct = fromB64u(ciphertext as string)
    key = await deriveKeystoreKey(passphrase, header.kdf, derive, prov)
    pt = await prov.aesGcmDecrypt(key, nonce, ct, canon(header))
    const inner = parseStrict(fromUtf8(pt))
    if (!sameKeys(inner, ['kem_seed', 'sig_seed'])) throw new KeystoreError()
    const seeds = { kem_seed: fromB64u(inner.kem_seed as string, 32), sig_seed: fromB64u(inner.sig_seed as string, 32) }
    return { seeds, key, file: doc as unknown as KeystoreFile }
  } catch {
    wipe(key)
    throw new KeystoreError()
  } finally {
    wipe(pt)
  }
}

/** SUITE.md 15: change the label (re-encrypts with a fresh nonce under the same key). */
export function relabel(file: KeystoreFile, key: Uint8Array, seeds: DeviceSeeds, label: KeystoreLabel, prov: CryptoProvider = getProvider()): Promise<KeystoreFile> {
  return sealWithKey(key, file.kdf, seeds, label, undefined, prov)
}

// ---- local storage of the wrapped keystore ---------------------------------------------------

/** What IndexedDB holds for this browser: the wrapped keystore plus public trust state. */
export interface StoredDevice {
  keystore: KeystoreFile
  device: {
    device_id: string
    device_name: string
    user_id: string
    user_name: string
    roles: string[]
    enrolled_at: string
  }
  /** Server keys pinned at enrolment; a different key later is refused. */
  server_keys: ServerKeys
  /** Highest directory epoch seen; a lower one is refused (SUITE.md 8.1). */
  highest_epoch: number
  revoked?: boolean
}

export interface DeviceStore {
  load(): Promise<StoredDevice | null>
  save(d: StoredDevice): Promise<void>
  clear(): Promise<void>
}

const RECORD_KEY = 'device'
let idbStore: UseStore | null = null
function store(): UseStore {
  if (!idbStore) idbStore = createStore('quantumguard', 'keystore')
  return idbStore
}

/** The IndexedDB-backed store (idb-keyval). Only wrapped key material is ever written. */
export const idbDeviceStore: DeviceStore = {
  async load() {
    return (await get<StoredDevice>(RECORD_KEY, store())) ?? null
  },
  save(d) {
    return set(RECORD_KEY, d, store())
  },
  clear() {
    return del(RECORD_KEY, store())
  },
}

/** An in-memory store for tests and environments without IndexedDB. */
export function memoryDeviceStore(): DeviceStore {
  let v: StoredDevice | null = null
  return {
    async load() {
      return v ? (JSON.parse(JSON.stringify(v)) as StoredDevice) : null
    },
    async save(d) {
      v = JSON.parse(JSON.stringify(d)) as StoredDevice
    },
    async clear() {
      v = null
    },
  }
}

// ---- in-memory key ring -----------------------------------------------------------------------

/** Holds unlocked seeds in memory only. `lock()` zeroes every byte it holds. */
export class Keyring {
  private seeds: DeviceSeeds | null = null

  load(seeds: DeviceSeeds): void {
    this.lock()
    this.seeds = { kem_seed: seeds.kem_seed.slice(), sig_seed: seeds.sig_seed.slice() }
  }

  get unlocked(): boolean {
    return this.seeds !== null
  }

  kemSeed(): Uint8Array {
    if (!this.seeds) throw new Error('keys are locked')
    return this.seeds.kem_seed
  }

  sigSeed(): Uint8Array {
    if (!this.seeds) throw new Error('keys are locked')
    return this.seeds.sig_seed
  }

  lock(): void {
    if (this.seeds) wipe(this.seeds.kem_seed, this.seeds.sig_seed)
    this.seeds = null
  }
}
