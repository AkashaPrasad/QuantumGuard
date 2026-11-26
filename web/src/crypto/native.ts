// Feature detection only (status page): does this browser's Web Crypto advertise ML-KEM-768 and
// ML-DSA-65 (WICG "Modern Algorithms in WebCrypto")? Device keys always use the noble provider.

type SubtleWithSupports = { supports?: (op: string, alg: string) => boolean }

async function probe(alg: string, usages: string[]): Promise<boolean> {
  const c = (globalThis as { crypto?: Crypto }).crypto
  if (!c?.subtle) return false
  const ctor = (globalThis as { SubtleCrypto?: SubtleWithSupports }).SubtleCrypto
  if (typeof ctor?.supports === 'function') {
    try {
      return ctor.supports('generateKey', alg)
    } catch {
      return false
    }
  }
  try {
    await c.subtle.generateKey({ name: alg }, false, usages as KeyUsage[])
    return true
  } catch {
    return false
  }
}

/** Reports native ML-KEM-768 / ML-DSA-65 support in Web Crypto. Never used for device keys. */
export async function detectNativePq(): Promise<{ mlkem: boolean; mldsa: boolean }> {
  const [mlkem, mldsa] = await Promise.all([
    probe('ML-KEM-768', ['encapsulateBits', 'decapsulateBits']),
    probe('ML-DSA-65', ['sign', 'verify']),
  ])
  return { mlkem, mldsa }
}
