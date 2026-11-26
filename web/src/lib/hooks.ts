import { useEffect, useState, useSyncExternalStore } from 'react'

export function useOnline(): boolean {
  return useSyncExternalStore(
    (cb) => {
      addEventListener('online', cb)
      addEventListener('offline', cb)
      return () => {
        removeEventListener('online', cb)
        removeEventListener('offline', cb)
      }
    },
    () => navigator.onLine,
    () => true,
  )
}

export function useReducedMotion(): boolean {
  return useSyncExternalStore(
    (cb) => {
      const mq = matchMedia('(prefers-reduced-motion: reduce)')
      mq.addEventListener('change', cb)
      return () => mq.removeEventListener('change', cb)
    },
    () => matchMedia('(prefers-reduced-motion: reduce)').matches,
    () => false,
  )
}

/** Re-renders on an interval; for countdowns and relative times. */
export function useNow(everyMs = 1000): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), everyMs)
    return () => clearInterval(t)
  }, [everyMs])
  return now
}

export function useDocumentTitle(title: string) {
  useEffect(() => {
    document.title = title ? `${title} · QuantumGuard` : 'QuantumGuard'
  }, [title])
}
