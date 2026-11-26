import { useEffect, useRef, useState } from 'react'
import { useToast } from '@/components/qg/toast'
import { useClient } from '../client-context'

const DEFAULT_IDLE_MS = 10 * 60 * 1000
export const IDLE_MS = Number(import.meta.env.VITE_QG_IDLE_MS) || DEFAULT_IDLE_MS

/** Locks the device after ten minutes without input. Returns milliseconds left. */
export function useIdleLock(active: boolean): number {
  const client = useClient()
  const toast = useToast()
  const last = useRef(Date.now())
  const warned = useRef(false)
  const [left, setLeft] = useState(IDLE_MS)

  useEffect(() => {
    if (!active) return
    last.current = Date.now()
    warned.current = false
    const touch = () => {
      last.current = Date.now()
      warned.current = false
    }
    const events = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const
    events.forEach((e) => addEventListener(e, touch, { passive: true }))
    const timer = setInterval(() => {
      const remaining = IDLE_MS - (Date.now() - last.current)
      setLeft(remaining)
      if (remaining <= 60_000 && remaining > 0 && !warned.current && IDLE_MS > 90_000) {
        warned.current = true
        toast({ tone: 'info', title: 'This device locks in one minute', body: 'Move the pointer or press a key to stay unlocked.' })
      }
      if (remaining <= 0) client.lock()
    }, 1000)
    return () => {
      events.forEach((e) => removeEventListener(e, touch))
      clearInterval(timer)
    }
  }, [active, client, toast])

  return left
}
