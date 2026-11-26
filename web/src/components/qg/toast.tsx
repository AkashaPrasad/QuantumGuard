import { Check, CircleAlert, Info, X } from 'lucide-react'
import { createContext, useCallback, useContext, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

// A small toast region of our own: the common libraries inject a <style> tag at
// run time, which the Content-Security-Policy (style-src 'self') forbids.

type Tone = 'done' | 'info' | 'problem'
interface Toast {
  id: number
  tone: Tone
  title: string
  body?: string
}

const ToastContext = createContext<(t: Omit<Toast, 'id'>) => void>(() => {})

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const next = useRef(1)
  const dismiss = useCallback((id: number) => setToasts((ts) => ts.filter((t) => t.id !== id)), [])
  const push = useCallback(
    (t: Omit<Toast, 'id'>) => {
      const id = next.current++
      setToasts((ts) => [...ts.slice(-2), { ...t, id }])
      setTimeout(() => dismiss(id), t.tone === 'problem' ? 9000 : 5000)
    },
    [dismiss],
  )
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div
        aria-live="polite"
        aria-relevant="additions"
        className="pointer-events-none fixed inset-x-3 bottom-3 z-[70] flex flex-col items-end gap-2 sm:inset-x-auto sm:right-4 sm:bottom-4"
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            data-testid="toast"
            className="animate-enter pointer-events-auto flex w-full items-start gap-2.5 border border-rule bg-popover p-3 shadow-lift sm:w-88"
          >
            {t.tone === 'done' ? (
              <Check className="mt-0.5 size-4 shrink-0 text-allow" aria-hidden />
            ) : t.tone === 'problem' ? (
              <CircleAlert className="mt-0.5 size-4 shrink-0 text-deny" aria-hidden />
            ) : (
              <Info className="mt-0.5 size-4 shrink-0 text-primary" aria-hidden />
            )}
            <div className="min-w-0 flex-1">
              <p className={cn('font-medium', !t.body && 'leading-5')}>{t.title}</p>
              {t.body ? <p className="mt-0.5 text-sm text-muted-foreground">{t.body}</p> : null}
            </div>
            <button
              type="button"
              onClick={() => dismiss(t.id)}
              className="inline-flex size-6 shrink-0 items-center justify-center text-muted-foreground hover:bg-muted hover:text-foreground"
              aria-label="Dismiss"
            >
              <X className="size-3.5" aria-hidden />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast() {
  return useContext(ToastContext)
}
