import { Check, KeyRound, Laptop } from 'lucide-react'
import { motion } from 'motion/react'
import { useReducedMotion } from '@/lib/hooks'
import { cn } from '@/lib/utils'

export interface WrapTarget {
  device_id: string
  device_name: string
  owner?: string
}

/**
 * Wrapping, drawn: one beam from the file key to each device, completed when
 * the server has accepted that device's key slot. A checklist when motion is reduced.
 */
export function WrapBeams({ targets, wrapped }: { targets: WrapTarget[]; wrapped: Set<string> }) {
  const reduced = useReducedMotion()
  return (
    <ul className="flex flex-col gap-1.5" data-testid="wrap-beams" aria-label="Devices receiving a wrapped key">
      {targets.map((t) => {
        const ok = wrapped.has(t.device_id)
        return (
          <li key={t.device_id} data-wrapped={ok} className="flex items-center gap-2">
            <KeyRound className={cn('size-4 shrink-0', ok ? 'text-primary' : 'text-muted-foreground')} aria-hidden />
            <span className="relative h-px min-w-6 flex-1 bg-border" aria-hidden>
              {ok ? (
                <motion.span
                  className="absolute inset-0 origin-left bg-primary"
                  initial={reduced ? false : { scaleX: 0 }}
                  animate={{ scaleX: 1 }}
                  transition={{ duration: 0.35, ease: [0.22, 0.8, 0.3, 1] }}
                />
              ) : null}
            </span>
            <Laptop className={cn('size-4 shrink-0', ok ? 'text-foreground' : 'text-muted-foreground')} aria-hidden />
            <span className={cn('w-1/2 truncate text-sm', !ok && 'text-muted-foreground')}>
              {t.device_name}
              {t.owner ? <span className="text-muted-foreground"> · {t.owner}</span> : null}
            </span>
            {ok ? <Check className="size-4 shrink-0 text-allow" aria-hidden /> : <span className="size-4 shrink-0" />}
            <span className="sr-only">{ok ? 'key wrapped' : 'waiting'}</span>
          </li>
        )
      })}
    </ul>
  )
}
