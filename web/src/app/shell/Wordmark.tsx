import { cn } from '@/lib/utils'

/** A nine-point lattice with one point filled: the device that holds the key. */
export function Mark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 20 20" className={cn('size-5', className)} aria-hidden>
      {[3, 10, 17].flatMap((y) =>
        [3, 10, 17].map((x) =>
          x === 10 && y === 10 ? (
            <rect key={`${x}-${y}`} x={7} y={7} width={6} height={6} className="fill-primary" />
          ) : (
            <rect key={`${x}-${y}`} x={x - 1.25} y={y - 1.25} width={2.5} height={2.5} className="fill-current" />
          ),
        ),
      )}
    </svg>
  )
}

export function Wordmark({ className }: { className?: string }) {
  return (
    <span className={cn('inline-flex items-center gap-2 font-semibold tracking-tight', className)}>
      <Mark />
      QuantumGuard
    </span>
  )
}
