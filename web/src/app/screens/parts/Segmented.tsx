import { cn } from '@/lib/utils'

/** A small filter: one choice at a time, keyboard reachable, state shown by more than colour. */
export function Segmented<T extends string>({
  value,
  onChange,
  options,
  label,
  testId,
}: {
  value: T
  onChange: (v: T) => void
  options: { value: T; label: string }[]
  label: string
  testId?: string
}) {
  return (
    <div role="group" aria-label={label} data-testid={testId} className="inline-flex flex-wrap border border-border bg-card">
      {options.map((o) => {
        const on = o.value === value
        return (
          <button
            key={o.value}
            type="button"
            aria-pressed={on}
            onClick={() => onChange(o.value)}
            className={cn(
              'h-9 border-r border-border px-3 text-sm last:border-r-0 focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring',
              on ? 'bg-accent font-medium text-accent-foreground shadow-[inset_0_-2px_0_var(--color-primary)]' : 'text-muted-foreground hover:bg-muted hover:text-foreground',
            )}
          >
            {o.label}
          </button>
        )
      })}
    </div>
  )
}
