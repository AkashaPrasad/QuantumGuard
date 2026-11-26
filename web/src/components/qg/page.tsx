import type { ReactNode } from 'react'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

export function PageHeader({
  title,
  description,
  actions,
  eyebrow,
}: {
  title: string
  description?: ReactNode
  actions?: ReactNode
  eyebrow?: ReactNode
}) {
  return (
    <header className="mb-6 flex flex-col gap-4 border-b border-rule pb-5 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        {eyebrow ? <div className="label-caps mb-1.5">{eyebrow}</div> : null}
        <h1 className="text-2xl leading-tight">{title}</h1>
        {description ? <p className="mt-1.5 max-w-[68ch] text-muted-foreground">{description}</p> : null}
      </div>
      {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2 [&>*]:max-sm:flex-1">{actions}</div> : null}
    </header>
  )
}

/** One serif headline, one sentence, the primary action. */
export function EmptyState({
  title,
  body,
  action,
  className,
  testId,
}: {
  title: string
  body?: ReactNode
  action?: ReactNode
  className?: string
  testId?: string
}) {
  return (
    <div
      data-testid={testId}
      className={cn('bg-lattice flex flex-col items-center border border-dashed border-rule px-6 py-14 text-center', className)}
    >
      <div className="bg-background px-4 py-2">
        <p className="font-display text-3xl leading-tight text-balance">{title}</p>
        {body ? <p className="mx-auto mt-2 max-w-[52ch] text-muted-foreground">{body}</p> : null}
        {action ? <div className="mt-5 flex justify-center gap-2">{action}</div> : null}
      </div>
    </div>
  )
}

export function Section({
  title,
  description,
  actions,
  children,
  className,
}: {
  title: string
  description?: ReactNode
  actions?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={cn('mt-8 first:mt-0', className)}>
      <div className="mb-3 flex items-end justify-between gap-3">
        <div>
          <h2 className="text-base">{title}</h2>
          {description ? <p className="mt-0.5 text-sm text-muted-foreground">{description}</p> : null}
        </div>
        {actions}
      </div>
      {children}
    </section>
  )
}

/** Skeleton rows in the final layout of a table. */
export function RowsSkeleton({ rows = 5, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn('border border-border', className)} aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="flex h-11 items-center gap-4 border-b border-border px-3 last:border-b-0">
          <Skeleton className="h-3.5 w-1/3" />
          <Skeleton className="h-3.5 w-20" />
          <Skeleton className="ml-auto h-3.5 w-24" />
        </div>
      ))}
    </div>
  )
}

/** A figure with its label, used in rows of key numbers. */
export function Figure({
  label,
  value,
  unit,
  tone,
  hint,
  testId,
}: {
  label: string
  value: ReactNode
  unit?: string
  tone?: 'allow' | 'deny' | 'caution'
  hint?: ReactNode
  testId?: string
}) {
  return (
    <div className="min-w-0 border-l border-rule pl-4 first:border-l-0 first:pl-0">
      <div className="label-caps">{label}</div>
      <div
        data-testid={testId}
        className={cn(
          'data mt-1 text-3xl leading-none font-medium',
          tone === 'allow' && 'text-allow',
          tone === 'deny' && 'text-deny',
          tone === 'caution' && 'text-caution',
        )}
      >
        {value}
        {unit ? <span className="ml-1 text-sm font-normal text-muted-foreground">{unit}</span> : null}
      </div>
      {hint ? <div className="mt-1.5 text-sm text-muted-foreground">{hint}</div> : null}
    </div>
  )
}
