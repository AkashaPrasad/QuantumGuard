import { Check, Copy } from 'lucide-react'
import { useEffect, useState } from 'react'
import { exactTime, relativeTime, shortId } from '@/lib/format'
import { useNow } from '@/lib/hooks'
import { cn } from '@/lib/utils'

/** A machine identifier: shortened, mono, with a copy button that says what it copied. */
export function Ident({
  value,
  full = false,
  label = 'identifier',
  className,
}: {
  value: string | null | undefined
  full?: boolean
  label?: string
  className?: string
}) {
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (!copied) return
    const t = setTimeout(() => setCopied(false), 1600)
    return () => clearTimeout(t)
  }, [copied])
  if (!value) return <span className="text-muted-foreground">—</span>
  return (
    <span className={cn('inline-flex max-w-full items-center gap-1 align-middle', className)}>
      <span className={cn('data text-[0.8125rem]', full ? 'break-all' : 'whitespace-nowrap')} title={full ? undefined : value}>
        {full ? value : shortId(value)}
      </span>
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation()
          void navigator.clipboard?.writeText(value).then(() => setCopied(true))
        }}
        className="inline-flex size-6 shrink-0 items-center justify-center text-muted-foreground hover:bg-muted hover:text-foreground"
        aria-label={copied ? `Copied ${label}` : `Copy ${label}`}
      >
        {copied ? <Check className="size-3 text-allow" aria-hidden /> : <Copy className="size-3" aria-hidden />}
      </button>
      <span className="sr-only" role="status">
        {copied ? 'Copied' : ''}
      </span>
    </span>
  )
}

/** Relative time for reading, exact UTC time on hover and for assistive technology. */
export function Time({ value, className }: { value: string | null | undefined; className?: string }) {
  const now = useNow(30_000)
  if (!value) return <span className="text-muted-foreground">—</span>
  return (
    <time dateTime={value} title={exactTime(value)} className={cn('whitespace-nowrap', className)}>
      {relativeTime(value, now)}
    </time>
  )
}
