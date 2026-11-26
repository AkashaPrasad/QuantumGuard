import { AlertTriangle, Ban, Check, CircleDashed, Clock, Lock, ShieldAlert, ShieldCheck, X } from 'lucide-react'
import type { ComponentType, ReactNode } from 'react'
import type { Classification, Decision, Device, IncidentStatus, Severity } from '@/client/types'
import { cn } from '@/lib/utils'

export type Tone = 'allow' | 'deny' | 'caution' | 'neutral' | 'accent'

const TONE: Record<Tone, string> = {
  allow: 'bg-allow-soft text-allow',
  deny: 'bg-deny-soft text-deny',
  caution: 'bg-caution-soft text-caution',
  neutral: 'bg-muted text-muted-foreground',
  accent: 'bg-accent text-accent-foreground',
}

/** A word with an icon on a tinted ground. Colour supports the word; it never replaces it. */
export function Chip({
  tone = 'neutral',
  icon: Icon,
  children,
  className,
}: {
  tone?: Tone
  icon?: ComponentType<{ className?: string }>
  children: ReactNode
  className?: string
}) {
  return (
    <span
      className={cn(
        'inline-flex h-6 items-center gap-1 px-1.5 font-mono text-[0.6875rem] font-medium uppercase tracking-[0.06em] whitespace-nowrap',
        TONE[tone],
        className,
      )}
    >
      {Icon ? <Icon className="size-3 shrink-0" aria-hidden /> : null}
      {children}
    </span>
  )
}

export function DecisionChip({ decision }: { decision: Decision }) {
  return decision === 'allow' ? (
    <Chip tone="allow" icon={Check}>
      Allowed
    </Chip>
  ) : (
    <Chip tone="deny" icon={X}>
      Denied
    </Chip>
  )
}

export function SeverityChip({ severity }: { severity: Severity }) {
  if (severity === 'critical')
    return (
      <Chip tone="deny" icon={ShieldAlert}>
        Critical
      </Chip>
    )
  if (severity === 'high')
    return (
      <Chip tone="caution" icon={AlertTriangle}>
        High
      </Chip>
    )
  return (
    <Chip tone="neutral" icon={AlertTriangle}>
      Medium
    </Chip>
  )
}

export function DeviceStatusChip({ status }: { status: Device['status'] }) {
  if (status === 'active')
    return (
      <Chip tone="allow" icon={ShieldCheck}>
        Active
      </Chip>
    )
  if (status === 'quarantined')
    return (
      <Chip tone="caution" icon={Clock}>
        Paused
      </Chip>
    )
  return (
    <Chip tone="deny" icon={Ban}>
      Revoked
    </Chip>
  )
}

const CLASS_LABEL: Record<Classification, string> = {
  internal: 'Internal',
  confidential: 'Confidential',
  restricted: 'Restricted',
}

export function ClassificationChip({ value }: { value: Classification }) {
  return (
    <Chip tone={value === 'restricted' ? 'accent' : 'neutral'} icon={value === 'internal' ? undefined : Lock}>
      {CLASS_LABEL[value]}
    </Chip>
  )
}

export function IncidentStatusChip({ status }: { status: IncidentStatus }) {
  switch (status) {
    case 'open':
      return (
        <Chip tone="deny" icon={ShieldAlert}>
          Open
        </Chip>
      )
    case 'rekeying':
      return (
        <Chip tone="caution" icon={CircleDashed}>
          New keys in progress
        </Chip>
      )
    case 'contained':
      return (
        <Chip tone="allow" icon={ShieldCheck}>
          Contained
        </Chip>
      )
    default:
      return (
        <Chip tone="neutral" icon={Check}>
          Closed
        </Chip>
      )
  }
}
