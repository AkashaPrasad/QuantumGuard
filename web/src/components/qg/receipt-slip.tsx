import { Check, ShieldCheck, X } from 'lucide-react'
import type { ReactNode } from 'react'
import { useNames } from '@/app/names'
import type { Receipt } from '@/client/types'
import { Button } from '@/components/ui/button'
import { actionWords, exactTime, shortId } from '@/lib/format'
import { cn } from '@/lib/utils'
import { Ident } from './ident'

export type SlipCheck = 'unchecked' | 'checking' | 'verified' | 'failed'

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[7.5rem_1fr] gap-2 py-1">
      <dt className="label-caps pt-0.5">{label}</dt>
      <dd className="min-w-0 text-[0.8125rem]">{children}</dd>
    </div>
  )
}

/**
 * The signature element: a decision printed as a slip of paper.
 * The stamp appears only after this device has checked the proof itself.
 */
export function ReceiptSlip({
  receipt,
  check = 'unchecked',
  onVerify,
  footer,
  className,
}: {
  receipt: Receipt
  check?: SlipCheck
  onVerify?: () => void
  footer?: ReactNode
  className?: string
}) {
  const names = useNames()
  const allow = receipt.decision === 'allow'
  const who = names.user(receipt.subject.user_id)
  const device = names.device(receipt.subject.device_id)
  return (
    <article
      data-testid="receipt-slip"
      data-receipt-id={receipt.id}
      data-check={check}
      aria-label={`Receipt ${receipt.id}`}
      className={cn('slip mb-2 w-full max-w-md px-4 pt-4 pb-5 font-mono', className)}
    >
      <header className="flex items-start justify-between gap-3">
        <div>
          <p className="label-caps">QuantumGuard receipt</p>
          <Ident value={receipt.id} label="receipt id" className="mt-0.5" />
        </div>
        <p
          className={cn(
            'inline-flex items-center gap-1 text-sm font-medium tracking-[0.08em] uppercase',
            allow ? 'text-allow' : 'text-deny',
          )}
        >
          {allow ? <Check className="size-4" aria-hidden /> : <X className="size-4" aria-hidden />}
          {allow ? 'Allowed' : 'Denied'}
        </p>
      </header>

      <p className="mt-3 font-sans text-base font-medium">{actionWords(receipt.action)}</p>
      <p className="font-sans text-sm break-words text-muted-foreground">{receipt.resource}</p>

      <dl className="rule-dotted mt-3 pt-2">
        <Row label="When">{exactTime(receipt.ts)}</Row>
        <Row label="Who">
          {who ?? <span className="text-muted-foreground">{shortId(receipt.subject.user_id)}</span>}
        </Row>
        <Row label="Device">
          {device ?? <span className="text-muted-foreground">{shortId(receipt.subject.device_id)}</span>}
        </Row>
        <Row label="Reason">{receipt.reason_code}</Row>
        <Row label="Rules">{receipt.matched_rules.length ? receipt.matched_rules.join(', ') : 'default deny'}</Row>
      </dl>
      <dl className="rule-dotted mt-2 pt-2">
        <Row label="Log entry">#{receipt.leaf_index}</Row>
        <Row label="Directory">epoch {receipt.directory_epoch}</Row>
        <Row label="Policy">
          <span className="break-all" title={receipt.policy_bundle_hash}>
            {shortId(receipt.policy_bundle_hash, 6)}
          </span>
        </Row>
        <Row label="Request">
          <span className="break-all" title={receipt.request_hash}>
            {shortId(receipt.request_hash, 6)}
          </span>
        </Row>
      </dl>

      <div className="rule-dotted mt-2 flex min-h-14 items-center justify-between gap-3 pt-3">
        {check === 'verified' ? (
          <p
            data-testid="receipt-stamp"
            className="animate-stamp inline-flex items-center gap-1.5 border-2 border-allow px-2 py-1 text-[0.6875rem] font-medium tracking-[0.1em] text-allow uppercase"
          >
            <ShieldCheck className="size-4" aria-hidden />
            Verified on this device
          </p>
        ) : check === 'failed' ? (
          <p className="inline-flex items-center gap-1.5 border-2 border-deny px-2 py-1 text-[0.6875rem] font-medium tracking-[0.1em] text-deny uppercase">
            <X className="size-4" aria-hidden />
            Did not verify
          </p>
        ) : (
          <p className="font-sans text-sm text-muted-foreground">
            {check === 'checking' ? 'Checking the proof on this device…' : 'Not yet checked on this device.'}
          </p>
        )}
        {onVerify && check !== 'verified' ? (
          <Button
            variant="outline"
            size="sm"
            onClick={onVerify}
            disabled={check === 'checking'}
            className="font-sans"
            data-testid="receipt-verify"
          >
            <ShieldCheck aria-hidden />
            {check === 'failed' ? 'Check again' : 'Verify'}
          </Button>
        ) : null}
      </div>
      {footer ? <div className="mt-2 font-sans">{footer}</div> : null}
    </article>
  )
}
