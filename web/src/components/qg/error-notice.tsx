import { CircleAlert, RotateCw } from 'lucide-react'
import { Link } from 'react-router'
import { Button } from '@/components/ui/button'
import { describeError } from '@/lib/errors'
import { cn } from '@/lib/utils'

/**
 * The one way an error is shown: what happened, why, what to do next,
 * and a details line with the code for whoever has to look it up.
 */
export function ErrorNotice({
  error,
  onRetry,
  retryLabel = 'Try again',
  className,
  testId = 'error-notice',
}: {
  error: unknown
  onRetry?: () => void
  retryLabel?: string
  className?: string
  testId?: string
}) {
  const e = describeError(error)
  return (
    <div
      role="alert"
      data-testid={testId}
      data-code={e.code}
      className={cn('border border-deny/40 bg-deny-soft/60 p-3 text-foreground', className)}
    >
      <div className="flex items-start gap-2.5">
        <CircleAlert className="mt-0.5 size-4 shrink-0 text-deny" aria-hidden />
        <div className="min-w-0 flex-1">
          <p className="font-semibold">{e.title}</p>
          <p className="mt-0.5 text-sm text-foreground/85">{e.body}</p>
          <details className="mt-2 text-muted-foreground">
            <summary className="label-caps cursor-pointer select-none hover:text-foreground">Details</summary>
            <dl className="data mt-1.5 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-[0.75rem]">
              <dt>code</dt>
              <dd>{e.code}</dd>
              {e.reason ? (
                <>
                  <dt>reason</dt>
                  <dd>{e.reason}</dd>
                </>
              ) : null}
              {e.requestId ? (
                <>
                  <dt>request</dt>
                  <dd className="break-all">{e.requestId}</dd>
                </>
              ) : null}
              {e.receiptId ? (
                <>
                  <dt>receipt</dt>
                  <dd>
                    <Link className="text-primary underline underline-offset-2" to={`/app/evidence/verify?receipt=${e.receiptId}`}>
                      {e.receiptId}
                    </Link>
                  </dd>
                </>
              ) : null}
            </dl>
          </details>
        </div>
        {onRetry ? (
          <Button variant="outline" size="sm" onClick={onRetry} className="shrink-0">
            <RotateCw aria-hidden />
            {retryLabel}
          </Button>
        ) : null}
      </div>
    </div>
  )
}
