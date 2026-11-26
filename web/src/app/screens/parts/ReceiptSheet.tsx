import { useMutation } from '@tanstack/react-query'
import { Link } from 'react-router'
import type { Receipt } from '@/client/types'
import { ErrorNotice } from '@/components/qg/error-notice'
import { ReceiptSlip } from '@/components/qg/receipt-slip'
import type { SlipCheck } from '@/components/qg/receipt-slip'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { actionWords } from '@/lib/format'
import { useClient } from '../../client-context'

function SheetBody({ receipt }: { receipt: Receipt }) {
  const client = useClient()
  const verify = useMutation({ mutationFn: () => client.verifyReceipt(receipt.id) })
  const check: SlipCheck = verify.isPending ? 'checking' : verify.error ? 'unchecked' : verify.data ? (verify.data.ok ? 'verified' : 'failed') : 'unchecked'
  return (
    <div className="flex flex-col gap-4 px-4 pb-6">
      <ReceiptSlip receipt={receipt} check={check} onVerify={() => verify.mutate()} />
      {verify.error ? <ErrorNotice error={verify.error} onRetry={() => verify.mutate()} /> : null}
      {verify.data && !verify.data.ok ? (
        <p role="alert" className="text-sm text-deny" data-testid="receipt-verify-failed">
          Verification failed{verify.data.failed_index !== null ? ` at entry ${verify.data.failed_index}` : ''}
          {verify.data.reason ? `: ${verify.data.reason}` : '.'}
        </p>
      ) : null}
      <Link to={`/app/evidence/verify?receipt=${receipt.id}`} className="text-sm text-primary underline underline-offset-2" data-testid="receipt-proof-link">
        See the proof step by step
      </Link>
    </div>
  )
}

/** A receipt in a right-hand sheet with a working Verify button. Used by Activity and Evidence. */
export function ReceiptSheet({ receipt, onClose }: { receipt: Receipt | null; onClose: () => void }) {
  return (
    <Sheet open={!!receipt} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full sm:max-w-xl overflow-y-auto" data-testid="receipt-sheet">
        <SheetHeader>
          <SheetTitle>{receipt ? actionWords(receipt.action) : 'Receipt'}</SheetTitle>
          <SheetDescription>A signed record of one decision. Verify it to check it against the log on this device.</SheetDescription>
        </SheetHeader>
        {receipt ? <SheetBody key={receipt.id} receipt={receipt} /> : null}
      </SheetContent>
    </Sheet>
  )
}
