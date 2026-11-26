import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { Search } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router'
import type { Receipt } from '@/client/types'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Ident, Time } from '@/components/qg/ident'
import { EmptyState, PageHeader, RowsSkeleton } from '@/components/qg/page'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { NativeSelect } from '@/components/qg/native-select'
import { actionWords } from '@/lib/format'
import { useDocumentTitle, useOnline } from '@/lib/hooks'
import { qk, useClient } from '../client-context'
import { ReceiptSheet } from './parts/ReceiptSheet'
import { DecisionSegment, ReceiptTable } from './parts/ReceiptTable'
import type { DecisionFilter } from './parts/ReceiptTable'

const ACTIONS = [
  'enroll', 'session.start', 'session.end', 'file.create', 'file.commit', 'slot.release', 'chunk.read', 'file.share', 'file.unshare', 'file.delete',
  'rekey.commit', 'device.report_lost', 'device.revoke', 'device.rename', 'invite.create', 'change.request', 'change.approve', 'change.reject',
  'alert.ack', 'response.lift', 'service.create', 'service.rotate', 'signal.receive', 'message.send', 'recovery.release', 'incident.close', 'bundle.export',
]

export default function Evidence() {
  useDocumentTitle('Evidence log')
  const client = useClient()
  const online = useOnline()
  const [decision, setDecision] = useState<DecisionFilter>('all')
  const [action, setAction] = useState('all')
  const [idInput, setIdInput] = useState('')
  const [lookupId, setLookupId] = useState('')
  const [open, setOpen] = useState<Receipt | null>(null)

  const checkpoint = useQuery({ queryKey: qk.checkpoint, queryFn: () => client.checkpoint() })
  const params = { decision: decision === 'all' ? undefined : decision, action: action === 'all' ? undefined : action }
  const q = useInfiniteQuery({
    queryKey: [...qk.receipts(params), 'pages'],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) => client.listReceipts({ ...params, before: pageParam }),
    getNextPageParam: (last) => last.next_before ?? undefined,
  })
  const lookup = useQuery({ queryKey: qk.receipt(lookupId), queryFn: () => client.getReceipt(lookupId), enabled: !!lookupId, retry: false })
  const items = q.data?.pages.flatMap((p) => p.items) ?? []
  const cp = checkpoint.data

  return (
    <>
      <PageHeader
        title="Evidence log"
        description="Every decision the system has made, in the order it was written. Anyone can check a receipt against the signed log."
        actions={
          <Button asChild className="h-9" data-testid="evidence-verify-link">
            <Link to="/app/evidence/verify">Verify a receipt or bundle</Link>
          </Button>
        }
      />
      <section aria-label="Current checkpoint" className="mb-6 border border-border bg-card p-4" data-testid="evidence-checkpoint">
        <h2 className="label-caps mb-2">Current checkpoint</h2>
        {checkpoint.isPending ? (
          <p className="text-sm text-muted-foreground">Loading</p>
        ) : cp ? (
          <>
            <dl className="grid gap-x-8 gap-y-2 sm:grid-cols-[auto_1fr_auto]">
              <div>
                <dt className="label-caps">Tree size</dt>
                <dd className="data">{cp.tree_size}</dd>
              </div>
              <div className="min-w-0">
                <dt className="label-caps">Root hash</dt>
                <dd>
                  <Ident value={cp.root_hash} label="root hash" />
                </dd>
              </div>
              <div>
                <dt className="label-caps">Signed</dt>
                <dd>
                  <Time value={cp.ts} />
                </dd>
              </div>
            </dl>
            <p className="mt-2 text-sm text-muted-foreground">Signed with Ed25519 and ML-DSA-65.</p>
          </>
        ) : (
          <ErrorNotice error={checkpoint.error} onRetry={() => void checkpoint.refetch()} />
        )}
      </section>

      <div className="mb-4 flex flex-wrap items-end gap-3" data-tour="evidence-log">
        <DecisionSegment value={decision} onChange={setDecision} />
        <div>
          <label htmlFor="ev-action" className="label-caps mb-1 block">Action</label>
          <NativeSelect
            id="ev-action"
            className="w-56 [&_select]:h-9"
            data-testid="filter-action"
            value={action}
            onValueChange={setAction}
            options={[{ value: 'all', label: 'All actions' }, ...ACTIONS.map((a) => ({ value: a, label: actionWords(a) }))]}
          />
        </div>
        <form
          className="flex items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            setLookupId(idInput.trim())
          }}
        >
          <div>
            <label htmlFor="ev-id" className="label-caps mb-1 block">Find a receipt by id</label>
            <Input id="ev-id" value={idInput} onChange={(e) => setIdInput(e.target.value)} placeholder="rcp_…" className="data h-9 w-56" data-testid="evidence-find-input" />
          </div>
          <Button type="submit" variant="outline" className="h-9" disabled={!idInput.trim() || !online} data-testid="evidence-find">
            <Search aria-hidden />
            Find
          </Button>
        </form>
      </div>

      {lookupId ? (
        <div className="mb-4" data-testid="evidence-lookup">
          {lookup.isPending ? (
            <p className="text-sm text-muted-foreground">Looking for that receipt…</p>
          ) : lookup.error ? (
            <ErrorNotice error={lookup.error} onRetry={() => void lookup.refetch()} />
          ) : (
            <Button variant="outline" className="h-9" onClick={() => setOpen(lookup.data)}>
              Open receipt {lookup.data.id}
            </Button>
          )}
        </div>
      ) : null}

      {q.isPending ? (
        <RowsSkeleton rows={6} />
      ) : q.error ? (
        <ErrorNotice error={q.error} onRetry={() => void q.refetch()} />
      ) : items.length === 0 ? (
        <EmptyState title="No receipts match" body="Change the filters, or clear them to see every receipt." testId="evidence-empty" />
      ) : (
        <>
          <div className="overflow-x-auto border border-border" data-testid="evidence-list">
            <ReceiptTable items={items} onOpen={setOpen} />
          </div>
          {q.hasNextPage ? (
            <div className="mt-4 flex justify-center">
              <Button variant="outline" className="h-9" onClick={() => void q.fetchNextPage()} disabled={q.isFetchingNextPage || !online}>
                {q.isFetchingNextPage ? 'Loading' : 'Load more'}
              </Button>
            </div>
          ) : null}
        </>
      )}
      <ReceiptSheet receipt={open} onClose={() => setOpen(null)} />
    </>
  )
}
