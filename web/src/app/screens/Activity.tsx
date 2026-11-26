import { useInfiniteQuery } from '@tanstack/react-query'
import { useState } from 'react'
import type { Receipt } from '@/client/types'
import { ErrorNotice } from '@/components/qg/error-notice'
import { EmptyState, PageHeader, RowsSkeleton } from '@/components/qg/page'
import { Button } from '@/components/ui/button'
import { useDocumentTitle, useOnline } from '@/lib/hooks'
import { qk, useClient, useMe } from '../client-context'
import { ReceiptSheet } from './parts/ReceiptSheet'
import { DecisionSegment, ReceiptTable } from './parts/ReceiptTable'
import type { DecisionFilter } from './parts/ReceiptTable'

export default function Activity() {
  useDocumentTitle('Activity')
  const client = useClient()
  const online = useOnline()
  const { device } = useMe()
  const [filter, setFilter] = useState<DecisionFilter>('all')
  const [open, setOpen] = useState<Receipt | null>(null)
  const userId = device?.user_id
  const q = useInfiniteQuery({
    queryKey: [...qk.receipts({ user_id: userId }), 'pages'],
    enabled: !!userId,
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam }) => client.listReceipts({ user_id: userId, before: pageParam }),
    getNextPageParam: (last) => last.next_before ?? undefined,
  })
  const all = q.data?.pages.flatMap((p) => p.items) ?? []
  const items = filter === 'all' ? all : all.filter((r) => r.decision === filter)

  return (
    <>
      <PageHeader title="Activity" description="Every decision made for you, newest first. Open one to check it against the log." actions={<DecisionSegment value={filter} onChange={setFilter} />} />
      {q.isPending ? (
        <RowsSkeleton rows={6} />
      ) : q.error ? (
        <ErrorNotice error={q.error} onRetry={() => void q.refetch()} />
      ) : all.length === 0 ? (
        <EmptyState title="Nothing recorded yet" body="Every decision made for you appears here as a receipt you can verify." testId="activity-empty" />
      ) : (
        <>
          <div className="overflow-x-auto border border-border" data-tour="activity-list" data-testid="activity-list">
            {items.length === 0 ? (
              <p className="p-4 text-sm text-muted-foreground">No {filter === 'allow' ? 'allowed' : 'denied'} decisions in what is loaded so far.</p>
            ) : (
              <ReceiptTable items={items} onOpen={setOpen} />
            )}
          </div>
          {q.hasNextPage ? (
            <div className="mt-4 flex justify-center">
              <Button variant="outline" className="h-9" onClick={() => void q.fetchNextPage()} disabled={q.isFetchingNextPage || !online} data-testid="activity-more">
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
