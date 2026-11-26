import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router'
import type { IncidentStatus } from '@/client/types'
import { IncidentStatusChip } from '@/components/qg/chips'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Time } from '@/components/qg/ident'
import { EmptyState, PageHeader, RowsSkeleton } from '@/components/qg/page'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useDocumentTitle } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { qk, useClient } from '../client-context'
import { Segmented } from './parts/Segmented'

type Filter = 'all' | IncidentStatus

export default function Incidents() {
  useDocumentTitle('Incidents')
  const client = useClient()
  const [filter, setFilter] = useState<Filter>('all')
  const status = filter === 'all' ? undefined : filter
  const incidents = useQuery({ queryKey: qk.incidents(status), queryFn: () => client.listIncidents(status), refetchInterval: 6000 })
  const list = incidents.data ?? []
  return (
    <>
      <PageHeader title="Incidents" description="Each revoked or lost device has an incident: what it could have opened, and the new keys that follow." />
      <div className="mb-3">
        <Segmented
          label="Filter by status"
          value={filter}
          onChange={setFilter}
          testId="incidents-filter"
          options={[
            { value: 'all', label: 'All' },
            { value: 'open', label: 'Open' },
            { value: 'rekeying', label: 'New keys in progress' },
            { value: 'contained', label: 'Contained' },
            { value: 'closed', label: 'Closed' },
          ]}
        />
      </div>
      {incidents.isPending ? (
        <RowsSkeleton rows={4} />
      ) : incidents.error ? (
        <ErrorNotice error={incidents.error} onRetry={() => void incidents.refetch()} />
      ) : list.length === 0 ? (
        <EmptyState title="No incidents" body="When a device is reported lost or revoked, its incident appears here with everything it could have opened." testId="incidents-empty" />
      ) : (
        <div className="overflow-x-auto border border-border" data-testid="incidents-list">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="label-caps">Device</TableHead>
                <TableHead className="label-caps max-md:hidden">Person</TableHead>
                <TableHead className="label-caps">Status</TableHead>
                <TableHead className="label-caps max-lg:hidden">Reported</TableHead>
                <TableHead className="label-caps max-lg:hidden">Lost at</TableHead>
                <TableHead className="label-caps text-right">Exposed</TableHead>
                <TableHead className="label-caps text-right max-sm:hidden">Held</TableHead>
                <TableHead className="label-caps text-right max-sm:hidden">Never released</TableHead>
                <TableHead className="label-caps text-right max-md:hidden">Denied</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.map((i) => (
                <TableRow key={i.id} className="h-11" data-testid={`incident-row-${i.id}`}>
                  <TableCell className="font-medium">
                    <Link to={`/app/ops/incidents/${i.id}`} className="text-primary underline-offset-2 hover:underline">
                      {i.device_name}
                    </Link>
                  </TableCell>
                  <TableCell className="max-md:hidden">{i.user_name}</TableCell>
                  <TableCell>
                    <IncidentStatusChip status={i.status} />
                  </TableCell>
                  <TableCell className="max-lg:hidden">
                    <Time value={i.reported_at} />
                  </TableCell>
                  <TableCell className="max-lg:hidden">
                    <Time value={i.compromise_time} />
                  </TableCell>
                  <TableCell className={cn('data text-right', i.counts.exposed > 0 && 'text-deny')}>{i.counts.exposed}</TableCell>
                  <TableCell className="data text-right max-sm:hidden">{i.counts.held}</TableCell>
                  <TableCell className="data text-right max-sm:hidden">{i.counts.never_released}</TableCell>
                  <TableCell className="data text-right max-md:hidden">{i.denied_attempts}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </>
  )
}
