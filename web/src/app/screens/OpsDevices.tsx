import { useQuery } from '@tanstack/react-query'
import { MonitorX, Search } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import type { Device } from '@/client/types'
import { DeviceStatusChip } from '@/components/qg/chips'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Time } from '@/components/qg/ident'
import { EmptyState, PageHeader, RowsSkeleton } from '@/components/qg/page'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useDocumentTitle, useOnline } from '@/lib/hooks'
import { qk, useClient, useMe } from '../client-context'
import { RevokeDialog } from './parts/RevokeDialog'
import { Segmented } from './parts/Segmented'

type Filter = 'all' | 'active' | 'revoked' | 'quarantined'

/** Flow: web/flows/revoke-device-operator.md */
export default function OpsDevices() {
  useDocumentTitle('All devices')
  const client = useClient()
  const online = useOnline()
  const me = useMe()
  const [q, setQ] = useState('')
  const [status, setStatus] = useState<Filter>('all')
  const [revoking, setRevoking] = useState<Device | null>(null)
  const devices = useQuery({ queryKey: qk.devices('all'), queryFn: () => client.listDevices('all'), refetchInterval: 8000 })
  const canRevoke = me.has('operator')

  const list = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return (devices.data ?? []).filter(
      (d) => (status === 'all' || d.status === status) && (!needle || d.name.toLowerCase().includes(needle) || d.user_name.toLowerCase().includes(needle)),
    )
  }, [devices.data, q, status])

  return (
    <>
      <PageHeader title="All devices" description="Every enrolled device in the organisation. Revoking one cuts it off at once and opens an incident." />
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Person or device name" aria-label="Filter by person or device name" className="h-9 pl-8" data-testid="ops-devices-filter" />
        </div>
        <Segmented
          label="Filter by status"
          value={status}
          onChange={setStatus}
          options={[
            { value: 'all', label: 'All' },
            { value: 'active', label: 'Active' },
            { value: 'revoked', label: 'Revoked' },
            { value: 'quarantined', label: 'Paused' },
          ]}
        />
      </div>
      {devices.isPending ? (
        <RowsSkeleton rows={6} />
      ) : devices.error ? (
        <ErrorNotice error={devices.error} onRetry={() => void devices.refetch()} />
      ) : (devices.data ?? []).length === 0 ? (
        <EmptyState title="No devices yet" body="Devices appear here once people enrol them." testId="ops-devices-empty" />
      ) : list.length === 0 ? (
        <EmptyState title="No devices match" body="Change the filter to see more." testId="ops-devices-nomatch" />
      ) : (
        <div className="overflow-x-auto border border-border" data-tour="ops-devices" data-testid="ops-devices">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="label-caps">Device</TableHead>
                <TableHead className="label-caps">Person</TableHead>
                <TableHead className="label-caps">Status</TableHead>
                <TableHead className="label-caps max-md:hidden">Enrolled</TableHead>
                <TableHead className="label-caps max-sm:hidden">Last seen</TableHead>
                <TableHead className="w-28">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.map((d) => (
                <TableRow key={d.device_id} className="h-11" data-testid={`ops-device-row-${d.device_id}`} data-status={d.status}>
                  <TableCell className="font-medium">{d.name}</TableCell>
                  <TableCell>{d.user_name}</TableCell>
                  <TableCell>
                    <DeviceStatusChip status={d.status} />
                  </TableCell>
                  <TableCell className="max-md:hidden">
                    <Time value={d.created_at} />
                  </TableCell>
                  <TableCell className="max-sm:hidden">
                    <Time value={d.last_seen_at} />
                  </TableCell>
                  <TableCell className="text-right">
                    {d.status !== 'revoked' && canRevoke ? (
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => setRevoking(d)}
                        disabled={!online}
                        aria-label={`Revoke ${d.name}`}
                        data-testid={`ops-device-revoke-${d.device_id}`}
                      >
                        <MonitorX aria-hidden />
                        Revoke
                      </Button>
                    ) : null}
                    {d.status === 'revoked' && d.open_incident_id ? (
                      <Link to={`/app/ops/incidents/${d.open_incident_id}`} className="text-primary underline underline-offset-2">
                        Incident
                      </Link>
                    ) : null}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {revoking ? <RevokeDialog device={revoking} mode="revoke" open onOpenChange={(o) => !o && setRevoking(null)} /> : null}
    </>
  )
}
