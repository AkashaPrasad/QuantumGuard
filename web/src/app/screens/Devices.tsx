import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Laptop, MonitorX, Pencil, Plus, RotateCw } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router'
import type { Device } from '@/client/types'
import { DeviceStatusChip } from '@/components/qg/chips'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Ident, Time } from '@/components/qg/ident'
import { EmptyState, PageHeader, RowsSkeleton } from '@/components/qg/page'
import { useToast } from '@/components/qg/toast'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { countdown } from '@/lib/format'
import { useDocumentTitle, useNow, useOnline } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { qk, useClient, useMe } from '../client-context'
import { RevokeDialog } from './parts/RevokeDialog'

/** Flow: web/flows/add-second-device.md */
function AddDeviceDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const client = useClient()
  const { device } = useMe()
  const now = useNow(1000)
  const invite = useMutation({
    mutationFn: async () => {
      const r = await client.createInvite({ user_id: device!.user_id })
      if (!('code' in r)) throw new Error('unexpected approval requirement')
      return r
    },
  })
  useEffect(() => {
    if (open) invite.mutate()
    else invite.reset()
    // Create a code each time the dialog opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])
  const left = invite.data ? new Date(invite.data.expires_at).getTime() - now : 0
  const expired = !!invite.data && left <= 0
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Add a device</DialogTitle>
          <DialogDescription>Use this one-time code on the device you want to add. Your files follow it there automatically.</DialogDescription>
        </DialogHeader>
        {invite.isPending ? <RowsSkeleton rows={2} className="mt-4" /> : null}
        {invite.error ? <ErrorNotice error={invite.error} className="mt-4" onRetry={() => invite.mutate()} /> : null}
        {invite.data ? (
          <div className="mt-4">
            <div className={cn('border border-rule bg-card p-4 text-center', expired && 'opacity-60')}>
              <p className="label-caps">Enrolment code</p>
              <div className="mt-1 flex items-center justify-center">
                <Ident value={invite.data.code} full label="enrolment code" className="[&>span:first-child]:text-2xl [&>span:first-child]:tracking-[0.12em]" />
              </div>
              <p className="data mt-2 text-sm text-muted-foreground" data-testid="invite-countdown" aria-live="off">
                {expired ? 'This code has expired.' : `Works once. Expires in ${countdown(left)}.`}
              </p>
            </div>
            {expired ? (
              <Button className="mt-3" onClick={() => invite.mutate()}>
                <RotateCw aria-hidden />
                New code
              </Button>
            ) : (
              <ol className="mt-4 flex list-decimal flex-col gap-1.5 pl-5">
                <li>On the new device, open QuantumGuard and choose Launch console.</li>
                <li>Enter this code, name the device and choose a passphrase for it.</li>
                <li>Keep this device unlocked for a minute: it shares your file keys with the new one.</li>
              </ol>
            )}
          </div>
        ) : null}
        <DialogFooter className="mt-5">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function DeviceRow({ device, onReport }: { device: Device; onReport: (d: Device) => void }) {
  const client = useClient()
  const qc = useQueryClient()
  const toast = useToast()
  const online = useOnline()
  const [editing, setEditing] = useState(false)
  const [name, setName] = useState(device.name)
  const rename = useMutation({
    mutationFn: () => client.renameDevice(device.device_id, name.trim()),
    onSuccess: () => {
      setEditing(false)
      toast({ tone: 'done', title: 'Device renamed' })
      void qc.invalidateQueries()
    },
  })
  const revoked = device.status === 'revoked'
  return (
    <li data-testid={`device-row-${device.device_id}`} data-status={device.status} className={cn('border border-border bg-card p-4', revoked && 'bg-transparent')}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <Laptop className={cn('size-5 shrink-0', revoked ? 'text-muted-foreground' : 'text-foreground')} aria-hidden />
        <div className="min-w-0 flex-1">
          {editing ? (
            <form
              className="flex gap-2"
              onSubmit={(e) => {
                e.preventDefault()
                if (name.trim().length >= 2) rename.mutate()
              }}
            >
              <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={48} aria-label="Device name" autoFocus className="h-9" data-testid="device-rename-input" />
              <Button type="submit" size="sm" className="h-9" disabled={rename.isPending || name.trim().length < 2}>
                <Check aria-hidden />
                Save
              </Button>
              <Button type="button" size="sm" variant="outline" className="h-9" onClick={() => setEditing(false)}>
                Cancel
              </Button>
            </form>
          ) : (
            <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className={cn('truncate text-base font-medium', revoked && 'text-muted-foreground line-through decoration-1')}>{device.name}</span>
              {device.is_current ? <span className="label-caps border border-primary px-1.5 py-0.5 text-primary">This device</span> : null}
              <DeviceStatusChip status={device.status} />
            </p>
          )}
          <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-sm text-muted-foreground">
            <span>
              Enrolled <Time value={device.created_at} />
            </span>
            <span>
              Last seen <Time value={device.last_seen_at} />
            </span>
            <Ident value={device.device_id} label="device id" />
          </p>
          {rename.error ? <ErrorNotice error={rename.error} className="mt-2" /> : null}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {device.open_incident_id ? (
            <Button asChild variant="outline" size="sm" className="h-9">
              <Link to={`/app/ops/incidents/${device.open_incident_id}`}>See what was affected</Link>
            </Button>
          ) : null}
          {!revoked && !editing ? (
            <Button variant="ghost" size="sm" className="h-9" onClick={() => setEditing(true)} disabled={!online} data-testid={`device-rename-${device.device_id}`}>
              <Pencil aria-hidden />
              Rename
            </Button>
          ) : null}
          {!revoked && !device.is_current ? (
            <Button
              variant="danger"
              size="sm"
              className="h-9"
              onClick={() => onReport(device)}
              data-tour="devices-report-lost"
              data-testid={`device-report-${device.device_id}`}
            >
              <MonitorX aria-hidden />
              Report lost
            </Button>
          ) : null}
        </div>
      </div>
      {device.is_current && !revoked ? (
        <p className="mt-3 border-t border-border pt-2 text-sm text-muted-foreground">
          To report this device lost, use one of your other devices or ask your operator. A device cannot revoke itself.
        </p>
      ) : null}
    </li>
  )
}

/** Flows: web/flows/report-lost-device.md, web/flows/add-second-device.md */
export default function Devices() {
  useDocumentTitle('Devices')
  const client = useClient()
  const online = useOnline()
  const [params, setParams] = useSearchParams()
  const [reporting, setReporting] = useState<Device | null>(null)
  const [adding, setAdding] = useState(false)
  const devices = useQuery({ queryKey: qk.devices('mine'), queryFn: () => client.listDevices('mine'), refetchInterval: 8000 })

  // Arriving from the command palette: go straight to the dialog when the choice is obvious.
  useEffect(() => {
    if (params.get('report') !== '1' || !devices.data) return
    const others = devices.data.filter((d) => !d.is_current && d.status !== 'revoked')
    if (others.length === 1) setReporting(others[0]!)
    params.delete('report')
    setParams(params, { replace: true })
  }, [params, setParams, devices.data])

  const list = devices.data ?? []
  const active = list.filter((d) => d.status !== 'revoked')
  const revoked = list.filter((d) => d.status === 'revoked')

  return (
    <>
      <PageHeader
        title="Devices"
        description="Each device holds its own keys. Losing one never means changing a password: you report it, and it is cut off at once."
        actions={
          <Button onClick={() => setAdding(true)} disabled={!online} data-tour="devices-add" data-testid="devices-add" className="h-9">
            <Plus aria-hidden />
            Add a device
          </Button>
        }
      />
      {devices.isPending ? (
        <RowsSkeleton rows={3} />
      ) : devices.error ? (
        <ErrorNotice error={devices.error} onRetry={() => void devices.refetch()} />
      ) : list.length === 0 ? (
        <EmptyState title="No devices yet" body="Devices you enrol appear here." testId="devices-empty" />
      ) : (
        <>
          <ul className="flex flex-col gap-2" data-tour="devices-list" data-testid="devices-list">
            {active.map((d) => (
              <DeviceRow key={d.device_id} device={d} onReport={setReporting} />
            ))}
          </ul>
          {active.length === 1 ? (
            <p className="mt-3 text-sm text-muted-foreground">
              With one device, losing it means asking your operator to revoke it. Adding a second device lets you do that yourself in two clicks.
            </p>
          ) : null}
          {revoked.length > 0 ? (
            <>
              <h2 className="label-caps mt-8 mb-2">Revoked</h2>
              <ul className="flex flex-col gap-2">
                {revoked.map((d) => (
                  <DeviceRow key={d.device_id} device={d} onReport={setReporting} />
                ))}
              </ul>
            </>
          ) : null}
        </>
      )}
      {reporting ? <RevokeDialog device={reporting} mode="report" open onOpenChange={(o) => !o && setReporting(null)} /> : null}
      <AddDeviceDialog open={adding} onOpenChange={setAdding} />
    </>
  )
}
