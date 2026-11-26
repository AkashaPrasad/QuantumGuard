import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { KeyRound, Plus, RotateCw } from 'lucide-react'
import { useEffect, useState } from 'react'
import type { Service, ServiceKey } from '@/client/types'
import { Chip } from '@/components/qg/chips'
import type { Tone } from '@/components/qg/chips'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Ident, Time } from '@/components/qg/ident'
import { EmptyState, PageHeader, RowsSkeleton } from '@/components/qg/page'
import { useToast } from '@/components/qg/toast'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useDocumentTitle, useOnline } from '@/lib/hooks'
import { qk, useClient, useMe } from '../client-context'

const KEY_TONE: Record<ServiceKey['status'], Tone> = { active: 'allow', retiring: 'caution', retired: 'neutral' }
const KEY_LABEL: Record<ServiceKey['status'], string> = { active: 'Active', retiring: 'Retiring', retired: 'Retired' }

/** Flow: web/flows/rotate-service-key.md */
function RotateDialog({ service, onClose }: { service: Service; onClose: () => void }) {
  const client = useClient()
  const qc = useQueryClient()
  const toast = useToast()
  const online = useOnline()
  const me = useMe()
  const isOperator = me.has('operator')
  const [reason, setReason] = useState('')
  const [emergency, setEmergency] = useState(isOperator)
  const active = service.keys.find((k) => k.status === 'active')
  const rotate = useMutation({
    mutationFn: () => client.rotateService(service.service_id, { reason: reason.trim(), emergency: isOperator && emergency }),
    onSuccess: () => {
      toast({ tone: 'done', title: `Key rotated for ${service.name}`, body: isOperator && emergency ? 'The old key is retired.' : 'The old key is retiring.' })
      void qc.invalidateQueries()
      onClose()
    },
  })
  const canSubmit = online && !rotate.isPending && reason.trim().length >= 3
  return (
    <Dialog open onOpenChange={(o) => (!o && !rotate.isPending ? onClose() : null)}>
      <DialogContent className="sm:max-w-lg">
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (canSubmit) rotate.mutate()
          }}
        >
          <DialogHeader>
            <DialogTitle>Rotate the key for {service.name}</DialogTitle>
            <DialogDescription>
              A new signing key becomes active at once. {isOperator && emergency ? 'The old key stops working immediately.' : 'The old key stays valid for a short overlap, then retires.'}
            </DialogDescription>
          </DialogHeader>
          <p className="mt-4 flex flex-wrap items-center gap-x-2 text-sm">
            <span className="text-muted-foreground">Current key</span>
            <Ident value={active?.key_id} label="key id" />
          </p>
          <div className="mt-4 flex flex-col gap-1.5">
            <Label htmlFor="rotate-reason">Reason</Label>
            <Input id="rotate-reason" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={200} autoFocus className="h-10" placeholder="For example: scheduled quarterly rotation" data-testid="rotate-reason" />
          </div>
          {isOperator ? (
            <div className="mt-4 flex items-start gap-3 border border-border p-3">
              <Switch id="rotate-emergency" checked={emergency} onCheckedChange={setEmergency} data-testid="rotate-emergency" />
              <div>
                <Label htmlFor="rotate-emergency">Emergency: retire the old key immediately</Label>
                <p className="mt-0.5 text-sm text-muted-foreground">Use this when the old key may have leaked. Anything still signed with it is refused and raises an alert.</p>
              </div>
            </div>
          ) : null}
          {rotate.error ? <ErrorNotice error={rotate.error} className="mt-4" onRetry={() => rotate.mutate()} /> : null}
          {!online ? <p className="mt-4 border-l-2 border-caution pl-3 text-sm">You are offline. Nothing is sent until the connection returns.</p> : null}
          <DialogFooter className="mt-5">
            <Button type="button" variant="outline" onClick={onClose} disabled={rotate.isPending}>
              Cancel
            </Button>
            <Button type="submit" variant={isOperator && emergency ? 'danger' : 'default'} disabled={!canSubmit} data-testid="rotate-submit">
              <RotateCw aria-hidden />
              {rotate.isPending ? 'Rotating…' : 'Rotate'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function AddServiceDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const client = useClient()
  const qc = useQueryClient()
  const toast = useToast()
  const online = useOnline()
  const [name, setName] = useState('')
  const add = useMutation({
    mutationFn: () => client.createService(name.trim()),
    onSuccess: (s) => {
      toast({ tone: 'done', title: 'Service added', body: s.name })
      void qc.invalidateQueries()
      onOpenChange(false)
    },
  })
  useEffect(() => {
    if (open) {
      setName('')
      add.reset()
    }
    // Reset only when the dialog opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])
  const canSubmit = online && !add.isPending && name.trim().length >= 2
  return (
    <Dialog open={open} onOpenChange={(o) => (add.isPending ? null : onOpenChange(o))}>
      <DialogContent className="sm:max-w-md">
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (canSubmit) add.mutate()
          }}
        >
          <DialogHeader>
            <DialogTitle>Add a service</DialogTitle>
            <DialogDescription>The service gets its first signing key at once.</DialogDescription>
          </DialogHeader>
          <div className="mt-4 flex flex-col gap-1.5">
            <Label htmlFor="service-name">Name</Label>
            <Input id="service-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={48} autoFocus className="h-10" data-testid="service-name" />
          </div>
          {add.error ? <ErrorNotice error={add.error} className="mt-4" onRetry={() => add.mutate()} /> : null}
          <DialogFooter className="mt-5">
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={add.isPending}>
              Cancel
            </Button>
            <Button type="submit" disabled={!canSubmit} data-testid="service-add-submit">
              {add.isPending ? 'Adding…' : 'Add service'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function ServiceBlock({ service, canRotate, onRotate }: { service: Service; canRotate: boolean; onRotate: (s: Service) => void }) {
  const online = useOnline()
  return (
    <li className="border border-border bg-card" data-testid={`service-row-${service.service_id}`}>
      <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-3">
        <KeyRound className="size-4 text-muted-foreground" aria-hidden />
        <h2 className="text-base">{service.name}</h2>
        <Chip tone={service.status === 'active' ? 'allow' : 'neutral'}>{service.status}</Chip>
        {canRotate ? (
          <Button variant="outline" className="ml-auto h-9" onClick={() => onRotate(service)} disabled={!online} data-testid={`service-rotate-${service.service_id}`}>
            <RotateCw aria-hidden />
            Rotate key
          </Button>
        ) : null}
      </div>
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="label-caps">Key</TableHead>
              <TableHead className="label-caps max-sm:hidden">Algorithm</TableHead>
              <TableHead className="label-caps">Status</TableHead>
              <TableHead className="label-caps max-md:hidden">Created</TableHead>
              <TableHead className="label-caps max-md:hidden">Retired</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {service.keys.map((k) => (
              <TableRow key={k.key_id} className="h-11" data-testid={`service-key-${k.key_id}`}>
                <TableCell>
                  <Ident value={k.key_id} label="key id" />
                </TableCell>
                <TableCell className="data max-sm:hidden">{k.alg}</TableCell>
                <TableCell>
                  <Chip tone={KEY_TONE[k.status]}>{KEY_LABEL[k.status]}</Chip>
                </TableCell>
                <TableCell className="max-md:hidden">
                  <Time value={k.created_at} />
                </TableCell>
                <TableCell className="max-md:hidden">
                  <Time value={k.retired_at} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </li>
  )
}

export default function Services() {
  useDocumentTitle('Services')
  const client = useClient()
  const online = useOnline()
  const me = useMe()
  const [rotatingId, setRotatingId] = useState<string | null>(null)
  const [adding, setAdding] = useState(false)
  const services = useQuery({ queryKey: qk.services, queryFn: () => client.listServices() })
  const keySet = useQuery({ queryKey: qk.keySet, queryFn: () => client.keySet() })
  const canRotate = me.has('admin', 'operator')
  const list = services.data ?? []
  const rotating = list.find((s) => s.service_id === rotatingId)
  const addButton = (
    <Button onClick={() => setAdding(true)} disabled={!online} data-testid="service-add" className="h-9">
      <Plus aria-hidden />
      Add a service
    </Button>
  )

  return (
    <>
      <PageHeader
        title="Services"
        description={
          <>
            Services sign what they issue with keys listed here.
            {keySet.data ? (
              <>
                {' '}
                Key set epoch <span className="data text-foreground">{keySet.data.epoch}</span>.
              </>
            ) : null}
          </>
        }
        actions={me.has('admin') ? addButton : undefined}
      />
      {services.isPending ? (
        <RowsSkeleton rows={3} />
      ) : services.error ? (
        <ErrorNotice error={services.error} onRetry={() => void services.refetch()} />
      ) : list.length === 0 ? (
        <EmptyState
          title="No services yet"
          body="Services that sign keys for this organisation appear here."
          testId="services-empty"
          action={me.has('admin') ? addButton : undefined}
        />
      ) : (
        <ul className="flex flex-col gap-4" data-tour="services-list" data-testid="services-list">
          {list.map((s) => (
            <ServiceBlock key={s.service_id} service={s} canRotate={canRotate} onRotate={(x) => setRotatingId(x.service_id)} />
          ))}
        </ul>
      )}
      {rotating ? <RotateDialog service={rotating} onClose={() => setRotatingId(null)} /> : null}
      <AddServiceDialog open={adding} onOpenChange={setAdding} />
    </>
  )
}
