import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, Check, MonitorX, Undo2 } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router'
import type { Alert, AlertResponse, Device } from '@/client/types'
import { Chip, DecisionChip, SeverityChip } from '@/components/qg/chips'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Time } from '@/components/qg/ident'
import { EmptyState, PageHeader, RowsSkeleton } from '@/components/qg/page'
import { useToast } from '@/components/qg/toast'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { actionWords } from '@/lib/format'
import { useDocumentTitle, useOnline } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { qk, useClient, useMe } from '../client-context'
import { useNames } from '../names'
import { RESPONSE_PHRASE } from './parts/labels'
import { RevokeDialog } from './parts/RevokeDialog'
import { Segmented } from './parts/Segmented'

type Filter = 'open' | 'acknowledged' | 'all'

function ResponseText({ response }: { response: AlertResponse | null }) {
  if (!response) return <span className="text-muted-foreground">None</span>
  return (
    <span>
      {RESPONSE_PHRASE[response.action]}
      {response.lifted_at ? (
        <span className="text-muted-foreground">, lifted</span>
      ) : response.expires_at ? (
        <span className="text-muted-foreground">
          , until <Time value={response.expires_at} />
        </span>
      ) : null}
    </span>
  )
}

function LiftDialog({ response, onClose }: { response: AlertResponse; onClose: () => void }) {
  const client = useClient()
  const qc = useQueryClient()
  const toast = useToast()
  const online = useOnline()
  const [reason, setReason] = useState('')
  const lift = useMutation({
    mutationFn: () => client.liftResponse(response.id, reason.trim()),
    onSuccess: () => {
      toast({ tone: 'done', title: 'Response lifted', body: RESPONSE_PHRASE[response.action] })
      void qc.invalidateQueries()
      onClose()
    },
    onError: () => void qc.invalidateQueries(),
  })
  const canSubmit = online && !lift.isPending && reason.trim().length >= 3
  return (
    <Dialog open onOpenChange={(o) => (!o && !lift.isPending ? onClose() : null)}>
      <DialogContent className="sm:max-w-md">
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (canSubmit) lift.mutate()
          }}
        >
          <DialogHeader>
            <DialogTitle>Lift the automatic response</DialogTitle>
            <DialogDescription>{RESPONSE_PHRASE[response.action]} ends now. The alert stays on record. If the cause is still there, it may fire again.</DialogDescription>
          </DialogHeader>
          <div className="mt-4 flex flex-col gap-1.5">
            <Label htmlFor="alert-lift-reason">Reason</Label>
            <Input id="alert-lift-reason" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={200} autoFocus className="h-10" data-testid="alert-lift-reason" />
          </div>
          {lift.error ? <ErrorNotice error={lift.error} className="mt-4" onRetry={() => lift.mutate()} /> : null}
          <DialogFooter className="mt-5">
            <Button type="button" variant="outline" onClick={onClose} disabled={lift.isPending}>
              Cancel
            </Button>
            <Button type="submit" disabled={!canSubmit} data-testid="alert-lift-confirm">
              {lift.isPending ? 'Lifting…' : 'Lift response'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Flow: web/flows/respond-to-alert.md */
function AlertSheet({ id, onClose }: { id: string; onClose: () => void }) {
  const client = useClient()
  const qc = useQueryClient()
  const toast = useToast()
  const online = useOnline()
  const me = useMe()
  const names = useNames()
  const [note, setNote] = useState('')
  const [lifting, setLifting] = useState<AlertResponse | null>(null)
  const [revoking, setRevoking] = useState<Device | null>(null)
  const alert = useQuery({ queryKey: qk.alert(id), queryFn: () => client.getAlert(id) })
  const devices = useQuery({ queryKey: qk.devices('all'), queryFn: () => client.listDevices('all'), enabled: me.has('operator') })
  const ack = useMutation({
    mutationFn: () => client.ackAlert(id, note.trim() || undefined),
    onSuccess: () => {
      toast({ tone: 'done', title: 'Alert acknowledged' })
      void qc.invalidateQueries()
    },
    onError: () => void qc.invalidateQueries(),
  })
  const a = alert.data
  const isOperator = me.has('operator')
  const device = a?.subject.device_id ? devices.data?.find((d) => d.device_id === a.subject.device_id) : undefined
  const canRevoke = isOperator && !!device && device.status !== 'revoked'
  const canLift = isOperator && !!a?.response && !a.response.lifted_at
  // Nobody lifts their own containment: the server refuses it, so the button explains instead of failing.
  const containsMe =
    !!a && !!me.device && (a.subject.user_id === me.device.user_id || a.subject.device_id === me.device.device_id || a.response?.scope.id === me.device.user_id || a.response?.scope.id === me.device.device_id)
  const who = a ? [names.user(a.subject.user_id), names.device(a.subject.device_id)].filter(Boolean).join(' on ') : ''

  return (
    <>
      <Sheet open onOpenChange={(o) => !o && onClose()}>
        <SheetContent className="w-full sm:max-w-xl overflow-y-auto" data-testid="alert-sheet">
          <SheetHeader>
            <SheetTitle>{a ? a.summary : 'Alert'}</SheetTitle>
            <SheetDescription>{a ? `Rule ${a.rule_id}${who ? `, ${who}` : ''}` : 'Loading the alert.'}</SheetDescription>
          </SheetHeader>
          <div className="flex flex-col gap-5 px-4 pb-6">
            {alert.isPending ? <RowsSkeleton rows={4} /> : null}
            {alert.error ? <ErrorNotice error={alert.error} onRetry={() => void alert.refetch()} /> : null}
            {a ? (
              <>
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityChip severity={a.severity} />
                  {a.status === 'acknowledged' ? <Chip tone="neutral" icon={Check}>Acknowledged</Chip> : <Chip tone="caution">Open</Chip>}
                  <Time value={a.ts} className="text-sm text-muted-foreground" />
                </div>
                <section data-testid="alert-why">
                  <h3 className="label-caps">Why this fired</h3>
                  <p className="mt-1">{a.explanation.condition}</p>
                </section>
                {a.rule_id === 'QG-R007' && a.path && a.path.length > 0 ? (
                  <section data-testid="alert-path">
                    <h3 className="label-caps">New path</h3>
                    <ul className="mt-1 flex flex-col gap-1">
                      {a.path.map((p, i) => (
                        <li key={i} className="data text-[0.8125rem]">
                          {names.user(p.from) ?? p.from} -&gt; {p.relation} -&gt; {names.user(p.to) ?? p.to}
                        </li>
                      ))}
                    </ul>
                  </section>
                ) : null}
                <section data-testid="alert-evidence">
                  <h3 className="label-caps">Evidence</h3>
                  {a.receipts.length === 0 ? (
                    <p className="mt-1 text-muted-foreground">No receipts are attached.</p>
                  ) : (
                    <ul className="mt-1 divide-y divide-border border border-border">
                      {a.receipts.map((r) => (
                        <li key={r.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
                          <Time value={r.ts} className="text-muted-foreground" />
                          <span className="min-w-0 flex-1">{actionWords(r.action)}</span>
                          <DecisionChip decision={r.decision} />
                          <Link to={`/app/evidence/verify?receipt=${encodeURIComponent(r.id)}`} className="inline-flex items-center gap-1 text-primary underline underline-offset-2" aria-label={`Check receipt for: ${actionWords(r.action)}`}>
                            Check
                            <ArrowRight className="size-3" aria-hidden />
                          </Link>
                        </li>
                      ))}
                    </ul>
                  )}
                </section>
                <section data-testid="alert-response">
                  <h3 className="label-caps">What was done automatically</h3>
                  {a.response ? (
                    <dl className="mt-1 border border-border">
                      <div className="flex justify-between gap-3 border-b border-border px-3 py-2">
                        <dt className="text-muted-foreground">Action</dt>
                        <dd>{RESPONSE_PHRASE[a.response.action]}</dd>
                      </div>
                      <div className="flex justify-between gap-3 border-b border-border px-3 py-2">
                        <dt className="text-muted-foreground">Applied to</dt>
                        <dd className="text-right">
                          {a.response.scope.kind}{' '}
                          <span className="font-medium">
                            {names.user(a.response.scope.id) ?? names.device(a.response.scope.id) ?? <span className="data">{a.response.scope.id}</span>}
                          </span>
                        </dd>
                      </div>
                      <div className="flex justify-between gap-3 px-3 py-2">
                        <dt className="text-muted-foreground">Ends</dt>
                        <dd>{a.response.lifted_at ? <>Lifted <Time value={a.response.lifted_at} /></> : a.response.expires_at ? <Time value={a.response.expires_at} /> : 'Until an operator lifts it'}</dd>
                      </div>
                    </dl>
                  ) : (
                    <p className="mt-1 text-muted-foreground">Nothing was done automatically.</p>
                  )}
                </section>

                {isOperator ? (
                  <section className="border-t border-rule pt-4">
                    {a.status === 'open' ? (
                      <div className="mb-3 flex flex-col gap-1.5">
                        <Label htmlFor="alert-note">Note (optional)</Label>
                        <Input id="alert-note" value={note} onChange={(e) => setNote(e.target.value)} maxLength={200} className="h-10" data-testid="alert-note" />
                      </div>
                    ) : null}
                    <div className="flex flex-wrap gap-2">
                      {a.status === 'open' ? (
                        <Button className="h-9" onClick={() => ack.mutate()} disabled={!online || ack.isPending} data-testid="alert-ack">
                          <Check aria-hidden />
                          {ack.isPending ? 'Saving…' : 'Acknowledge'}
                        </Button>
                      ) : null}
                      {canLift ? (
                        <Button variant="outline" className="h-9" onClick={() => setLifting(a.response)} disabled={!online || containsMe} data-testid="alert-lift">
                          <Undo2 aria-hidden />
                          Lift response
                        </Button>
                      ) : null}
                      {canLift && containsMe ? (
                        <p className="basis-full text-sm text-muted-foreground" data-testid="alert-self-lift-note">
                          This response contains you or this device, so someone else has to lift it.
                        </p>
                      ) : null}
                      {canRevoke ? (
                        <Button variant="danger" className="h-9" onClick={() => setRevoking(device!)} disabled={!online} data-testid="alert-revoke-device">
                          <MonitorX aria-hidden />
                          Revoke this device
                        </Button>
                      ) : null}
                    </div>
                    {ack.error ? <ErrorNotice error={ack.error} className="mt-3" /> : null}
                  </section>
                ) : null}
              </>
            ) : null}
          </div>
        </SheetContent>
      </Sheet>
      {lifting ? <LiftDialog response={lifting} onClose={() => setLifting(null)} /> : null}
      {revoking ? <RevokeDialog device={revoking} mode="revoke" open onOpenChange={(o) => !o && setRevoking(null)} /> : null}
    </>
  )
}

export default function Alerts() {
  useDocumentTitle('Alerts')
  const client = useClient()
  const names = useNames()
  const [filter, setFilter] = useState<Filter>('open')
  const [openId, setOpenId] = useState<string | null>(null)
  const status = filter === 'all' ? undefined : filter
  const alerts = useQuery({ queryKey: qk.alerts({ status }), queryFn: () => client.listAlerts({ status }), refetchInterval: 6000 })
  const list: Alert[] = [...(alerts.data ?? [])].sort((x, y) => y.ts.localeCompare(x.ts))

  // Alerts that arrive after the first load enter at the top with a short animation.
  const known = useRef<Set<string> | null>(null)
  const [fresh, setFresh] = useState<Set<string>>(new Set())
  useEffect(() => {
    if (!alerts.data) return
    if (known.current === null) {
      known.current = new Set(alerts.data.map((a) => a.id))
      return
    }
    const added = alerts.data.filter((a) => !known.current!.has(a.id)).map((a) => a.id)
    if (added.length) {
      added.forEach((i) => known.current!.add(i))
      setFresh((f) => new Set([...f, ...added]))
    }
  }, [alerts.data])

  return (
    <>
      <PageHeader title="Alerts" description="Rules watch every decision. When one fires, an automatic response may already be in place." />
      <div className="mb-3">
        <Segmented
          label="Filter by status"
          value={filter}
          onChange={(v) => {
            known.current = null
            setFresh(new Set())
            setFilter(v)
          }}
          testId="alerts-filter"
          options={[
            { value: 'open', label: 'Open' },
            { value: 'acknowledged', label: 'Acknowledged' },
            { value: 'all', label: 'All' },
          ]}
        />
      </div>
      {alerts.isPending ? (
        <RowsSkeleton rows={4} />
      ) : alerts.error ? (
        <ErrorNotice error={alerts.error} onRetry={() => void alerts.refetch()} />
      ) : list.length === 0 ? (
        <EmptyState title={filter === 'open' ? 'No open alerts' : 'No alerts'} body="When a rule fires, the alert appears here with what was done about it." testId="alerts-empty" />
      ) : (
        <div className="overflow-x-auto border border-border" data-tour="alerts-list" data-testid="alerts-list">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="label-caps">Severity</TableHead>
                <TableHead className="label-caps max-md:hidden">Rule</TableHead>
                <TableHead className="label-caps">Summary</TableHead>
                <TableHead className="label-caps max-lg:hidden">Concerns</TableHead>
                <TableHead className="label-caps max-md:hidden">Response</TableHead>
                <TableHead className="label-caps max-sm:hidden">When</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.map((a) => {
                const concerns = [names.user(a.subject.user_id), names.device(a.subject.device_id)].filter(Boolean).join(' on ')
                return (
                  <TableRow key={a.id} className={cn('h-11 cursor-pointer', fresh.has(a.id) && 'animate-enter')} onClick={() => setOpenId(a.id)} data-testid={`alert-row-${a.id}`} data-status={a.status}>
                    <TableCell>
                      <SeverityChip severity={a.severity} />
                    </TableCell>
                    <TableCell className="data max-md:hidden">{a.rule_id}</TableCell>
                    <TableCell className="max-w-[28rem] whitespace-normal">
                      <button type="button" className="text-left font-medium hover:underline focus-visible:outline-2 focus-visible:outline-ring" onClick={() => setOpenId(a.id)}>
                        {a.summary}
                      </button>
                      {a.status === 'acknowledged' ? <span className="ml-2 text-xs text-muted-foreground">Acknowledged</span> : null}
                    </TableCell>
                    <TableCell className="max-lg:hidden">{concerns || '—'}</TableCell>
                    <TableCell className="max-md:hidden">
                      <ResponseText response={a.response} />
                    </TableCell>
                    <TableCell className="max-sm:hidden">
                      <Time value={a.ts} />
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      )}
      {openId ? <AlertSheet key={openId} id={openId} onClose={() => setOpenId(null)} /> : null}
    </>
  )
}
