import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowRight, MonitorX } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import type { Device, RevokeResult } from '@/client/types'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Figure } from '@/components/qg/page'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { exactTime, toLocalInput } from '@/lib/format'
import { useOnline } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { RevokeCut } from '@/motion/RevokeCut'
import { qk, useClient } from '../../client-context'

type Preset = 'now' | 'hour' | 'morning' | 'yesterday' | 'exact'

const PRESETS: { id: Preset; label: string }[] = [
  { id: 'now', label: 'Just now' },
  { id: 'hour', label: '1 hour ago' },
  { id: 'morning', label: 'This morning' },
  { id: 'yesterday', label: 'Yesterday' },
  { id: 'exact', label: 'Exact time' },
]

function presetTime(p: Preset, exact: string): Date {
  const now = new Date()
  switch (p) {
    case 'hour':
      return new Date(now.getTime() - 3600_000)
    case 'morning': {
      const d = new Date(now)
      d.setHours(8, 0, 0, 0)
      return d < now ? d : new Date(now.getTime() - 3600_000)
    }
    case 'yesterday':
      return new Date(now.getTime() - 24 * 3600_000)
    case 'exact': {
      const d = new Date(exact)
      return Number.isNaN(d.getTime()) || d > now ? now : d
    }
    default:
      return now
  }
}

/**
 * Cut a device off. Two modes share one dialog:
 *   report  the owner, from another of their devices (web/flows/report-lost-device.md)
 *   revoke  an operator, with a reason (web/flows/revoke-device-operator.md)
 * Two clicks and a time: the button that opens this, then "Revoke access now".
 */
export function RevokeDialog({
  device,
  mode,
  open,
  onOpenChange,
  correcting = false,
}: {
  device: Device
  mode: 'report' | 'revoke'
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The device is already revoked; this call only re-scopes its incident. */
  correcting?: boolean
}) {
  const client = useClient()
  const qc = useQueryClient()
  const online = useOnline()
  const [preset, setPreset] = useState<Preset>('now')
  const [exact, setExact] = useState(() => toLocalInput(new Date()))
  const [text, setText] = useState('')
  const [result, setResult] = useState<RevokeResult | null>(null)

  useEffect(() => {
    if (open) {
      setPreset('now')
      setExact(toLocalInput(new Date()))
      setText('')
      setResult(null)
      revoke.reset()
    }
    // Reset only when the dialog opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const when = useMemo(() => presetTime(preset, exact), [preset, exact, open])
  const revoke = useMutation({
    mutationFn: () => {
      const iso = presetTime(preset, exact).toISOString()
      return mode === 'report'
        ? client.reportLost(device.device_id, { lost_at: iso, note: text.trim() || undefined })
        : client.revokeDevice(device.device_id, { compromise_time: iso, reason: text.trim() })
    },
    onSuccess: (r) => {
      setResult(r)
      void qc.invalidateQueries()
    },
  })

  // Scope is calculated just after the transaction; poll the incident until the counts are in.
  const incident = useQuery({
    queryKey: qk.incident(result?.incident_id ?? ''),
    queryFn: () => client.getIncident(result!.incident_id),
    enabled: !!result,
    refetchInterval: (q) => (q.state.data?.timeline.some((s) => s.step === 'scoped') ? false : 800),
  })
  const scoped = incident.data?.timeline.some((s) => s.step === 'scoped') ?? false
  const needsReason = mode === 'revoke'
  const canSubmit = online && !revoke.isPending && (!needsReason || text.trim().length >= 3)

  return (
    <Dialog open={open} onOpenChange={(o) => (revoke.isPending ? null : onOpenChange(o))}>
      <DialogContent className="sm:max-w-lg" data-testid="revoke-dialog">
        {result ? (
          <div data-testid={mode === 'report' ? 'report-result' : 'revoke-result'}>
            <DialogHeader>
              <DialogTitle>{correcting ? 'Scope recalculated' : `Access removed from ${device.name}`}</DialogTitle>
              <DialogDescription>
                {correcting
                  ? 'The incident now uses the corrected time. Access was already removed and stays removed.'
                  : 'It can no longer start a session or receive a key. Requests from it are refused and recorded.'}
              </DialogDescription>
            </DialogHeader>
            <div className="mt-4 flex flex-col gap-4">
              <RevokeCut deviceName={device.name} epoch={result.directory_epoch} slotsDeleted={result.slots_deleted} />
              <div className="grid grid-cols-3 gap-4">
                <Figure
                  label="Enforced in"
                  value={result.time_to_enforce_ms}
                  unit="ms"
                  tone="allow"
                  testId={mode === 'report' ? 'report-enforce-ms' : 'revoke-enforce-ms'}
                />
                <Figure label="Sessions ended" value={result.sessions_ended} />
                <Figure label="Directory epoch" value={result.directory_epoch} />
              </div>
              <div className="border border-rule bg-card p-3" aria-live="polite">
                <p className="label-caps">What it could have opened since {exactTime(incident.data?.compromise_time ?? when.toISOString())}</p>
                {scoped && incident.data ? (
                  <p className="mt-1.5" data-testid="revoke-scope">
                    <strong className={cn('data font-medium', incident.data.counts.exposed > 0 && 'text-deny')}>{incident.data.counts.exposed}</strong>{' '}
                    {incident.data.counts.exposed === 1 ? 'file was' : 'files were'} opened after that time,{' '}
                    <strong className="data font-medium">{incident.data.counts.held}</strong> had a key from before, and{' '}
                    <strong className="data font-medium">{incident.data.counts.never_released}</strong> were never released to it. The first two
                    groups are getting new keys now.
                  </p>
                ) : (
                  <p className="mt-1.5 text-muted-foreground">Working out which files are affected…</p>
                )}
              </div>
            </div>
            <DialogFooter className="mt-5">
              <Button variant="outline" onClick={() => onOpenChange(false)} data-testid="revoke-done">
                Done
              </Button>
              <Button asChild data-testid={mode === 'report' ? 'report-view-incident' : 'revoke-open-incident'}>
                <Link to={`/app/ops/incidents/${result.incident_id}`} onClick={() => onOpenChange(false)}>
                  See what was affected
                  <ArrowRight aria-hidden />
                </Link>
              </Button>
            </DialogFooter>
          </div>
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault()
              if (canSubmit) revoke.mutate()
            }}
          >
            <DialogHeader>
              <DialogTitle>
                {correcting ? `Correct the loss time for ${device.name}` : mode === 'report' ? `Report ${device.name} lost` : `Revoke ${device.name}`}
              </DialogTitle>
              <DialogDescription>
                {correcting
                  ? 'This recalculates which files count as exposed. It never restores access.'
                  : `This cuts the device off at once${mode === 'revoke' ? ` for ${device.user_name}` : ''}. It cannot be undone: a device that is found again is enrolled as a new one.`}
              </DialogDescription>
            </DialogHeader>

            <fieldset className="mt-5">
              <legend className="font-medium">{mode === 'report' ? 'When did you last have it?' : 'Compromised since'}</legend>
              <div className="mt-2 flex flex-wrap gap-1.5" role="radiogroup" aria-label="Time presets">
                {PRESETS.map((p, i) => (
                  <label
                    key={p.id}
                    className={cn(
                      'inline-flex h-9 cursor-pointer items-center border px-3 has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-ring',
                      preset === p.id ? 'border-primary bg-accent text-accent-foreground' : 'border-input hover:bg-muted',
                    )}
                  >
                    <input
                      type="radio"
                      name="revoke-preset"
                      className="sr-only"
                      value={p.id}
                      checked={preset === p.id}
                      onChange={() => setPreset(p.id)}
                      autoFocus={i === 0}
                      data-testid={`${mode === 'report' ? 'report' : 'revoke'}-preset-${p.id}`}
                    />
                    {p.label}
                  </label>
                ))}
              </div>
              {preset === 'exact' ? (
                <div className="mt-3 flex flex-col gap-1.5">
                  <Label htmlFor="revoke-time">Date and time (your local time)</Label>
                  <Input
                    id="revoke-time"
                    type="datetime-local"
                    value={exact}
                    max={toLocalInput(new Date())}
                    onChange={(e) => setExact(e.target.value)}
                    className="h-10 w-fit"
                    data-testid={mode === 'report' ? 'report-time' : 'revoke-time'}
                  />
                </div>
              ) : null}
              <p className="mt-2 text-sm text-muted-foreground">
                Recorded as <span className="data text-foreground">{exactTime(when.toISOString())}</span>. Files it opened after this time are
                treated as exposed. If you are unsure, choose the earlier time.
              </p>
            </fieldset>

            <div className="mt-4 flex flex-col gap-1.5">
              <Label htmlFor="revoke-text">{needsReason ? 'Reason' : 'Note for your operator (optional)'}</Label>
              <Input
                id="revoke-text"
                value={text}
                onChange={(e) => setText(e.target.value)}
                maxLength={200}
                className="h-10"
                placeholder={needsReason ? 'For example: reported stolen by phone' : 'For example: left in a taxi'}
                data-testid={mode === 'report' ? 'report-note' : 'revoke-reason'}
              />
            </div>

            {revoke.error ? <ErrorNotice error={revoke.error} className="mt-4" onRetry={() => revoke.mutate()} /> : null}
            {!online ? (
              <p className="mt-4 border-l-2 border-caution pl-3 text-sm">
                You are offline, so this cannot be sent. If you can reach your operator another way, ask them to revoke the device now.
              </p>
            ) : null}

            <DialogFooter className="mt-5">
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={revoke.isPending} data-testid={mode === 'report' ? 'report-cancel' : 'revoke-cancel'}>
                Cancel
              </Button>
              <Button type="submit" variant="danger" disabled={!canSubmit} data-testid={mode === 'report' ? 'report-confirm' : 'revoke-confirm'}>
                <MonitorX aria-hidden />
                {revoke.isPending ? 'Revoking…' : correcting ? 'Recalculate scope' : 'Revoke access now'}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}
