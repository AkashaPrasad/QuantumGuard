import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Ban, Check, ClockAlert, FileDown, Flag, KeyRound, ListChecks, ScanSearch, ShieldCheck, ShieldOff } from 'lucide-react'
import { useState } from 'react'
import type { ComponentType } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import type { Device, ExposedFile, Incident, ProofBundle, TimelineStep } from '@/client/types'
import { ClassificationChip, Chip, DecisionChip, IncidentStatusChip } from '@/components/qg/chips'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Ident, Time } from '@/components/qg/ident'
import { Figure, PageHeader, RowsSkeleton } from '@/components/qg/page'
import { useToast } from '@/components/qg/toast'
import { Button } from '@/components/ui/button'
import { saveJson } from '@/lib/download'
import { actionWords, exactTime, plural } from '@/lib/format'
import { useDocumentTitle, useOnline } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { qk, useClient, useMe } from '../client-context'
import { useNames } from '../names'
import { RevokeDialog } from './parts/RevokeDialog'

const STEP: Record<TimelineStep, { label: string; icon: ComponentType<{ className?: string }>; tone: 'deny' | 'allow' | 'caution' | 'plain' }> = {
  reported: { label: 'Reported lost', icon: Flag, tone: 'plain' },
  revoked: { label: 'Access revoked', icon: ShieldOff, tone: 'deny' },
  scoped: { label: 'Scope calculated', icon: ScanSearch, tone: 'plain' },
  rekey_started: { label: 'New keys started', icon: KeyRound, tone: 'caution' },
  rekey_progress: { label: 'New key issued', icon: KeyRound, tone: 'plain' },
  rekey_done: { label: 'New keys finished', icon: ListChecks, tone: 'allow' },
  denied_attempt: { label: 'Attempt from the device denied', icon: Ban, tone: 'deny' },
  rescoped: { label: 'Scope recalculated', icon: ClockAlert, tone: 'caution' },
  bundle_exported: { label: 'Proof exported', icon: FileDown, tone: 'plain' },
  closed: { label: 'Closed', icon: Check, tone: 'allow' },
}

type Group = 'exposed' | 'held' | 'never_released' | 'suspect'

const GROUP_HELP: Record<Group, string> = {
  exposed: 'A key for these was released to the device at or after the loss time. Assume they were read.',
  held: 'The device received a key for these before the loss time. They are re-keyed so a copy of the old key is useless for future versions.',
  never_released: 'The device was allowed to open these but never asked. No key left the server.',
  suspect: 'Decisions made for this device after the loss time. Each one should be treated as made for whoever held the device.',
}

function Timeline({ incident }: { incident: Incident }) {
  return (
    <ol className="relative before:absolute before:top-2 before:bottom-2 before:left-[0.72rem] before:w-px before:bg-rule" data-tour="incident-timeline" data-testid="incident-timeline">
      {incident.timeline.map((e, i) => {
        const s = STEP[e.step]
        return (
          <li key={`${e.step}-${e.ts}-${i}`} data-testid={`incident-step-${e.step}`} className="animate-enter relative flex gap-3 pb-4 last:pb-0">
            <span
              className={cn(
                'z-10 flex size-6 shrink-0 items-center justify-center border bg-background',
                s.tone === 'deny' && 'border-deny text-deny',
                s.tone === 'allow' && 'border-allow text-allow',
                s.tone === 'caution' && 'border-caution text-caution',
                s.tone === 'plain' && 'border-rule text-muted-foreground',
              )}
              aria-hidden
            >
              <s.icon className="size-3.5" />
            </span>
            <div className="min-w-0 flex-1">
              <p className="font-medium">{s.label}</p>
              {e.detail ? <p className="text-sm text-muted-foreground">{e.detail}</p> : null}
              <p className="data mt-0.5 flex flex-wrap items-center gap-x-3 text-[0.75rem] text-muted-foreground">
                <span>{exactTime(e.ts)}</span>
                {e.receipt_id ? (
                  <Link className="text-primary underline underline-offset-2" to={`/app/evidence/verify?receipt=${e.receipt_id}`}>
                    receipt
                  </Link>
                ) : null}
              </p>
            </div>
          </li>
        )
      })}
    </ol>
  )
}

function FileRows({ files }: { files: ExposedFile[] }) {
  if (files.length === 0) return <p className="border border-dashed border-rule p-4 text-muted-foreground">Nothing in this group.</p>
  return (
    <ul className="border border-border">
      {files.map((f) => (
        <li key={f.file_id} data-testid={`incident-file-${f.file_id}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-border px-3 py-2 last:border-b-0">
          <div className="min-w-0 flex-1 basis-56">
            <p className="truncate font-medium">{f.name}</p>
            <p className="text-sm text-muted-foreground">
              {f.releases.length === 0 ? (
                'Never released to this device'
              ) : (
                <>
                  {plural(f.releases.length, 'release')}, last <Time value={f.releases[f.releases.length - 1]!.ts} />
                </>
              )}
            </p>
          </div>
          <ClassificationChip value={f.classification} />
          {f.rekey === 'done' ? (
            <Chip tone="allow" icon={Check}>
              New key{f.new_version ? ` · v${f.new_version}` : ''}
            </Chip>
          ) : f.rekey === 'pending' ? (
            <Chip tone="caution" icon={KeyRound}>
              New key pending
            </Chip>
          ) : (
            <Chip tone="neutral">No new key needed</Chip>
          )}
        </li>
      ))}
    </ul>
  )
}

/** Flow: web/flows/incident-review.md */
export default function IncidentDetail() {
  const { incidentId = '' } = useParams()
  const client = useClient()
  const qc = useQueryClient()
  const toast = useToast()
  const online = useOnline()
  const navigate = useNavigate()
  const names = useNames()
  const { has } = useMe()
  const [group, setGroup] = useState<Group>('exposed')
  const [correcting, setCorrecting] = useState(false)
  const [bundle, setBundle] = useState<ProofBundle | null>(null)

  const settled = (i?: Incident) => i?.status === 'contained' || i?.status === 'closed'
  const incident = useQuery({
    queryKey: qk.incident(incidentId),
    queryFn: () => client.getIncident(incidentId),
    refetchInterval: (q) => (settled(q.state.data) ? 15_000 : 2000),
  })
  const exposure = useQuery({
    queryKey: qk.exposure(incidentId),
    queryFn: () => client.getExposure(incidentId),
    refetchInterval: () => (settled(incident.data) ? 15_000 : 2500),
  })
  useDocumentTitle(incident.data ? `Incident: ${incident.data.device_name}` : 'Incident')

  const exportBundle = useMutation({
    mutationFn: () => client.exportBundle(incidentId),
    onSuccess: (b) => {
      setBundle(b)
      saveJson(b, `quantumguard-proof-${incidentId}.json`)
      toast({ tone: 'done', title: 'Proof bundle saved', body: 'It can be verified offline, here or with the command-line tool.' })
      void qc.invalidateQueries({ queryKey: qk.incident(incidentId) })
    },
  })
  const close = useMutation({
    mutationFn: () => client.closeIncident(incidentId),
    onSuccess: () => {
      toast({ tone: 'done', title: 'Incident closed' })
      void qc.invalidateQueries()
    },
  })

  if (incident.isPending) return <RowsSkeleton rows={6} />
  if (incident.error) return <ErrorNotice error={incident.error} onRetry={() => void incident.refetch()} />
  const i = incident.data
  const operator = has('operator')
  const asDevice: Device = {
    device_id: i.device_id,
    user_id: i.user_id,
    user_name: i.user_name,
    name: i.device_name,
    status: 'revoked',
    created_at: i.reported_at,
    last_seen_at: null,
    is_current: false,
    open_incident_id: i.id,
  }
  const x = exposure.data
  const tabs: { id: Group; label: string; count: number }[] = [
    { id: 'exposed', label: 'Exposed', count: x?.exposed.length ?? i.counts.exposed },
    { id: 'held', label: 'Held', count: x?.held.length ?? i.counts.held },
    { id: 'never_released', label: 'Never released', count: x?.never_released.length ?? i.counts.never_released },
    { id: 'suspect', label: 'Suspect decisions', count: x?.suspect_decisions.length ?? 0 },
  ]

  return (
    <>
      <PageHeader
        eyebrow={
          <span className="flex flex-wrap items-center gap-2">
            Incident <Ident value={i.id} label="incident id" />
          </span>
        }
        title={`${i.device_name} · ${i.user_name}`}
        description={
          <>
            Reported <Time value={i.reported_at} /> by {i.reported_by.name}. Loss time{' '}
            <span className="data text-foreground">{exactTime(i.compromise_time)}</span>.{i.note ? ` Note: ${i.note}` : ''}
          </>
        }
        actions={
          <>
            <span data-testid="incident-status">
              <IncidentStatusChip status={i.status} />
            </span>
            {operator && i.status !== 'closed' ? (
              <Button variant="outline" className="h-9" onClick={() => setCorrecting(true)} disabled={!online} data-testid="incident-correct-time">
                <ClockAlert aria-hidden />
                Correct the loss time
              </Button>
            ) : null}
            {has('operator', 'auditor') ? (
              <Button className="h-9" onClick={() => exportBundle.mutate()} disabled={exportBundle.isPending || !online} data-tour="incident-export" data-testid="incident-export">
                <FileDown aria-hidden />
                {exportBundle.isPending ? 'Preparing…' : 'Export proof bundle'}
              </Button>
            ) : null}
          </>
        }
      />

      {exportBundle.error ? <ErrorNotice error={exportBundle.error} className="mb-4" /> : null}
      {bundle ? (
        <div className="mb-5 flex flex-wrap items-center gap-3 border border-allow/40 bg-allow-soft px-4 py-2.5">
          <ShieldCheck className="size-4 text-allow" aria-hidden />
          <p className="flex-1">The proof bundle was saved to this device. You do not have to take its word for it.</p>
          <Button variant="outline" size="sm" className="h-9" onClick={() => navigate('/app/evidence/verify', { state: { bundle } })} data-testid="incident-verify">
            Verify it here
          </Button>
        </div>
      ) : null}

      <div className="grid grid-cols-2 gap-x-4 gap-y-5 border border-rule bg-card p-4 sm:grid-cols-4" data-tour="incident-figures">
        <Figure label="Enforced in" value={i.time_to_enforce_ms} unit="ms" tone="allow" testId="incident-enforce-ms" hint="for the revocation to commit on the server" />
        <Figure label="Exposed" value={i.counts.exposed} tone={i.counts.exposed > 0 ? 'deny' : undefined} hint="opened after the loss time" />
        <Figure label="Held" value={i.counts.held} hint="key received before it" />
        <Figure label="Attempts denied" value={i.denied_attempts} tone={i.denied_attempts > 0 ? 'caution' : undefined} hint="requests from the device since" />
      </div>
      {i.counts.pending > 0 ? (
        <p className="mt-3 flex items-center gap-2 text-sm text-caution" role="status">
          <KeyRound className="size-4" aria-hidden />
          {i.counts.rekeyed} of {i.counts.rekeyed + i.counts.pending} affected files have a new key. A device that can still open them does this work; it continues
          when one is unlocked.
        </p>
      ) : null}

      <div className="mt-8 grid gap-8 lg:grid-cols-[minmax(0,22rem)_minmax(0,1fr)]">
        <section aria-labelledby="timeline-title">
          <h2 id="timeline-title" className="mb-3 text-base">
            What happened, in order
          </h2>
          <Timeline incident={i} />
        </section>

        <section aria-labelledby="exposure-title" data-tour="incident-exposure" data-testid="incident-exposure">
          <h2 id="exposure-title" className="mb-3 text-base">
            What the device could have seen
          </h2>
          <div role="tablist" aria-label="Exposure groups" className="mb-3 inline-flex flex-wrap border border-border bg-card">
            {tabs.map((t) => (
              <button
                key={t.id}
                role="tab"
                type="button"
                aria-selected={group === t.id}
                onClick={() => setGroup(t.id)}
                data-testid={`incident-tab-${t.id}`}
                className={cn(
                  'h-9 border-r border-border px-3 last:border-r-0 focus-visible:-outline-offset-2',
                  group === t.id ? 'bg-accent font-medium text-accent-foreground shadow-[inset_0_-2px_0_var(--color-primary)]' : 'text-muted-foreground hover:bg-muted hover:text-foreground',
                )}
              >
                {t.label} <span className="data ml-1 text-muted-foreground">{t.count}</span>
              </button>
            ))}
          </div>
          <p className="mb-3 text-sm text-muted-foreground">{GROUP_HELP[group]}</p>
          {exposure.isPending ? (
            <RowsSkeleton rows={3} />
          ) : exposure.error ? (
            <ErrorNotice error={exposure.error} onRetry={() => void exposure.refetch()} />
          ) : group === 'suspect' ? (
            x!.suspect_decisions.length === 0 ? (
              <p className="border border-dashed border-rule p-4 text-muted-foreground">Nothing in this group.</p>
            ) : (
              <ul className="border border-border">
                {x!.suspect_decisions.map((r) => (
                  <li key={r.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-border px-3 py-2 last:border-b-0">
                    <div className="min-w-0 flex-1 basis-56">
                      <Link className="font-medium hover:text-primary hover:underline" to={`/app/evidence/verify?receipt=${r.id}`}>
                        {actionWords(r.action)}
                      </Link>
                      <p className="truncate text-sm text-muted-foreground">
                        {r.resource} · {names.device(r.subject.device_id) ?? i.device_name}
                      </p>
                    </div>
                    <span className="data text-[0.75rem] text-muted-foreground">{exactTime(r.ts)}</span>
                    <DecisionChip decision={r.decision} />
                  </li>
                ))}
              </ul>
            )
          ) : (
            <FileRows files={x![group]} />
          )}
        </section>
      </div>

      {operator && i.status !== 'closed' ? (
        <section className="mt-10 border-t border-rule pt-5">
          <h2 className="text-base">Close the incident</h2>
          <p className="mt-1 max-w-[68ch] text-muted-foreground">
            Close it once every affected file has a new key and you have exported the proof. Closing changes nothing about access: the device stays revoked.
          </p>
          {close.error ? <ErrorNotice error={close.error} className="mt-3 max-w-xl" /> : null}
          <Button variant="outline" className="mt-3 h-9" onClick={() => close.mutate()} disabled={close.isPending || !online} data-testid="incident-close">
            <Check aria-hidden />
            {close.isPending ? 'Closing…' : 'Close incident'}
          </Button>
        </section>
      ) : null}

      {correcting ? <RevokeDialog device={asDevice} mode="revoke" correcting open onOpenChange={(o) => !o && setCorrecting(false)} /> : null}
    </>
  )
}
