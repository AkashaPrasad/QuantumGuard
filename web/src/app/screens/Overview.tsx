import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router'
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from 'recharts'
import { IncidentStatusChip, SeverityChip } from '@/components/qg/chips'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Time } from '@/components/qg/ident'
import { Figure, PageHeader, Section } from '@/components/qg/page'
import { ChartContainer, ChartLegend, ChartLegendContent, ChartTooltip, ChartTooltipContent } from '@/components/ui/chart'
import type { ChartConfig } from '@/components/ui/chart'
import { Skeleton } from '@/components/ui/skeleton'
import { useDocumentTitle } from '@/lib/hooks'
import { qk, useClient, useMe } from '../client-context'

const config = {
  allow: { label: 'Allowed', color: 'var(--chart-3)' },
  deny: { label: 'Denied', color: 'var(--chart-2)' },
} satisfies ChartConfig

function hourLabel(iso: string) {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : `${String(d.getUTCHours()).padStart(2, '0')}:00`
}

function Lists() {
  const client = useClient()
  const alerts = useQuery({ queryKey: qk.alerts({ status: 'open' }), queryFn: () => client.listAlerts({ status: 'open' }) })
  const incidents = useQuery({ queryKey: qk.incidents(), queryFn: () => client.listIncidents() })
  return (
    <div className="mt-8 grid gap-6 md:grid-cols-2">
      <Section title="Open alerts" className="mt-0">
        {alerts.isPending ? (
          <Skeleton className="h-24 w-full" />
        ) : alerts.error ? (
          <ErrorNotice error={alerts.error} onRetry={() => void alerts.refetch()} />
        ) : alerts.data.length === 0 ? (
          <p className="border border-dashed border-rule p-4 text-sm text-muted-foreground" data-testid="overview-no-alerts">No open alerts</p>
        ) : (
          <ul className="border border-border" data-testid="overview-alerts">
            {alerts.data.slice(0, 5).map((a) => (
              <li key={a.id} className="border-b border-border last:border-b-0">
                <Link to="/app/ops/alerts" className="flex min-h-11 flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 hover:bg-muted">
                  <SeverityChip severity={a.severity} />
                  <span className="min-w-0 flex-1">{a.summary}</span>
                  <Time value={a.ts} className="text-sm text-muted-foreground" />
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Section>
      <Section title="Recent incidents" className="mt-0">
        {incidents.isPending ? (
          <Skeleton className="h-24 w-full" />
        ) : incidents.error ? (
          <ErrorNotice error={incidents.error} onRetry={() => void incidents.refetch()} />
        ) : incidents.data.length === 0 ? (
          <p className="border border-dashed border-rule p-4 text-sm text-muted-foreground" data-testid="overview-no-incidents">No incidents</p>
        ) : (
          <ul className="border border-border" data-testid="overview-incidents">
            {incidents.data.slice(0, 5).map((i) => (
              <li key={i.id} className="border-b border-border last:border-b-0">
                <Link to={`/app/ops/incidents/${i.id}`} className="flex min-h-11 flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 hover:bg-muted">
                  <IncidentStatusChip status={i.status} />
                  <span className="min-w-0 flex-1">
                    {i.device_name} <span className="text-muted-foreground">({i.user_name})</span>
                  </span>
                  <Time value={i.reported_at} className="text-sm text-muted-foreground" />
                </Link>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  )
}

export default function Overview() {
  useDocumentTitle('Overview')
  const client = useClient()
  const me = useMe()
  const q = useQuery({ queryKey: qk.overview, queryFn: () => client.overview(), refetchInterval: 10000 })
  const o = q.data
  const allowed = o?.decisions_by_hour.reduce((n, h) => n + h.allow, 0) ?? 0
  const denied = o?.decisions_by_hour.reduce((n, h) => n + h.deny, 0) ?? 0
  const data = (o?.decisions_by_hour ?? []).map((h) => ({ ...h, label: hourLabel(h.hour) }))

  return (
    <>
      <PageHeader title="Overview" description="The state of the organisation right now. It refreshes every ten seconds." />
      {q.isPending ? (
        <div className="grid grid-cols-2 gap-4 border border-border p-4 lg:grid-cols-5" role="status" aria-busy="true" aria-label="Loading">
          {Array.from({ length: 5 }, (_, i) => (
            <Skeleton key={i} className="h-14" />
          ))}
        </div>
      ) : q.error ? (
        <ErrorNotice error={q.error} onRetry={() => void q.refetch()} />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-x-4 gap-y-5 border border-border bg-card p-4 lg:grid-cols-5" data-tour="overview-figures" data-testid="overview-figures">
            <Figure label="Active devices" value={o!.active_devices} testId="figure-active-devices" />
            <Figure label="Awaiting new keys" value={o!.pending_rekeys} testId="figure-pending-rekeys" />
            <Figure label="Open alerts" value={o!.open_alerts} tone={o!.open_alerts > 0 ? 'deny' : undefined} testId="figure-open-alerts" />
            <Figure label="Open incidents" value={o!.open_incidents} testId="figure-open-incidents" />
            <Figure
              label="Last time to enforce"
              value={o!.last_time_to_enforce_ms === null ? <span className="text-base font-normal text-muted-foreground">no revocation yet</span> : o!.last_time_to_enforce_ms}
              unit={o!.last_time_to_enforce_ms === null ? undefined : 'ms'}
              testId="figure-enforce-ms"
            />
          </div>

          <Section title="Decisions in the last 24 hours" className="mt-8">
            <div className="border border-border bg-card p-4">
              <ChartContainer config={config} className="aspect-auto h-60 w-full">
                <BarChart data={data} accessibilityLayer>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="label" tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={24} />
                  <YAxis tickLine={false} axisLine={false} allowDecimals={false} width={32} />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <ChartLegend content={<ChartLegendContent />} />
                  <Bar dataKey="allow" stackId="d" fill="var(--color-allow)" isAnimationActive={false} />
                  <Bar dataKey="deny" stackId="d" fill="var(--color-deny)" isAnimationActive={false} />
                </BarChart>
              </ChartContainer>
              <p className="data mt-2 text-sm text-muted-foreground" data-testid="overview-chart-summary">
                {allowed} allowed, {denied} denied
              </p>
            </div>
          </Section>

          {me.has('operator', 'auditor') ? <Lists /> : null}

          <p className="data mt-8 border-t border-rule pt-3 text-[0.8125rem] text-muted-foreground" data-testid="overview-footer">
            directory epoch {o!.directory_epoch} · log size {o!.tree_size}
          </p>
        </>
      )}
    </>
  )
}
