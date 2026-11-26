import { useQuery } from '@tanstack/react-query'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Chip } from '@/components/qg/chips'
import { Ident, Time } from '@/components/qg/ident'
import { EmptyState, PageHeader, RowsSkeleton } from '@/components/qg/page'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useDocumentTitle } from '@/lib/hooks'
import { qk, useClient } from '../client-context'

function show(v: unknown): string {
  if (Array.isArray(v)) return v.map(show).join(', ')
  if (v !== null && typeof v === 'object') return Object.entries(v).map(([k, x]) => `${k} ${show(x)}`).join('; ')
  return String(v)
}

export default function Policy() {
  useDocumentTitle('Policy')
  const client = useClient()
  const q = useQuery({ queryKey: qk.policy, queryFn: () => client.policy() })
  const p = q.data
  return (
    <>
      <PageHeader title="Policy" description="The rules that decide every request. This page is read-only." />
      {q.isPending ? (
        <RowsSkeleton rows={6} />
      ) : q.error ? (
        <ErrorNotice error={q.error} onRetry={() => void q.refetch()} />
      ) : (
        <>
          <section className="mb-6 border border-border bg-card p-4" data-testid="policy-header">
            <dl className="grid gap-x-8 gap-y-3 sm:grid-cols-[1fr_auto_auto]">
              <div className="min-w-0">
                <dt className="label-caps">Bundle hash</dt>
                <dd>
                  <Ident value={p!.bundle_hash} full label="bundle hash" />
                </dd>
              </div>
              <div>
                <dt className="label-caps">Version</dt>
                <dd className="data">{p!.version}</dd>
              </div>
              <div>
                <dt className="label-caps">Signed</dt>
                <dd>
                  <Time value={p!.signed_at} />
                </dd>
              </div>
            </dl>
            <p className="mt-3 max-w-[68ch] text-sm text-muted-foreground">
              Default is deny. A request is allowed only when a rule below says so, and every decision records the bundle hash it was made under.
            </p>
          </section>
          {p!.rules.length === 0 ? (
            <EmptyState title="No rules" body="With no rules, every request is denied." />
          ) : (
            <div className="overflow-x-auto border border-border" data-tour="policy-rules" data-testid="policy-rules">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="label-caps">Rule</TableHead>
                    <TableHead className="label-caps">Effect</TableHead>
                    <TableHead className="label-caps">What it says</TableHead>
                    <TableHead className="label-caps">Roles</TableHead>
                    <TableHead className="label-caps">Actions</TableHead>
                    <TableHead className="label-caps">Conditions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {p!.rules.map((r) => (
                    <TableRow key={r.id} className="align-top" data-testid={`policy-rule-${r.id}`}>
                      <TableCell className="data whitespace-nowrap">{r.id}</TableCell>
                      <TableCell>
                        <Chip tone={r.effect === 'allow' ? 'allow' : 'deny'}>{r.effect === 'allow' ? 'Allow' : 'Deny'}</Chip>
                      </TableCell>
                      <TableCell className="min-w-56 whitespace-normal">{r.description}</TableCell>
                      <TableCell className="whitespace-normal">{r.roles.length ? r.roles.join(', ') : 'any'}</TableCell>
                      <TableCell className="data min-w-40 text-[0.75rem] break-words whitespace-normal">{r.actions.join(' ')}</TableCell>
                      <TableCell className="data min-w-40 text-[0.75rem] whitespace-normal">
                        {Object.keys(r.conditions).length === 0 ? (
                          <span className="text-muted-foreground">none</span>
                        ) : (
                          Object.entries(r.conditions).map(([k, v]) => <div key={k}>{k}: {show(v)}</div>)
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </>
      )}
    </>
  )
}
