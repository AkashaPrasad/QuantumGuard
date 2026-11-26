import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Copy, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import type { Change } from '@/client/types'
import { Chip } from '@/components/qg/chips'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Time } from '@/components/qg/ident'
import { EmptyState, PageHeader, RowsSkeleton } from '@/components/qg/page'
import { useToast } from '@/components/qg/toast'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { exactTime } from '@/lib/format'
import { useDocumentTitle, useOnline } from '@/lib/hooks'
import { qk, useClient, useMe } from '../client-context'
import { useNames } from '../names'
import { changeSentence } from './parts/labels'
import { Segmented } from './parts/Segmented'

type Filter = 'pending' | 'applied' | 'rejected' | 'all'

function StatusChip({ status }: { status: Change['status'] }) {
  if (status === 'applied') return <Chip tone="allow" icon={Check}>Applied</Chip>
  if (status === 'rejected') return <Chip tone="deny" icon={X}>Rejected</Chip>
  return <Chip tone="caution">Pending</Chip>
}

function CommandBlock({ command }: { command: string }) {
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (!copied) return
    const t = setTimeout(() => setCopied(false), 1600)
    return () => clearTimeout(t)
  }, [copied])
  return (
    <div className="border border-rule bg-card p-3">
      <div className="flex items-start gap-2">
        <code className="data min-w-0 flex-1 text-[0.8125rem] break-all" data-testid="recovery-command">
          {command}
        </code>
        <button
          type="button"
          onClick={() => void navigator.clipboard?.writeText(command).then(() => setCopied(true))}
          className="inline-flex size-8 shrink-0 items-center justify-center text-muted-foreground hover:bg-muted hover:text-foreground"
          aria-label={copied ? 'Copied recovery command' : 'Copy recovery command'}
        >
          {copied ? <Check className="size-4 text-allow" aria-hidden /> : <Copy className="size-4" aria-hidden />}
        </button>
      </div>
      <p className="mt-2 text-sm text-muted-foreground">Run this on a trusted machine, with the recovery kit. The console never asks for the kit.</p>
    </div>
  )
}

function ChangeSheet({ change, title, onClose }: { change: Change; title: string; onClose: () => void }) {
  const client = useClient()
  const qc = useQueryClient()
  const toast = useToast()
  const online = useOnline()
  const me = useMe()
  const names = useNames()
  const [rejecting, setRejecting] = useState(false)
  const [reason, setReason] = useState('')
  const isAdmin = me.has('admin')
  const myId = me.device?.user_id
  const isSelf = !!myId && (change.requested_by.user_id === myId || change.target_user.user_id === myId)
  const alreadyApproved = !!myId && change.approvals.some((a) => a.user_id === myId)
  const pending = change.status === 'pending'

  const approve = useMutation({
    mutationFn: () => client.approveChange(change.id),
    onSuccess: (c) => {
      toast({ tone: 'done', title: c.status === 'applied' ? 'Change applied' : 'Approval recorded', body: title })
      void qc.invalidateQueries()
    },
    onError: () => void qc.invalidateQueries(),
  })
  const reject = useMutation({
    mutationFn: () => client.rejectChange(change.id, reason.trim()),
    onSuccess: () => {
      toast({ tone: 'done', title: 'Change rejected', body: title })
      setRejecting(false)
      setReason('')
      void qc.invalidateQueries()
    },
    onError: () => void qc.invalidateQueries(),
  })

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="w-full sm:max-w-xl overflow-y-auto" data-testid="change-sheet">
        <SheetHeader>
          <SheetTitle>{title}</SheetTitle>
          <SheetDescription>
            Requested by {change.requested_by.name}, <Time value={change.requested_at} />.
          </SheetDescription>
        </SheetHeader>
        <div className="flex flex-col gap-5 px-4 pb-6">
          <div className="flex items-center gap-2">
            <StatusChip status={change.status} />
            <span className="data text-sm">
              {change.approvals.length} of {change.approvals_required} approvals
            </span>
          </div>
          <section>
            <h3 className="label-caps">Reason</h3>
            <p className="mt-1">{change.reason}</p>
          </section>
          <section>
            <h3 className="label-caps">Requested by</h3>
            <p className="mt-1">
              {change.requested_by.name}
              <span className="text-muted-foreground"> on {names.device(change.requested_by.device_id) ?? 'a device'}</span>
            </p>
          </section>
          <section>
            <h3 className="label-caps">Approvals</h3>
            {change.approvals.length === 0 ? (
              <p className="mt-1 text-muted-foreground">None yet.</p>
            ) : (
              <ul className="mt-1 flex flex-col divide-y divide-border border border-border">
                {change.approvals.map((a) => (
                  <li key={`${a.user_id}-${a.at}`} className="flex items-center justify-between gap-3 px-3 py-2">
                    <span>
                      {a.name}
                      <span className="text-muted-foreground"> on {names.device(a.device_id) ?? 'a device'}</span>
                    </span>
                    <time dateTime={a.at} className="data text-[0.8125rem] whitespace-nowrap" title={exactTime(a.at)}>
                      {exactTime(a.at)}
                    </time>
                  </li>
                ))}
              </ul>
            )}
          </section>

          {change.type === 'recovery_release' && change.status === 'applied' && change.file_id ? (
            <section>
              <h3 className="label-caps">Run the recovery</h3>
              <div className="mt-1">
                <CommandBlock command={`qg recover ${change.file_id} --change ${change.id} --kit <path>`} />
              </div>
            </section>
          ) : null}

          {isAdmin && pending ? (
            <section className="border-t border-rule pt-4">
              {isSelf ? (
                <p className="mb-3 border-l-2 border-caution pl-3 text-sm" data-testid="change-self-note">
                  A different admin must approve this.
                </p>
              ) : alreadyApproved ? (
                <p className="mb-3 border-l-2 border-rule pl-3 text-sm">You have already approved this.</p>
              ) : null}
              {rejecting ? (
                <form
                  className="flex flex-col gap-1.5"
                  onSubmit={(e) => {
                    e.preventDefault()
                    if (online && reason.trim().length >= 3) reject.mutate()
                  }}
                >
                  <Label htmlFor="change-reject-reason">Reason for rejecting</Label>
                  <Textarea id="change-reject-reason" value={reason} onChange={(e) => setReason(e.target.value)} rows={2} maxLength={300} autoFocus />
                  <div className="mt-2 flex gap-2">
                    <Button type="button" variant="outline" className="h-9" onClick={() => setRejecting(false)} disabled={reject.isPending}>
                      Cancel
                    </Button>
                    <Button type="submit" variant="danger" className="h-9" disabled={!online || reject.isPending || reason.trim().length < 3} data-testid="change-reject-confirm">
                      {reject.isPending ? 'Rejecting…' : 'Reject request'}
                    </Button>
                  </div>
                </form>
              ) : (
                <div className="flex flex-wrap gap-2">
                  <Button className="h-9" onClick={() => approve.mutate()} disabled={!online || isSelf || alreadyApproved || approve.isPending} data-testid="change-approve">
                    <Check aria-hidden />
                    {approve.isPending ? 'Approving…' : 'Approve'}
                  </Button>
                  <Button variant="outline" className="h-9" onClick={() => setRejecting(true)} disabled={!online} data-testid="change-reject">
                    <X aria-hidden />
                    Reject
                  </Button>
                </div>
              )}
              {approve.error ? <ErrorNotice error={approve.error} className="mt-3" /> : null}
              {reject.error ? <ErrorNotice error={reject.error} className="mt-3" /> : null}
            </section>
          ) : null}
        </div>
      </SheetContent>
    </Sheet>
  )
}

/** Flows: web/flows/role-change-and-approval.md, web/flows/recovery.md */
export default function Changes() {
  useDocumentTitle('Change requests')
  const client = useClient()
  const [filter, setFilter] = useState<Filter>('pending')
  const [openId, setOpenId] = useState<string | null>(null)
  const status = filter === 'all' ? undefined : filter
  const changes = useQuery({ queryKey: qk.changes(status), queryFn: () => client.listChanges(status), refetchInterval: 8000 })
  const all = useQuery({ queryKey: qk.changes(undefined), queryFn: () => client.listChanges(), enabled: !!openId })
  const files = useQuery({ queryKey: qk.files(), queryFn: () => client.listFiles(), retry: false })
  const fileName = (id: string) => files.data?.find((f) => f.file_id === id)?.name ?? null
  const sentence = (c: Change) => changeSentence(c, fileName)
  const opened = openId ? (all.data ?? changes.data ?? []).find((c) => c.id === openId) : undefined
  const list = changes.data ?? []

  return (
    <>
      <PageHeader title="Change requests" description="Sensitive changes need a second person. Each request shows who asked, why, and who has agreed." />
      <div className="mb-3">
        <Segmented
          label="Filter by status"
          value={filter}
          onChange={setFilter}
          testId="changes-filter"
          options={[
            { value: 'pending', label: 'Pending' },
            { value: 'applied', label: 'Applied' },
            { value: 'rejected', label: 'Rejected' },
            { value: 'all', label: 'All' },
          ]}
        />
      </div>
      {changes.isPending ? (
        <RowsSkeleton rows={4} />
      ) : changes.error ? (
        <ErrorNotice error={changes.error} onRetry={() => void changes.refetch()} />
      ) : list.length === 0 ? (
        <EmptyState
          title="No change requests"
          body={filter === 'pending' ? 'Nothing is waiting for approval.' : 'Requests with this status appear here.'}
          testId="changes-empty"
        />
      ) : (
        <div className="overflow-x-auto border border-border" data-tour="changes-list" data-testid="changes-list">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="label-caps">Change</TableHead>
                <TableHead className="label-caps max-md:hidden">Requested by</TableHead>
                <TableHead className="label-caps max-sm:hidden">When</TableHead>
                <TableHead className="label-caps">Approvals</TableHead>
                <TableHead className="label-caps">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.map((c) => (
                <TableRow key={c.id} className="h-11 cursor-pointer" onClick={() => setOpenId(c.id)} data-testid={`change-row-${c.id}`}>
                  <TableCell className="font-medium">
                    <button type="button" className="text-left hover:underline focus-visible:outline-2 focus-visible:outline-ring" onClick={() => setOpenId(c.id)}>
                      {sentence(c)}
                    </button>
                  </TableCell>
                  <TableCell className="max-md:hidden">{c.requested_by.name}</TableCell>
                  <TableCell className="max-sm:hidden">
                    <Time value={c.requested_at} />
                  </TableCell>
                  <TableCell className="data">
                    {c.approvals.length} of {c.approvals_required}
                  </TableCell>
                  <TableCell>
                    <StatusChip status={c.status} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      {opened ? <ChangeSheet key={opened.id} change={opened} title={sentence(opened)} onClose={() => setOpenId(null)} /> : null}
    </>
  )
}
