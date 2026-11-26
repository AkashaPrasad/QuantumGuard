import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, Copy, MoreHorizontal, Plus, UserPlus } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import type { DirectoryUser, Invite, Role } from '@/client/types'
import { Chip } from '@/components/qg/chips'
import type { Tone } from '@/components/qg/chips'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Time } from '@/components/qg/ident'
import { EmptyState, PageHeader, RowsSkeleton, Section } from '@/components/qg/page'
import { useToast } from '@/components/qg/toast'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { NativeSelect } from '@/components/qg/native-select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { countdown } from '@/lib/format'
import { useDocumentTitle, useNow, useOnline } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { qk, useClient } from '../client-context'
import { ROLE_LABEL, ROLE_ORDER } from './parts/labels'

const NEEDS_APPROVAL: Role[] = ['operator', 'admin']

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (!copied) return
    const t = setTimeout(() => setCopied(false), 1600)
    return () => clearTimeout(t)
  }, [copied])
  return (
    <button
      type="button"
      onClick={() => void navigator.clipboard?.writeText(value).then(() => setCopied(true))}
      className="inline-flex size-8 shrink-0 items-center justify-center text-muted-foreground hover:bg-muted hover:text-foreground"
      aria-label={copied ? 'Copied enrolment code' : 'Copy enrolment code'}
      data-testid="invite-copy"
    >
      {copied ? <Check className="size-4 text-allow" aria-hidden /> : <Copy className="size-4" aria-hidden />}
    </button>
  )
}

function RoleSelect({ id, value, onChange, testId }: { id: string; value: Role; onChange: (r: Role) => void; testId: string }) {
  return (
    <NativeSelect
      id={id}
      data-testid={testId}
      value={value}
      onValueChange={(v) => onChange(v as Role)}
      options={ROLE_ORDER.map((r) => ({ value: r, label: ROLE_LABEL[r] }))}
    />
  )
}

/** Flow: web/flows/invite-person.md */
function InviteDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const client = useClient()
  const qc = useQueryClient()
  const online = useOnline()
  const now = useNow(1000)
  const [name, setName] = useState('')
  const [role, setRole] = useState<Role>('employee')
  const create = useMutation({
    mutationFn: () => client.createInvite({ name: name.trim(), roles: [role] }),
    onSuccess: () => void qc.invalidateQueries(),
  })
  useEffect(() => {
    if (open) {
      setName('')
      setRole('employee')
      create.reset()
    }
    // Reset only when the dialog opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])
  const result = create.data
  const code = result && 'code' in result ? result : null
  const left = code ? new Date(code.expires_at).getTime() - now : 0
  const expired = !!code && left <= 0
  const needsApproval = NEEDS_APPROVAL.includes(role)
  const canSubmit = online && !create.isPending && name.trim().length >= 2

  return (
    <Dialog open={open} onOpenChange={(o) => (create.isPending ? null : onOpenChange(o))}>
      <DialogContent className="sm:max-w-lg">
        {result ? (
          <div>
            <DialogHeader>
              <DialogTitle>{code ? `Enrolment code for ${name.trim()}` : 'Sent for approval'}</DialogTitle>
              <DialogDescription>
                {code
                  ? 'Give this one-time code to the person. They use it on their own device to join.'
                  : `A second admin has to approve before the code for ${name.trim()} is issued.`}
              </DialogDescription>
            </DialogHeader>
            {code ? (
              <div className={cn('mt-4 border border-rule bg-card p-4 text-center', expired && 'opacity-60')}>
                <p className="label-caps">Enrolment code</p>
                <div className="mt-1 flex items-center justify-center gap-1">
                  <span className="data text-2xl tracking-[0.12em] break-all" data-testid="invite-code">
                    {code.code}
                  </span>
                  <CopyButton value={code.code} />
                </div>
                <p className="data mt-2 text-sm text-muted-foreground" data-testid="invite-countdown" aria-live="off">
                  {expired ? 'This code has expired.' : `Works once. Expires in ${countdown(left)}.`}
                </p>
                <p className="mt-1 text-sm font-medium">This code is shown once.</p>
              </div>
            ) : (
              <div className="mt-4 border border-rule bg-card p-4" data-testid="invite-pending-approval">
                <p>
                  The request is waiting in{' '}
                  <Link to="/app/admin/changes" className="text-primary underline underline-offset-2" onClick={() => onOpenChange(false)}>
                    Change requests
                  </Link>
                  . The code appears there once it is approved.
                </p>
              </div>
            )}
            <DialogFooter className="mt-5">
              <Button onClick={() => onOpenChange(false)} variant={code ? 'default' : 'outline'}>
                Close
              </Button>
            </DialogFooter>
          </div>
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault()
              if (canSubmit) create.mutate()
            }}
          >
            <DialogHeader>
              <DialogTitle>Invite a person</DialogTitle>
              <DialogDescription>They get a one-time code that works for 15 minutes.</DialogDescription>
            </DialogHeader>
            <div className="mt-4 flex flex-col gap-1.5">
              <Label htmlFor="invite-name">Name</Label>
              <Input id="invite-name" value={name} onChange={(e) => setName(e.target.value)} maxLength={64} autoFocus className="h-10" data-testid="invite-name" />
            </div>
            <div className="mt-4 flex flex-col gap-1.5">
              <Label htmlFor="invite-role">Role</Label>
              <RoleSelect id="invite-role" value={role} onChange={setRole} testId="invite-role" />
              {needsApproval ? <p className="text-sm text-muted-foreground">Needs approval from a second admin before the code is issued.</p> : null}
            </div>
            {create.error ? <ErrorNotice error={create.error} className="mt-4" onRetry={() => create.mutate()} /> : null}
            {!online ? <p className="mt-4 border-l-2 border-caution pl-3 text-sm">You are offline. Nothing is sent until the connection returns.</p> : null}
            <DialogFooter className="mt-5">
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={create.isPending}>
                Cancel
              </Button>
              <Button type="submit" disabled={!canSubmit} data-testid="invite-submit">
                {create.isPending ? 'Creating…' : 'Create code'}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

/** Flow: web/flows/role-change-and-approval.md */
function ChangeRoleDialog({ person, onClose }: { person: DirectoryUser; onClose: () => void }) {
  const client = useClient()
  const qc = useQueryClient()
  const toast = useToast()
  const online = useOnline()
  const [kind, setKind] = useState<'role_grant' | 'role_revoke'>('role_grant')
  const [role, setRole] = useState<Role>('auditor')
  const [reason, setReason] = useState('')
  const [pendingId, setPendingId] = useState<string | null>(null)
  const request = useMutation({
    mutationFn: () => client.requestChange({ type: kind, target_user_id: person.user_id, role, reason: reason.trim() }),
    onSuccess: (c) => {
      void qc.invalidateQueries()
      toast({ tone: 'done', title: c.status === 'pending' ? 'Change requested' : 'Change applied', body: `${person.name}: ${ROLE_LABEL[role]}` })
      if (c.status === 'pending') setPendingId(c.id)
      else onClose()
    },
  })
  const canSubmit = online && !request.isPending && reason.trim().length >= 3
  return (
    <Dialog open onOpenChange={(o) => (!o && !request.isPending ? onClose() : null)}>
      <DialogContent className="sm:max-w-lg">
        {pendingId ? (
          <div>
            <DialogHeader>
              <DialogTitle>Change requested for {person.name}</DialogTitle>
              <DialogDescription>It takes effect once enough other admins approve.</DialogDescription>
            </DialogHeader>
            <p className="mt-4" data-testid="change-pending-note">
              Waiting for approval in{' '}
              <Link to="/app/admin/changes" className="text-primary underline underline-offset-2" onClick={onClose}>
                Change requests
              </Link>
              .
            </p>
            <DialogFooter className="mt-5">
              <Button variant="outline" onClick={onClose}>
                Close
              </Button>
            </DialogFooter>
          </div>
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault()
              if (canSubmit) request.mutate()
            }}
          >
            <DialogHeader>
              <DialogTitle>Change role for {person.name}</DialogTitle>
              <DialogDescription>Sensitive roles need a second admin to approve. The reason is kept with the request.</DialogDescription>
            </DialogHeader>
            <fieldset className="mt-4">
              <legend className="font-medium">What to do</legend>
              <div className="mt-2 flex gap-1.5" role="radiogroup" aria-label="Grant or remove">
                {(
                  [
                    ['role_grant', 'Grant a role'],
                    ['role_revoke', 'Remove a role'],
                  ] as const
                ).map(([v, label]) => (
                  <label
                    key={v}
                    className={cn(
                      'inline-flex h-9 cursor-pointer items-center border px-3 has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-ring',
                      kind === v ? 'border-primary bg-accent text-accent-foreground' : 'border-input hover:bg-muted',
                    )}
                  >
                    <input type="radio" name="change-kind" className="sr-only" checked={kind === v} onChange={() => setKind(v)} />
                    {label}
                  </label>
                ))}
              </div>
            </fieldset>
            <div className="mt-4 flex flex-col gap-1.5">
              <Label htmlFor="change-role">Role</Label>
              <RoleSelect id="change-role" value={role} onChange={setRole} testId="change-role" />
            </div>
            <div className="mt-4 flex flex-col gap-1.5">
              <Label htmlFor="change-reason">Reason</Label>
              <Textarea id="change-reason" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={300} rows={3} data-testid="change-reason" />
            </div>
            {request.error ? <ErrorNotice error={request.error} className="mt-4" onRetry={() => request.mutate()} /> : null}
            {!online ? <p className="mt-4 border-l-2 border-caution pl-3 text-sm">You are offline. Nothing is sent until the connection returns.</p> : null}
            <DialogFooter className="mt-5">
              <Button type="button" variant="outline" onClick={onClose} disabled={request.isPending}>
                Cancel
              </Button>
              <Button type="submit" disabled={!canSubmit} data-testid="change-submit">
                {request.isPending ? 'Sending…' : 'Request change'}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

const INVITE_TONE: Record<Invite['status'], Tone> = { pending: 'caution', used: 'allow', expired: 'neutral', cancelled: 'neutral' }
const INVITE_LABEL: Record<Invite['status'], string> = { pending: 'Pending', used: 'Used', expired: 'Expired', cancelled: 'Cancelled' }

function InviteRow({ invite }: { invite: Invite }) {
  const client = useClient()
  const qc = useQueryClient()
  const toast = useToast()
  const online = useOnline()
  const cancel = useMutation({
    mutationFn: () => client.cancelInvite(invite.invite_id),
    onSuccess: () => {
      toast({ tone: 'done', title: 'Code cancelled', body: invite.user_name })
      void qc.invalidateQueries()
    },
  })
  return (
    <TableRow className="h-11" data-testid={`invite-row-${invite.invite_id}`}>
      <TableCell className="font-medium">{invite.user_name}</TableCell>
      <TableCell className="max-md:hidden">{invite.created_by}</TableCell>
      <TableCell>
        <Chip tone={INVITE_TONE[invite.status]}>{INVITE_LABEL[invite.status]}</Chip>
        {cancel.error ? <ErrorNotice error={cancel.error} className="mt-2" /> : null}
      </TableCell>
      <TableCell className="max-sm:hidden">
        <Time value={invite.expires_at} />
      </TableCell>
      <TableCell className="text-right">
        {invite.status === 'pending' ? (
          <Button
            variant="outline"
            size="sm"
            className="h-8"
            onClick={() => cancel.mutate()}
            disabled={!online || cancel.isPending}
            aria-label={`Cancel code for ${invite.user_name}`}
            data-testid={`invite-cancel-${invite.invite_id}`}
          >
            Cancel
          </Button>
        ) : null}
      </TableCell>
    </TableRow>
  )
}

export default function People() {
  useDocumentTitle('People')
  const client = useClient()
  const online = useOnline()
  const [inviting, setInviting] = useState(false)
  const [changing, setChanging] = useState<DirectoryUser | null>(null)
  const directory = useQuery({ queryKey: qk.directory, queryFn: () => client.directory() })
  const invites = useQuery({ queryKey: qk.invites, queryFn: () => client.listInvites() })

  const people = useMemo(() => {
    const d = directory.data
    if (!d) return []
    const revoked = new Set(d.revoked.map((r) => r.device_id))
    return d.users.map((u) => {
      const devs = d.devices.filter((x) => x.user_id === u.user_id)
      const live = devs.filter((x) => !revoked.has(x.device_id)).length
      return { user: u, live, anyRevoked: devs.some((x) => revoked.has(x.device_id)) }
    })
  }, [directory.data])

  return (
    <>
      <PageHeader
        title="People"
        description="Everyone in the organisation, the roles they hold and how many devices they have enrolled."
        actions={
          <Button onClick={() => setInviting(true)} disabled={!online} data-tour="people-invite" data-testid="people-invite" className="h-9">
            <Plus aria-hidden />
            Invite a person
          </Button>
        }
      />
      {directory.isPending ? (
        <RowsSkeleton rows={5} />
      ) : directory.error ? (
        <ErrorNotice error={directory.error} onRetry={() => void directory.refetch()} />
      ) : people.length === 0 ? (
        <EmptyState
          title="No people yet"
          body="Invite the first person to give them a one-time enrolment code."
          testId="people-empty"
          action={
            <Button onClick={() => setInviting(true)} disabled={!online} className="h-9">
              <UserPlus aria-hidden />
              Invite a person
            </Button>
          }
        />
      ) : (
        <div className="overflow-x-auto border border-border" data-testid="people-list">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="label-caps">Name</TableHead>
                <TableHead className="label-caps">Roles</TableHead>
                <TableHead className="label-caps text-right">Devices</TableHead>
                <TableHead className="label-caps">Status</TableHead>
                <TableHead className="w-12">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {people.map(({ user, live, anyRevoked }) => (
                <TableRow key={user.user_id} className="h-11" data-testid={`person-row-${user.user_id}`}>
                  <TableCell className="font-medium">{user.name}</TableCell>
                  <TableCell>
                    <span className="flex flex-wrap gap-1">
                      {user.roles.map((r) => (
                        <Chip key={r} tone={r === 'employee' ? 'neutral' : 'accent'}>
                          {ROLE_LABEL[r]}
                        </Chip>
                      ))}
                    </span>
                  </TableCell>
                  <TableCell className="data text-right">
                    {live}
                    {anyRevoked ? <span className="ml-1.5 text-xs text-muted-foreground">(one revoked)</span> : null}
                  </TableCell>
                  <TableCell>
                    {user.status === 'active' ? <Chip tone="allow">Active</Chip> : user.status === 'quarantined' ? <Chip tone="caution">Paused</Chip> : <Chip tone="deny">Disabled</Chip>}
                  </TableCell>
                  <TableCell className="text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon" aria-label={`More actions for ${user.name}`} data-testid={`people-menu-${user.user_id}`}>
                          <MoreHorizontal aria-hidden />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem disabled={!online} onSelect={() => setChanging(user)} data-testid={`people-change-role-${user.user_id}`}>
                          Change role
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <Section title="Enrolment codes" description="One-time codes that let a new person or device join." className="mt-10">
        {invites.isPending ? (
          <RowsSkeleton rows={2} />
        ) : invites.error ? (
          <ErrorNotice error={invites.error} onRetry={() => void invites.refetch()} />
        ) : (invites.data ?? []).length === 0 ? (
          <p className="border border-dashed border-rule p-4 text-muted-foreground" data-testid="invites-empty">
            No enrolment codes yet. Codes you create appear here.
          </p>
        ) : (
          <div className="overflow-x-auto border border-border" data-testid="invites-list">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="label-caps">Person</TableHead>
                  <TableHead className="label-caps max-md:hidden">Created by</TableHead>
                  <TableHead className="label-caps">Status</TableHead>
                  <TableHead className="label-caps max-sm:hidden">Expires</TableHead>
                  <TableHead className="w-24">
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(invites.data ?? []).map((i) => (
                  <InviteRow key={i.invite_id} invite={i} />
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </Section>

      <InviteDialog open={inviting} onOpenChange={setInviting} />
      {changing ? <ChangeRoleDialog person={changing} onClose={() => setChanging(null)} /> : null}
    </>
  )
}
