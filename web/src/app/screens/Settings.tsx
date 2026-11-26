import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Monitor, Moon, Sun } from 'lucide-react'
import { useState } from 'react'
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import type { Change } from '@/client/types'
import { Chip } from '@/components/qg/chips'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Ident, Time } from '@/components/qg/ident'
import { PageHeader, RowsSkeleton, Section } from '@/components/qg/page'
import { useToast } from '@/components/qg/toast'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { NativeSelect } from '@/components/qg/native-select'
import { Textarea } from '@/components/ui/textarea'
import { formatBytes } from '@/lib/format'
import { useDocumentTitle, useOnline } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { qk, useClient, useMe } from '../client-context'
import { useTheme } from '../theme'
import type { Theme } from '../theme'

function duration(seconds: number): string {
  if (seconds % 3600 === 0 && seconds >= 3600) return `${seconds / 3600} ${seconds === 3600 ? 'hour' : 'hours'}`
  if (seconds % 60 === 0 && seconds >= 60) return `${seconds / 60} ${seconds === 60 ? 'minute' : 'minutes'}`
  return `${seconds} ${seconds === 1 ? 'second' : 'seconds'}`
}

function Row({ label, children, testId }: { label: string; children: ReactNode; testId?: string }) {
  return (
    <div className="grid grid-cols-1 gap-x-4 gap-y-0.5 border-b border-border px-4 py-2.5 last:border-b-0 sm:grid-cols-[14rem_1fr]">
      <dt className="text-muted-foreground">{label}</dt>
      <dd data-testid={testId} className="min-w-0">
        {children}
      </dd>
    </div>
  )
}

function Organisation() {
  const client = useClient()
  const meta = useQuery({ queryKey: qk.meta, queryFn: () => client.meta() })
  if (meta.isPending) return <RowsSkeleton rows={6} />
  if (meta.error) return <ErrorNotice error={meta.error} onRetry={() => void meta.refetch()} />
  const m = meta.data
  const on = (b: boolean) => (b ? 'On' : 'Off')
  return (
    <>
      <dl className="border border-border bg-card" data-testid="settings-organisation">
        <Row label="Protocol suite">
          <span className="data">{m.suite}</span>
        </Row>
        <Row label="Server version">
          <span className="data">{m.version}</span>
        </Row>
        <Row label="Build">
          <span className="data">{m.commit}</span>
        </Row>
        <Row label="File chunk size">{formatBytes(m.limits.chunk_bytes)}</Row>
        <Row label="Largest file">{formatBytes(m.limits.max_file_bytes)}</Row>
        <Row label="Devices one file can be shared with">
          <span className="data">{m.limits.max_recipients}</span>
        </Row>
        <Row label="Permission to read lasts">{duration(m.limits.lease_seconds)}</Row>
        <Row label="Unlocked session lasts">
          {duration(m.limits.session_ttl_seconds)} idle, at most {duration(m.limits.session_hard_cap_seconds)}
        </Row>
        <Row label="Messaging">{on(m.features.messaging)}</Row>
        <Row label="Extra signature scheme (SLH-DSA)">{on(m.features.slhdsa)}</Row>
        {m.demo ? <Row label="Mode">Demonstration server</Row> : null}
      </dl>
    </>
  )
}

function ServerKeys() {
  const client = useClient()
  const meta = useQuery({ queryKey: qk.meta, queryFn: () => client.meta() })
  if (meta.isPending) return <RowsSkeleton rows={4} />
  if (meta.error) return <ErrorNotice error={meta.error} onRetry={() => void meta.refetch()} />
  const m = meta.data
  const keys: { label: string; value: string; use: string }[] = [
    { label: 'Signing key (Ed25519)', value: m.server_keys.ed25519_pk, use: 'Checks the server signed the directory, checkpoints and key sets. Used with the post-quantum key below.' },
    { label: 'Signing key (ML-DSA)', value: m.server_keys.mldsa_pk, use: 'The post-quantum half of every server signature. Both must verify.' },
    { label: 'Key exchange key (ML-KEM)', value: m.server_keys.kem_pk, use: 'Lets a device set up a session with the server that nobody else can read.' },
    { label: 'Recovery public key', value: m.recovery_pk, use: 'Locks the recovery slot of every file. Only the recovery kit can open it, and only after approval.' },
  ]
  return (
    <dl className="border border-border bg-card" data-testid="settings-server-keys">
      {keys.map((k) => (
        <Row key={k.label} label={k.label}>
          <Ident value={k.value} label={k.label} />
          <p className="mt-0.5 text-sm text-muted-foreground">{k.use}</p>
        </Row>
      ))}
    </dl>
  )
}

/** Flow: web/flows/recovery.md */
function Recovery() {
  const client = useClient()
  const qc = useQueryClient()
  const toast = useToast()
  const online = useOnline()
  const me = useMe()
  const [fileId, setFileId] = useState('')
  const [reason, setReason] = useState('')
  const files = useQuery({ queryKey: qk.files(), queryFn: () => client.listFiles() })
  const changes = useQuery({ queryKey: qk.changes(undefined), queryFn: () => client.listChanges() })
  const request = useMutation({
    mutationFn: () => client.requestChange({ type: 'recovery_release', target_user_id: me.device!.user_id, file_id: fileId, reason: reason.trim() }),
    onSuccess: () => {
      toast({ tone: 'done', title: 'Recovery requested', body: 'Other admins can now approve it.' })
      setFileId('')
      setReason('')
      void qc.invalidateQueries()
    },
  })
  const fileName = (id: string | null) => files.data?.find((f) => f.file_id === id)?.name ?? id ?? 'a file'
  const requests: Change[] = (changes.data ?? []).filter((c) => c.type === 'recovery_release')
  const canSubmit = online && !request.isPending && !!fileId && reason.trim().length >= 3

  return (
    <>
      <p className="max-w-[68ch]">
        When every device that could open a file is gone, the recovery kit can. The kit is a key created when the server first started and shown once. The server does not keep it. Releasing a file needs two other admins to approve, and the kit holder then runs a command on a trusted machine.
      </p>
      <form
        className="mt-4 flex max-w-xl flex-col gap-4 border border-border bg-card p-4"
        onSubmit={(e) => {
          e.preventDefault()
          if (canSubmit) request.mutate()
        }}
      >
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="recovery-file">File</Label>
          <NativeSelect
            id="recovery-file"
            className="w-full"
            data-testid="recovery-file"
            value={fileId}
            onValueChange={setFileId}
            disabled={files.isPending}
            options={[
              { value: '', label: files.isPending ? 'Loading files…' : 'Choose a file', disabled: true },
              ...(files.data ?? []).map((f) => ({ value: f.file_id, label: f.name })),
            ]}
          />
          {files.error ? <ErrorNotice error={files.error} onRetry={() => void files.refetch()} /> : null}
          {files.data && files.data.length === 0 ? <p className="text-sm text-muted-foreground">There are no files to recover.</p> : null}
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="recovery-reason">Reason</Label>
          <Textarea id="recovery-reason" value={reason} onChange={(e) => setReason(e.target.value)} rows={3} maxLength={300} data-testid="recovery-reason" />
        </div>
        {request.error ? <ErrorNotice error={request.error} onRetry={() => request.mutate()} /> : null}
        <div>
          <Button type="submit" className="h-10" disabled={!canSubmit} data-testid="recovery-submit">
            {request.isPending ? 'Requesting…' : 'Request recovery'}
          </Button>
          {!online ? <span className="ml-3 text-sm text-muted-foreground">You are offline.</span> : null}
        </div>
      </form>

      <h3 className="label-caps mt-6 mb-2" id="recovery-requests-heading">
        Recovery requests
      </h3>
      {changes.isPending ? (
        <RowsSkeleton rows={2} />
      ) : changes.error ? (
        <ErrorNotice error={changes.error} onRetry={() => void changes.refetch()} />
      ) : requests.length === 0 ? (
        <p className="border border-dashed border-rule p-4 text-muted-foreground" data-testid="recovery-empty">
          No recovery requests.
        </p>
      ) : (
        <ul className="border border-border" aria-labelledby="recovery-requests-heading">
          {requests.map((c) => (
            <li key={c.id} className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-border px-4 py-2.5 last:border-b-0" data-testid={`recovery-row-${c.id}`}>
              <span className="font-medium">{fileName(c.file_id)}</span>
              <Chip tone={c.status === 'applied' ? 'allow' : c.status === 'rejected' ? 'deny' : 'caution'}>{c.status === 'applied' ? 'Applied' : c.status === 'rejected' ? 'Rejected' : 'Pending'}</Chip>
              <span className="data text-sm">
                {c.approvals.length} of {c.approvals_required}
              </span>
              <span className="text-sm text-muted-foreground">
                {c.requested_by.name}, <Time value={c.requested_at} />
              </span>
              <Link to="/app/admin/changes" className="ml-auto text-primary underline underline-offset-2">
                Open in Change requests
              </Link>
            </li>
          ))}
        </ul>
      )}
    </>
  )
}

function Appearance() {
  const { theme, setTheme } = useTheme()
  const options: { value: Theme; label: string; icon: typeof Sun }[] = [
    { value: 'light', label: 'Light', icon: Sun },
    { value: 'dark', label: 'Dark', icon: Moon },
    { value: 'system', label: 'Match this device', icon: Monitor },
  ]
  return (
    <div role="group" aria-label="Theme" className="flex flex-wrap gap-2" data-testid="settings-theme">
      {options.map((o) => (
        <Button
          key={o.value}
          type="button"
          variant="outline"
          className={cn('h-9', theme === o.value && 'border-primary bg-accent text-accent-foreground')}
          aria-pressed={theme === o.value}
          onClick={() => setTheme(o.value)}
          data-testid={`theme-${o.value}`}
        >
          <o.icon aria-hidden />
          {o.label}
        </Button>
      ))}
    </div>
  )
}

export default function Settings() {
  useDocumentTitle('Settings')
  return (
    <>
      <PageHeader title="Settings" description="How this server is set up, the keys it publishes, and how to get a file back when no device can open it." />
      <Section title="Organisation" description="What this server is running and the limits it enforces.">
        <Organisation />
      </Section>
      <Section title="Server keys" description="Public keys only. Anyone can check a signature against them.">
        <ServerKeys />
      </Section>
      <Section title="Recovery">
        <Recovery />
      </Section>
      <Section title="Appearance">
        <Appearance />
      </Section>
    </>
  )
}
