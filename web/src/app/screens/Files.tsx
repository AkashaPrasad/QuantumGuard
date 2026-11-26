import { useQuery } from '@tanstack/react-query'
import { Download, FolderLock, Lock, Search, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router'
import type { Classification, FileItem } from '@/client/types'
import { ClassificationChip } from '@/components/qg/chips'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Time } from '@/components/qg/ident'
import { EmptyState, PageHeader, RowsSkeleton } from '@/components/qg/page'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { describeError } from '@/lib/errors'
import { formatBytes } from '@/lib/format'
import { useDocumentTitle, useOnline } from '@/lib/hooks'
import { qk, useClient, useMe } from '../client-context'
import { FileSheet } from './parts/FileSheet'
import { ProtectDialog } from './parts/ProtectDialog'
import { Segmented } from './parts/Segmented'
import { useOpenFile } from './parts/useOpenFile'

const FILTERS: { value: Classification | 'all'; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'internal', label: 'Internal' },
  { value: 'confidential', label: 'Confidential' },
  { value: 'restricted', label: 'Restricted' },
]

function whoCanOpen(f: FileItem, myId: string | undefined): string {
  const others = [...new Set(f.recipients.filter((r) => r.user_id !== myId).map((r) => r.user_name))]
  const me = f.recipients.some((r) => r.user_id === myId)
  if (others.length === 0) return me ? 'Only you' : 'Nobody on an active device'
  const lead = me ? 'You and ' : ''
  if (others.length === 1) return `${lead}${others[0]}`
  return `${lead}${others.length} ${me ? 'others' : 'people'}`
}

/** Flows: web/flows/protect-file.md, web/flows/open-file.md, web/flows/share-file.md */
export default function Files() {
  useDocumentTitle('Files')
  const client = useClient()
  const online = useOnline()
  const navigate = useNavigate()
  const { device } = useMe()
  const { fileId } = useParams()
  const [params, setParams] = useSearchParams()
  const [q, setQ] = useState('')
  const [filter, setFilter] = useState<Classification | 'all'>('all')
  const [protecting, setProtecting] = useState(false)
  const [dropped, setDropped] = useState<File | null>(null)
  const [dragging, setDragging] = useState(false)
  const { states, open, words } = useOpenFile()

  const files = useQuery({ queryKey: qk.files({}), queryFn: () => client.listFiles(), refetchInterval: 15_000 })

  useEffect(() => {
    if (params.get('protect') !== '1') return
    setDropped(null)
    setProtecting(true)
    params.delete('protect')
    setParams(params, { replace: true })
  }, [params, setParams])

  const all = files.data ?? []
  const needle = q.trim().toLowerCase()
  const shown = all.filter(
    (f) => (filter === 'all' || f.classification === filter) && (!needle || f.name.toLowerCase().includes(needle) || f.owner.name.toLowerCase().includes(needle)),
  )
  const sheetState = fileId ? states[fileId] : undefined

  return (
    <div
      onDragEnter={(e) => {
        if (e.dataTransfer.types.includes('Files')) setDragging(true)
      }}
      onDragOver={(e) => {
        if (e.dataTransfer.types.includes('Files')) e.preventDefault()
      }}
      onDragLeave={(e) => {
        if (e.currentTarget === e.target) setDragging(false)
      }}
      onDrop={(e) => {
        const f = e.dataTransfer.files[0]
        setDragging(false)
        if (!f) return
        e.preventDefault()
        setDropped(f)
        setProtecting(true)
      }}
      className="relative"
    >
      <PageHeader
        title="Files"
        description="Files are encrypted on this device before they leave it. The server stores ciphertext and decides, each time, whether to release a key."
        actions={
          <Button
            onClick={() => {
              setDropped(null)
              setProtecting(true)
            }}
            disabled={!online}
            data-tour="files-protect"
            data-testid="files-protect"
            className="h-9"
          >
            <Lock aria-hidden />
            Protect a file
          </Button>
        }
      />

      {all.length > 0 ? (
        <div className="mb-3 flex flex-col gap-2 sm:flex-row sm:items-center">
          <div className="relative sm:w-72">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Find by name or owner" aria-label="Find a file" className="h-9 pl-8" data-testid="files-search" />
          </div>
          <Segmented value={filter} onChange={setFilter} options={FILTERS} label="Filter by sensitivity" testId="files-filter" />
          <p className="data text-sm text-muted-foreground sm:ml-auto" aria-live="polite">
            {shown.length} of {all.length}
          </p>
        </div>
      ) : null}

      {files.isPending ? (
        <RowsSkeleton rows={6} />
      ) : files.error ? (
        <ErrorNotice error={files.error} onRetry={() => void files.refetch()} />
      ) : all.length === 0 ? (
        <EmptyState
          testId="files-empty"
          title="Nothing protected yet"
          body="Drop a file anywhere on this page, or choose one. It is encrypted here before anything is sent."
          action={
            <Button onClick={() => setProtecting(true)} disabled={!online}>
              <Lock aria-hidden />
              Protect a file
            </Button>
          }
        />
      ) : shown.length === 0 ? (
        <EmptyState title="No file matches" body="Try a shorter search or another sensitivity." />
      ) : (
        <div className="overflow-x-auto border border-border" data-tour="files-list" data-testid="files-list">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="label-caps">Name</TableHead>
                <TableHead className="label-caps max-md:hidden">Sensitivity</TableHead>
                <TableHead className="label-caps max-lg:hidden">Who can open</TableHead>
                <TableHead className="label-caps max-md:hidden">Updated</TableHead>
                <TableHead className="label-caps text-right">
                  <span className="sr-only">Open</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.map((f) => {
                const s = states[f.file_id]
                return (
                  <TableRow key={f.file_id} data-testid={`file-row-${f.file_id}`} className="h-11">
                    <TableCell className="max-w-0 w-full sm:w-auto sm:max-w-80">
                      <button
                        type="button"
                        onClick={() => navigate(`/app/files/${f.file_id}`)}
                        className="flex w-full min-w-0 items-center gap-2 text-left hover:text-primary"
                      >
                        <FolderLock className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                        <span className="min-w-0">
                          <span className="block truncate font-medium">{f.name}</span>
                          <span className="block truncate text-[0.75rem] text-muted-foreground">
                            <span className="data">{formatBytes(f.size_bytes)}</span>
                            {f.owner.user_id !== device?.user_id ? ` · from ${f.owner.name}` : ''}
                            {f.rekey !== 'none' ? ' · new key pending' : ''}
                          </span>
                        </span>
                      </button>
                      {s?.kind === 'failed' ? (
                        <p className="mt-1 text-sm text-deny" role="alert" data-testid="file-open-error" data-code={describeError(s.error).code}>
                          {describeError(s.error).title}. {describeError(s.error).body}
                        </p>
                      ) : null}
                    </TableCell>
                    <TableCell className="max-md:hidden">
                      <ClassificationChip value={f.classification} />
                    </TableCell>
                    <TableCell className="max-lg:hidden">{whoCanOpen(f, device?.user_id)}</TableCell>
                    <TableCell className="text-muted-foreground max-md:hidden">
                      <Time value={f.updated_at} />
                    </TableCell>
                    <TableCell className="text-right whitespace-nowrap">
                      {s?.kind === 'opened' ? (
                        <span className="mr-2 inline-flex items-center gap-1 align-middle text-sm text-allow" data-testid="file-verified">
                          <ShieldCheck className="size-4" aria-hidden />
                          <span className="max-sm:sr-only">{s.verified ? 'Checked on this device' : 'Opened'}</span>
                          <Link className="ml-1 text-primary underline underline-offset-2" to={`/app/evidence/verify?receipt=${s.receipt_id}`} data-testid="file-receipt-link">
                            Receipt
                          </Link>
                        </span>
                      ) : null}
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-9 min-w-20"
                        onClick={() => void open(f.file_id)}
                        disabled={!f.can_open || s?.kind === 'working' || !online}
                        data-testid={`file-open-${f.file_id}`}
                        aria-label={`Open ${f.name}`}
                        title={f.can_open ? undefined : 'This device has no key for this file'}
                      >
                        {s?.kind === 'working' ? (
                          <span className="data" data-testid="file-open-progress" role="status">
                            {words(s.progress)}
                          </span>
                        ) : (
                          <>
                            <Download aria-hidden />
                            {s?.kind === 'failed' ? 'Open again' : 'Open'}
                          </>
                        )}
                      </Button>
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </div>
      )}

      {dragging ? (
        <div className="pointer-events-none absolute inset-0 z-10 flex items-center justify-center border-2 border-dashed border-primary bg-accent/85" aria-hidden>
          <p className="font-display text-3xl text-accent-foreground">Drop to protect this file</p>
        </div>
      ) : null}

      <ProtectDialog open={protecting} onOpenChange={setProtecting} initialFile={dropped} />
      <FileSheet
        fileId={fileId ?? null}
        onClose={() => navigate('/app/files')}
        onOpenFile={(id) => void open(id)}
        openState={sheetState}
        openWords={sheetState?.kind === 'working' ? words(sheetState.progress) : null}
      />
    </div>
  )
}
