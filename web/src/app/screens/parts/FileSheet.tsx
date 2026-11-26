import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, ShieldCheck, Trash2, UserMinus, UserPlus } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router'
import type { FileRecipient } from '@/client/types'
import { ClassificationChip, DecisionChip } from '@/components/qg/chips'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Time } from '@/components/qg/ident'
import { RowsSkeleton } from '@/components/qg/page'
import { useToast } from '@/components/qg/toast'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { actionWords, formatBytes, plural } from '@/lib/format'
import { useOnline } from '@/lib/hooks'
import { qk, useClient, useMe } from '../../client-context'
import { useNames } from '../../names'
import type { OpenState } from './useOpenFile'

function byPerson(recipients: FileRecipient[]) {
  const map = new Map<string, { user_id: string; name: string; devices: string[] }>()
  for (const r of recipients) {
    const e = map.get(r.user_id) ?? { user_id: r.user_id, name: r.user_name, devices: [] }
    e.devices.push(r.device_name)
    map.set(r.user_id, e)
  }
  return [...map.values()]
}

/** File detail, sharing and its recent receipts. Flow: web/flows/share-file.md */
export function FileSheet({
  fileId,
  onClose,
  onOpenFile,
  openState,
  openWords,
}: {
  fileId: string | null
  onClose: () => void
  onOpenFile: (id: string) => void
  openState?: OpenState
  openWords: string | null
}) {
  const client = useClient()
  const qc = useQueryClient()
  const toast = useToast()
  const online = useOnline()
  const { device } = useMe()
  const names = useNames()
  const [picking, setPicking] = useState(false)
  const [chosen, setChosen] = useState<Set<string>>(new Set())
  const [removing, setRemoving] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)

  const file = useQuery({ queryKey: qk.file(fileId ?? ''), queryFn: () => client.getFile(fileId!), enabled: !!fileId })
  const done = (title: string) => {
    toast({ tone: 'done', title })
    void qc.invalidateQueries()
  }
  const share = useMutation({
    mutationFn: () => client.shareFile(fileId!, [...chosen]),
    onSuccess: () => {
      setPicking(false)
      setChosen(new Set())
      done('Shared')
    },
  })
  const unshare = useMutation({
    mutationFn: (userId: string) => client.unshareFile(fileId!, userId),
    onSuccess: () => {
      setRemoving(null)
      done('Access removed. The file is getting a new key.')
    },
  })
  const remove = useMutation({
    mutationFn: () => client.deleteFile(fileId!),
    onSuccess: () => {
      done('File deleted')
      onClose()
    },
  })

  const f = file.data
  const people = f ? byPerson(f.recipients) : []
  const mine = !!f && f.owner.user_id === device?.user_id
  const candidates = (names.directory?.users ?? []).filter((u) => u.status === 'active' && !people.some((p) => p.user_id === u.user_id))
  const working = openState?.kind === 'working'

  return (
    <Sheet
      open={!!fileId}
      onOpenChange={(o) => {
        if (!o) {
          setPicking(false)
          setRemoving(null)
          setDeleting(false)
          onClose()
        }
      }}
    >
      <SheetContent className="w-full overflow-y-auto sm:max-w-xl" data-testid="file-sheet">
        <SheetHeader>
          <SheetTitle className="break-words">{f?.name ?? 'File'}</SheetTitle>
          <SheetDescription>
            {f ? `${formatBytes(f.size_bytes)} · version ${f.version} · protected by ${mine ? 'you' : f.owner.name}` : 'Loading details'}
          </SheetDescription>
        </SheetHeader>
        <div className="px-4 pb-6">
          {file.isPending ? <RowsSkeleton rows={4} /> : null}
          {file.error ? <ErrorNotice error={file.error} onRetry={() => void file.refetch()} /> : null}
          {f ? (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <ClassificationChip value={f.classification} />
                {f.rekey !== 'none' ? <span className="label-caps bg-caution-soft px-1.5 py-1 text-caution">New key pending</span> : null}
                <Button className="ml-auto h-9" onClick={() => onOpenFile(f.file_id)} disabled={!f.can_open || working || !online} data-testid="file-sheet-open">
                  <Download aria-hidden />
                  {working ? openWords : 'Open'}
                </Button>
              </div>
              {openState?.kind === 'failed' ? <ErrorNotice error={openState.error} className="mt-3" onRetry={() => onOpenFile(f.file_id)} retryLabel="Open again" /> : null}
              {openState?.kind === 'opened' ? (
                <p className="mt-3 flex items-center gap-1.5 text-sm text-allow">
                  <ShieldCheck className="size-4" aria-hidden />
                  {openState.verified ? 'Opened and checked on this device.' : 'Opened.'}{' '}
                  <Link className="text-primary underline underline-offset-2" to={`/app/evidence/verify?receipt=${openState.receipt_id}`}>
                    View receipt
                  </Link>
                </p>
              ) : null}
              {!f.can_open ? (
                <p className="mt-3 border-l-2 border-rule pl-3 text-sm text-muted-foreground">
                  This device has no key for this file. Someone who can open it has to share it with you again.
                </p>
              ) : null}

              <section className="mt-6">
                <div className="mb-2 flex items-center justify-between">
                  <h3 className="text-base">Who can open this</h3>
                  {f.can_open && !picking ? (
                    <Button variant="outline" size="sm" className="h-9" onClick={() => setPicking(true)} disabled={!online} data-testid="file-share-open">
                      <UserPlus aria-hidden />
                      Share
                    </Button>
                  ) : null}
                </div>
                <ul className="border border-border">
                  {people.map((p) => (
                    <li key={p.user_id} className="border-b border-border px-3 py-2 last:border-b-0">
                      <div className="flex items-center gap-2">
                        <div className="min-w-0 flex-1">
                          <p className="font-medium">
                            {p.name}
                            {p.user_id === device?.user_id ? <span className="font-normal text-muted-foreground"> (you)</span> : null}
                          </p>
                          <p className="truncate text-sm text-muted-foreground">{p.devices.join(', ')}</p>
                        </div>
                        {p.user_id !== device?.user_id && f.can_open ? (
                          <Button variant="ghost" size="sm" className="h-9" onClick={() => setRemoving(p.user_id)} disabled={!online} data-testid={`unshare-${p.user_id}`}>
                            <UserMinus aria-hidden />
                            Remove
                          </Button>
                        ) : null}
                      </div>
                      {removing === p.user_id ? (
                        <div className="mt-2 border border-deny/40 bg-deny-soft/60 p-2.5">
                          <p className="text-sm">
                            Remove access for {p.name}. Their key slots are deleted now and the file gets a new key. Anything they already opened
                            stays with them.
                          </p>
                          <div className="mt-2 flex gap-2">
                            <Button variant="danger" size="sm" onClick={() => unshare.mutate(p.user_id)} disabled={unshare.isPending} data-testid="unshare-confirm">
                              {unshare.isPending ? 'Removing…' : `Remove access for ${p.name.split(' ')[0]}`}
                            </Button>
                            <Button variant="outline" size="sm" onClick={() => setRemoving(null)}>
                              Cancel
                            </Button>
                          </div>
                          {unshare.error ? <ErrorNotice error={unshare.error} className="mt-2" /> : null}
                        </div>
                      ) : null}
                    </li>
                  ))}
                </ul>
                {people.length === 1 ? <p className="mt-2 text-sm text-muted-foreground">Only you can open this.</p> : null}

                {picking ? (
                  <div className="mt-3 border border-rule bg-card p-3">
                    <p className="font-medium">Share with</p>
                    {candidates.length === 0 ? (
                      <p className="mt-1 text-sm text-muted-foreground">Everyone in the organisation can already open this.</p>
                    ) : (
                      <ul className="mt-2">
                        {candidates.map((u) => {
                          const id = `share-user-${u.user_id}`
                          return (
                            <li key={u.user_id} className="flex h-10 items-center gap-3">
                              <Checkbox
                                id={id}
                                data-testid={id}
                                checked={chosen.has(u.user_id)}
                                onCheckedChange={(c) =>
                                  setChosen((s) => {
                                    const n = new Set(s)
                                    if (c === true) n.add(u.user_id)
                                    else n.delete(u.user_id)
                                    return n
                                  })
                                }
                              />
                              <label htmlFor={id} className="flex-1 cursor-pointer">
                                {u.name}
                              </label>
                            </li>
                          )
                        })}
                      </ul>
                    )}
                    {share.error ? <ErrorNotice error={share.error} className="mt-2" /> : null}
                    <div className="mt-3 flex gap-2">
                      <Button size="sm" className="h-9" onClick={() => share.mutate()} disabled={chosen.size === 0 || share.isPending} data-testid="share-submit">
                        {share.isPending ? 'Wrapping the key…' : `Share with ${plural(chosen.size, 'person', 'people')}`}
                      </Button>
                      <Button variant="outline" size="sm" className="h-9" onClick={() => setPicking(false)}>
                        Cancel
                      </Button>
                    </div>
                  </div>
                ) : null}
              </section>

              <section className="mt-6">
                <h3 className="mb-2 text-base">Recent decisions</h3>
                {f.activity.length === 0 ? (
                  <p className="text-sm text-muted-foreground">Nothing recorded for this file yet.</p>
                ) : (
                  <ul className="border border-border">
                    {f.activity.slice(0, 8).map((r) => (
                      <li key={r.id} className="flex min-h-11 items-center gap-2 border-b border-border px-3 py-1.5 last:border-b-0">
                        <div className="min-w-0 flex-1">
                          <Link className="hover:text-primary hover:underline" to={`/app/evidence/verify?receipt=${r.id}`}>
                            {actionWords(r.action)}
                          </Link>
                          <p className="truncate text-sm text-muted-foreground">
                            {names.user(r.subject.user_id) ?? 'Someone'} · {names.device(r.subject.device_id) ?? 'a device'} · <Time value={r.ts} />
                          </p>
                        </div>
                        <DecisionChip decision={r.decision} />
                      </li>
                    ))}
                  </ul>
                )}
              </section>

              {mine ? (
                <section className="mt-8 border-t border-rule pt-4">
                  {deleting ? (
                    <div className="border border-deny/40 bg-deny-soft/60 p-3">
                      <p className="text-sm">Delete {f.name} for everyone. The ciphertext and every key slot are removed. This cannot be undone.</p>
                      {remove.error ? <ErrorNotice error={remove.error} className="mt-2" /> : null}
                      <div className="mt-2 flex gap-2">
                        <Button variant="danger" size="sm" onClick={() => remove.mutate()} disabled={remove.isPending} data-testid="file-delete-confirm">
                          {remove.isPending ? 'Deleting…' : 'Delete this file'}
                        </Button>
                        <Button variant="outline" size="sm" onClick={() => setDeleting(false)}>
                          Keep it
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <Button variant="ghost" size="sm" className="h-9 text-deny" onClick={() => setDeleting(true)} disabled={!online} data-testid="file-delete">
                      <Trash2 aria-hidden />
                      Delete this file
                    </Button>
                  )}
                </section>
              ) : null}
            </>
          ) : null}
        </div>
      </SheetContent>
    </Sheet>
  )
}
