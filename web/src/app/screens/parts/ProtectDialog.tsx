import { useQuery, useQueryClient } from '@tanstack/react-query'
import { FileUp, Lock, Upload } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { ProtectProgress } from '@/client/client'
import type { Classification, FileItem, Receipt } from '@/client/types'
import { ErrorNotice } from '@/components/qg/error-notice'
import { ReceiptSlip } from '@/components/qg/receipt-slip'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { isCode } from '@/lib/errors'
import { formatBytes, plural } from '@/lib/format'
import { useOnline } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { EncryptChunks } from '@/motion/EncryptChunks'
import { WrapBeams } from '@/motion/WrapBeams'
import type { WrapTarget } from '@/motion/WrapBeams'
import { qk, useClient, useMe } from '../../client-context'

const LEVELS: { id: Classification; label: string; hint: string }[] = [
  { id: 'internal', label: 'Internal', hint: 'Routine work. Anyone you choose can open it.' },
  { id: 'confidential', label: 'Confidential', hint: 'The usual choice for anything you would not email.' },
  { id: 'restricted', label: 'Restricted', hint: 'Most sensitive. Access is paused first if anything looks wrong.' },
]

type Stage = 'form' | 'working' | 'done'

/** Flow: web/flows/protect-file.md */
export function ProtectDialog({
  open,
  onOpenChange,
  initialFile,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  initialFile?: File | null
}) {
  const client = useClient()
  const qc = useQueryClient()
  const online = useOnline()
  const { device } = useMe()
  const directory = useQuery({ queryKey: qk.directory, queryFn: () => client.directory(), enabled: open })
  const meta = useQuery({ queryKey: qk.meta, queryFn: () => client.meta(), staleTime: 60_000, enabled: open })

  const [file, setFile] = useState<File | null>(null)
  const [level, setLevel] = useState<Classification>('confidential')
  const [people, setPeople] = useState<Set<string>>(new Set())
  const [stage, setStage] = useState<Stage>('form')
  const [progress, setProgress] = useState<ProtectProgress | null>(null)
  const [wrapped, setWrapped] = useState<Set<string>>(new Set())
  const [error, setError] = useState<unknown>(null)
  const [result, setResult] = useState<{ file: FileItem; receipt: Receipt | null } | null>(null)
  const [over, setOver] = useState(false)
  const abort = useRef<AbortController | null>(null)
  const input = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!open) return
    setFile(initialFile ?? null)
    setLevel('confidential')
    setPeople(new Set())
    setStage('form')
    setProgress(null)
    setWrapped(new Set())
    setError(null)
    setResult(null)
  }, [open, initialFile])

  const revokedIds = useMemo(() => new Set((directory.data?.revoked ?? []).map((r) => r.device_id)), [directory.data])
  const others = (directory.data?.users ?? []).filter((u) => u.user_id !== device?.user_id && u.status === 'active')
  const myDevices = (directory.data?.devices ?? []).filter((d) => d.user_id === device?.user_id && !revokedIds.has(d.device_id))

  // Every device that will receive a wrapped key, in the order they are shown.
  const targets: WrapTarget[] = useMemo(() => {
    const users = new Map((directory.data?.users ?? []).map((u) => [u.user_id, u.name]))
    return (directory.data?.devices ?? [])
      .filter((d) => !revokedIds.has(d.device_id) && (d.user_id === device?.user_id || people.has(d.user_id)))
      .map((d) => ({ device_id: d.device_id, device_name: d.name, owner: d.user_id === device?.user_id ? 'you' : users.get(d.user_id) }))
  }, [directory.data, revokedIds, people, device])

  const limit = meta.data?.limits.max_file_bytes ?? Infinity
  const tooBig = !!file && file.size > limit
  const noDeviceFor = others.filter((u) => people.has(u.user_id) && !(directory.data?.devices ?? []).some((d) => d.user_id === u.user_id && !revokedIds.has(d.device_id)))

  async function protect() {
    if (!file || tooBig) return
    setStage('working')
    setError(null)
    setWrapped(new Set())
    setProgress({ phase: 'encrypting', chunk: 0, chunks: Math.max(1, Math.ceil(file.size / (meta.data?.limits.chunk_bytes ?? 1_048_576))) })
    abort.current = new AbortController()
    try {
      const r = await client.protectFile(
        { file, classification: level, recipient_user_ids: [...people] },
        (p) => {
          setProgress(p)
          if (p.phase === 'wrapping') setWrapped((w) => new Set(w).add(p.device_id))
        },
        abort.current.signal,
      )
      let receipt: Receipt | null = null
      try {
        receipt = await client.getReceipt(r.receipt_id)
      } catch {
        receipt = null // the file is protected; the slip is a courtesy
      }
      setResult({ file: r.file, receipt })
      setStage('done')
      void qc.invalidateQueries()
    } catch (err) {
      if (isCode(err, 'QG_LOCAL_CANCELLED')) {
        onOpenChange(false)
        return
      }
      setError(err)
      setStage('form')
    }
  }

  function requestClose(next: boolean) {
    if (next) return onOpenChange(true)
    if (stage === 'working') {
      if (progress?.phase === 'committing') return
      if (!confirm('Stop protecting this file? Nothing has been saved yet.')) return
      abort.current?.abort()
      return
    }
    onOpenChange(false)
  }

  const encrypting = progress?.phase === 'encrypting' || progress?.phase === 'uploading' ? progress : null
  const pastEncrypt = progress?.phase === 'wrapping' || progress?.phase === 'committing' || progress?.phase === 'done'
  const phaseText =
    progress?.phase === 'encrypting'
      ? `Encrypting on this device: block ${Math.min(progress.chunk + 1, progress.chunks)} of ${progress.chunks}`
      : progress?.phase === 'uploading'
        ? `Sending ciphertext: block ${Math.min(progress.chunk + 1, progress.chunks)} of ${progress.chunks}`
        : progress?.phase === 'wrapping'
          ? `Wrapping the file key for each device: ${progress.done} of ${progress.total}`
          : progress?.phase === 'committing'
            ? 'Signing the manifest and committing'
            : 'Starting'

  return (
    <Dialog open={open} onOpenChange={requestClose}>
      <DialogContent className="max-h-[92dvh] overflow-y-auto sm:max-w-xl" data-testid="protect-dialog">
        {stage === 'done' && result ? (
          <div data-testid="protect-receipt">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Lock className="size-4 text-allow" aria-hidden />
                Protected
              </DialogTitle>
              <DialogDescription>
                <span className="font-medium text-foreground">{result.file.name}</span> can be opened by {plural(result.file.recipients.length, 'device')}.
                The server holds ciphertext and sealed key slots only.
              </DialogDescription>
            </DialogHeader>
            {result.receipt ? <ReceiptSlip receipt={result.receipt} className="mx-auto mt-4" /> : null}
            <DialogFooter className="mt-6">
              <Button onClick={() => onOpenChange(false)} data-testid="protect-done" autoFocus>
                Done
              </Button>
            </DialogFooter>
          </div>
        ) : stage === 'working' && file ? (
          <div data-testid="protect-progress">
            <DialogHeader>
              <DialogTitle>Protecting {file.name}</DialogTitle>
              <DialogDescription>The file is encrypted here, on this device, before anything is sent.</DialogDescription>
            </DialogHeader>
            <div className="mt-4 border border-rule bg-card p-4">
              <EncryptChunks name={file.name} chunk={encrypting?.chunk ?? 0} chunks={encrypting?.chunks ?? 1} done={!!pastEncrypt || progress?.phase === 'uploading'} />
            </div>
            <div className="mt-3 border border-rule bg-card p-4">
              <p className="label-caps mb-2">File key, wrapped for</p>
              <WrapBeams targets={targets} wrapped={wrapped} />
            </div>
            <p className="mt-3 text-sm text-muted-foreground" role="status" aria-live="polite">
              {phaseText}
            </p>
            <DialogFooter className="mt-5">
              <Button variant="outline" onClick={() => abort.current?.abort()} disabled={progress?.phase === 'committing'} data-testid="protect-cancel">
                Cancel
              </Button>
            </DialogFooter>
          </div>
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault()
              void protect()
            }}
          >
            <DialogHeader>
              <DialogTitle>Protect a file</DialogTitle>
              <DialogDescription>It is encrypted on this device. Only the devices of the people you choose can open it.</DialogDescription>
            </DialogHeader>

            {error ? <ErrorNotice error={error} className="mt-4" /> : null}

            <div
              data-testid="protect-drop"
              onDragOver={(e) => {
                e.preventDefault()
                setOver(true)
              }}
              onDragLeave={() => setOver(false)}
              onDrop={(e) => {
                e.preventDefault()
                setOver(false)
                const f = e.dataTransfer.files[0]
                if (f) setFile(f)
              }}
              className={cn('mt-4 border border-dashed p-4', over ? 'border-primary bg-accent' : 'border-rule bg-card')}
            >
              <input
                ref={input}
                type="file"
                className="sr-only"
                id="protect-file-input"
                aria-label="File to protect"
                data-testid="protect-file-input"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
              {file ? (
                <div className="flex items-center gap-3">
                  <FileUp className="size-5 shrink-0 text-primary" aria-hidden />
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-medium">{file.name}</p>
                    <p className="data text-sm text-muted-foreground">{formatBytes(file.size)}</p>
                  </div>
                  <Button type="button" variant="outline" size="sm" className="h-9" onClick={() => input.current?.click()}>
                    Choose another
                  </Button>
                </div>
              ) : (
                <div className="flex flex-col items-center gap-2 py-4 text-center">
                  <Upload className="size-5 text-muted-foreground" aria-hidden />
                  <p>Drop a file here, or</p>
                  <Button type="button" variant="outline" className="h-9" onClick={() => input.current?.click()} autoFocus>
                    Choose a file
                  </Button>
                </div>
              )}
            </div>
            {tooBig ? (
              <p role="alert" className="mt-2 text-sm text-deny">
                This file is {formatBytes(file!.size)}. The largest file this server accepts is {formatBytes(limit)}.
              </p>
            ) : null}

            <fieldset className="mt-5" data-testid="protect-classification">
              <legend className="font-medium">How sensitive is it?</legend>
              <div className="mt-2 grid gap-1.5 sm:grid-cols-3">
                {LEVELS.map((l) => (
                  <label
                    key={l.id}
                    className={cn(
                      'cursor-pointer border p-2.5 has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-ring',
                      level === l.id ? 'border-primary bg-accent' : 'border-input hover:bg-muted',
                    )}
                  >
                    <input type="radio" name="protect-level" value={l.id} checked={level === l.id} onChange={() => setLevel(l.id)} className="sr-only" data-testid={`protect-level-${l.id}`} />
                    <span className="block font-medium">{l.label}</span>
                    <span className="mt-0.5 block text-sm text-muted-foreground">{l.hint}</span>
                  </label>
                ))}
              </div>
            </fieldset>

            <fieldset className="mt-5">
              <legend className="font-medium">Who can open it?</legend>
              <ul className="mt-2 border border-border">
                <li className="flex h-11 items-center gap-3 border-b border-border bg-muted/50 px-3">
                  <Checkbox checked disabled aria-label="You, always included" />
                  <span className="flex-1">
                    You <span className="text-muted-foreground">on {plural(Math.max(myDevices.length, 1), 'device')}</span>
                  </span>
                  <span className="label-caps">Always</span>
                </li>
                {others.map((u) => {
                  const id = `protect-recipient-${u.user_id}`
                  return (
                    <li key={u.user_id} className="flex h-11 items-center gap-3 border-b border-border px-3 last:border-b-0">
                      <Checkbox
                        id={id}
                        data-testid={id}
                        checked={people.has(u.user_id)}
                        onCheckedChange={(c) =>
                          setPeople((p) => {
                            const n = new Set(p)
                            if (c === true) n.add(u.user_id)
                            else n.delete(u.user_id)
                            return n
                          })
                        }
                      />
                      <label htmlFor={id} className="flex-1 cursor-pointer">
                        {u.name}
                      </label>
                      <span className="text-sm text-muted-foreground capitalize">{u.roles.join(', ')}</span>
                    </li>
                  )
                })}
                {directory.isPending ? <li className="px-3 py-3 text-sm text-muted-foreground">Loading people…</li> : null}
              </ul>
              {noDeviceFor.length > 0 ? (
                <p className="mt-2 text-sm text-caution">
                  {noDeviceFor.map((u) => u.name).join(', ')} {noDeviceFor.length === 1 ? 'has' : 'have'} no active device yet, so cannot open it until one is enrolled and you share again.
                </p>
              ) : null}
            </fieldset>

            <DialogFooter className="mt-6">
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={!file || tooBig || !online || directory.isPending} data-testid="protect-submit">
                <Lock aria-hidden />
                Protect
              </Button>
            </DialogFooter>
            {!online ? <p className="mt-2 text-right text-sm text-muted-foreground">You are offline. Protecting needs a connection.</p> : null}
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}
