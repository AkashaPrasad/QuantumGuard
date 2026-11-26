import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, KeyRound, RotateCw } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import type { WorkProgress } from '@/client/client'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { describeError } from '@/lib/errors'
import { plural } from '@/lib/format'
import { useOnline } from '@/lib/hooks'
import { qk, useClient, useMe } from '../client-context'

/**
 * Background work this device owes: new keys after a revocation or an unshare,
 * and catch-up shares for a newly enrolled device. Runs by itself; the person only watches.
 * Flow: web/flows/rekey-pending.md
 */
export function PendingWorkBanner() {
  const client = useClient()
  const qc = useQueryClient()
  const { unlocked } = useMe()
  const online = useOnline()
  const pending = useQuery({
    queryKey: qk.pending,
    queryFn: () => client.pendingWork(),
    enabled: unlocked,
    refetchInterval: 5000,
  })
  const rekeys = pending.data?.rekeys.length ?? 0
  const shares = pending.data?.shares.length ?? 0
  const total = rekeys + shares

  const [progress, setProgress] = useState<WorkProgress | null>(null)
  const [running, setRunning] = useState(false)
  const [failed, setFailed] = useState<unknown>(null)
  const [finished, setFinished] = useState<{ rekeyed: number; shared: number } | null>(null)
  const busy = useRef(false)
  const abort = useRef<AbortController | null>(null)

  useEffect(() => () => abort.current?.abort(), [])

  function start() {
    if (busy.current) return
    busy.current = true
    setRunning(true)
    setFailed(null)
    abort.current = new AbortController()
    client
      .runPendingWork(setProgress, abort.current.signal)
      .then((r) => {
        setFinished(r)
        setTimeout(() => setFinished(null), 6000)
      })
      .catch(setFailed)
      .finally(() => {
        busy.current = false
        setRunning(false)
        setProgress(null)
        void qc.invalidateQueries()
      })
  }

  useEffect(() => {
    if (unlocked && online && total > 0 && !busy.current && !failed) start()
    // start() is stable enough for this purpose; it reads refs and setters only.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [unlocked, online, total, failed])

  if (finished && !running && total === 0) {
    return (
      <div role="status" data-testid="rekey-done" className="flex items-center gap-2 border-b border-allow/30 bg-allow-soft px-4 py-2 text-sm text-allow sm:px-6">
        <Check className="size-4 shrink-0" aria-hidden />
        {finished.rekeyed > 0 ? 'All affected files have new keys.' : 'Your other device can now open your files.'}
      </div>
    )
  }
  if (total === 0 && !running) return null

  const done = progress ? progress.index : 0
  const of = progress ? progress.total : total
  const pct = of > 0 ? Math.round((done / of) * 100) : 0
  const what =
    rekeys > 0 || progress?.kind === 'rekey'
      ? `${plural(of, 'file')} ${of === 1 ? 'is' : 'are'} getting new keys`
      : `Sharing ${plural(of, 'file')} with your other device`

  return (
    <div
      role="status"
      data-testid="rekey-banner"
      className="flex flex-col gap-2 border-b border-caution/30 bg-caution-soft px-4 py-2.5 sm:flex-row sm:items-center sm:gap-4 sm:px-6"
    >
      <div className="flex min-w-0 flex-1 items-center gap-2 text-sm text-caution">
        <KeyRound className="size-4 shrink-0" aria-hidden />
        <span className="min-w-0">
          <span className="font-medium">{what}</span>
          {failed ? (
            <span> · Stopped: {describeError(failed).title.toLowerCase()}.</span>
          ) : !online ? (
            <span> · Paused, resumes when you are back online.</span>
          ) : (
            <span data-testid="rekey-progress" className="data">
              {' '}
              ({done} of {of}){progress ? ` · ${progress.name}` : ''}
            </span>
          )}
          {!failed && online ? <span className="max-sm:hidden"> · Keep this tab open.</span> : null}
        </span>
      </div>
      {failed ? (
        <Button size="sm" variant="outline" onClick={() => setFailed(null)}>
          <RotateCw aria-hidden />
          Resume
        </Button>
      ) : (
        <Progress value={pct} className="h-1.5 w-full sm:w-48" aria-label="New keys progress" />
      )}
    </div>
  )
}
