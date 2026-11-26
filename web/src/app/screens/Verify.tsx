import { FileJson, ShieldCheck, ShieldX, Upload } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { useLocation, useSearchParams } from 'react-router'
import type { VerifyResult, VerifyStep } from '@/client/client'
import type { Receipt } from '@/client/types'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Ident } from '@/components/qg/ident'
import { PageHeader } from '@/components/qg/page'
import { ReceiptSlip } from '@/components/qg/receipt-slip'
import type { SlipCheck } from '@/components/qg/receipt-slip'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { exactTime, plural } from '@/lib/format'
import { useDocumentTitle, useOnline } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { MerkleClimb } from '@/motion/MerkleClimb'
import { useClient } from '../client-context'
import { Segmented } from './parts/Segmented'

type Mode = 'receipt' | 'bundle'

function ResultPanel({ result, what }: { result: VerifyResult; what: string }) {
  return (
    <div
      role="status"
      data-testid="verify-result"
      data-ok={result.ok}
      className={cn('border p-4', result.ok ? 'border-allow/40 bg-allow-soft' : 'border-deny/40 bg-deny-soft')}
    >
      <p className={cn('flex items-center gap-2 text-base font-semibold', result.ok ? 'text-allow' : 'text-deny')}>
        {result.ok ? <ShieldCheck className="size-5" aria-hidden /> : <ShieldX className="size-5" aria-hidden />}
        {result.ok ? 'Verified on this device' : 'Verification failed'}
      </p>
      {result.ok ? (
        <p className="mt-1">
          {what} {result.checked === 1 ? 'is' : 'are'} in the log, and the log's signed root carries two valid signatures. This check used only
          public keys and ran in this browser.
        </p>
      ) : (
        <p className="mt-1">
          {result.failed_index !== null ? (
            <>
              The first entry that did not verify is{' '}
              <strong className="data font-medium" data-testid="verify-failed-index">
                #{result.failed_index}
              </strong>
              .{' '}
            </>
          ) : null}
          {result.reason ?? 'The proof does not lead to the signed root.'} Treat this record as altered and tell an operator.
        </p>
      )}
      {result.checkpoint ? (
        <dl className="data mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-0.5 border-t border-current/20 pt-2 text-[0.8125rem]">
          <dt className="text-muted-foreground">checkpoint</dt>
          <dd>{exactTime(result.checkpoint.ts)}</dd>
          <dt className="text-muted-foreground">log size</dt>
          <dd>{result.checkpoint.tree_size} entries</dd>
          <dt className="text-muted-foreground">root</dt>
          <dd className="min-w-0">
            <Ident value={result.checkpoint.root_hash} label="root hash" />
          </dd>
        </dl>
      ) : null}
    </div>
  )
}

/** Flow: web/flows/verify-evidence.md */
export default function Verify() {
  useDocumentTitle('Verify')
  const client = useClient()
  const online = useOnline()
  const location = useLocation()
  const [params, setParams] = useSearchParams()
  const carried = (location.state as { bundle?: unknown } | null)?.bundle

  const [mode, setMode] = useState<Mode>(carried ? 'bundle' : 'receipt')
  const [id, setId] = useState(params.get('receipt') ?? '')
  const [receipt, setReceipt] = useState<Receipt | null>(null)
  const [steps, setSteps] = useState<VerifyStep[]>([])
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<VerifyResult | null>(null)
  const [error, setError] = useState<unknown>(null)
  const [bundleName, setBundleName] = useState<string | null>(null)
  const [over, setOver] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)
  const started = useRef(false)

  const reset = () => {
    setSteps([])
    setResult(null)
    setError(null)
    setReceipt(null)
  }

  const verifyReceipt = useCallback(
    async (receiptId: string) => {
      const wanted = receiptId.trim()
      if (!wanted) return
      reset()
      setRunning(true)
      try {
        setReceipt(await client.getReceipt(wanted))
        setResult(await client.verifyReceipt(wanted, (s) => setSteps((all) => [...all, s])))
      } catch (err) {
        setError(err)
      } finally {
        setRunning(false)
      }
    },
    [client],
  )

  const verifyBundle = useCallback(
    async (bundle: unknown, name: string) => {
      reset()
      setBundleName(name)
      setRunning(true)
      try {
        setResult(await client.verifyBundle(bundle, (s) => setSteps((all) => [...all, s])))
      } catch (err) {
        setError(err)
      } finally {
        setRunning(false)
      }
    },
    [client],
  )

  // Arriving with a receipt in the address, or a bundle handed over from an incident: start at once.
  useEffect(() => {
    if (started.current) return
    started.current = true
    if (carried) void verifyBundle(carried, 'the exported bundle')
    else if (params.get('receipt')) void verifyReceipt(params.get('receipt')!)
  }, [carried, params, verifyBundle, verifyReceipt])

  async function readBundle(file: File) {
    try {
      await verifyBundle(JSON.parse(await file.text()), file.name)
    } catch {
      reset()
      setBundleName(file.name)
      setResult({ ok: false, checked: 0, failed_index: null, reason: 'This file is not a proof bundle (it is not valid JSON).', checkpoint: null })
    }
  }

  const check: SlipCheck = running ? 'checking' : result ? (result.ok ? 'verified' : 'failed') : 'unchecked'

  return (
    <>
      <PageHeader
        title="Verify"
        description="Check a decision without trusting the server. The hashing and both signature checks run here, in this browser, against public keys."
      />
      <div className="mb-5" data-tour="evidence-verify">
        <Segmented
          value={mode}
          onChange={(m) => {
            setMode(m)
            reset()
          }}
          options={[
            { value: 'receipt', label: 'One receipt' },
            { value: 'bundle', label: 'A proof bundle' },
          ]}
          label="What to verify"
          testId="verify-mode"
        />
      </div>

      {mode === 'receipt' ? (
        <form
          className="flex max-w-xl flex-col gap-1.5"
          onSubmit={(e) => {
            e.preventDefault()
            params.set('receipt', id.trim())
            setParams(params, { replace: true })
            void verifyReceipt(id)
          }}
        >
          <Label htmlFor="verify-input">Receipt id</Label>
          <div className="flex gap-2">
            <Input id="verify-input" data-testid="verify-input" value={id} onChange={(e) => setId(e.target.value)} placeholder="rcp_…" spellCheck={false} className="data h-10" />
            <Button type="submit" className="h-10" disabled={!id.trim() || running || !online} data-testid="verify-submit">
              <ShieldCheck aria-hidden />
              {running ? 'Checking…' : 'Verify'}
            </Button>
          </div>
          <p className="text-sm text-muted-foreground">
            {online
              ? 'Receipt ids are shown in Activity, on each file, and in every error message that was recorded.'
              : 'You are offline. One receipt needs the network to fetch its proof; a proof bundle can be verified offline.'}
          </p>
        </form>
      ) : (
        <div
          data-testid="verify-drop"
          onDragOver={(e) => {
            e.preventDefault()
            setOver(true)
          }}
          onDragLeave={() => setOver(false)}
          onDrop={(e) => {
            e.preventDefault()
            setOver(false)
            const f = e.dataTransfer.files[0]
            if (f) void readBundle(f)
          }}
          className={cn('flex max-w-xl flex-col items-center gap-2 border border-dashed p-6 text-center', over ? 'border-primary bg-accent' : 'border-rule bg-card')}
        >
          <input
            ref={fileInput}
            type="file"
            accept="application/json,.json"
            className="sr-only"
            data-testid="verify-file-input"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) void readBundle(f)
              e.target.value = ''
            }}
          />
          {bundleName ? <FileJson className="size-5 text-primary" aria-hidden /> : <Upload className="size-5 text-muted-foreground" aria-hidden />}
          <p>{bundleName ? <span className="data">{bundleName}</span> : 'Drop a proof bundle here, or'}</p>
          <Button type="button" variant="outline" className="h-9" onClick={() => fileInput.current?.click()} disabled={running}>
            {bundleName ? 'Choose another bundle' : 'Choose a file'}
          </Button>
          <p className="text-sm text-muted-foreground">Bundles are exported from an incident. Verifying one makes no network request.</p>
        </div>
      )}

      {error ? <ErrorNotice error={error} className="mt-5 max-w-xl" onRetry={mode === 'receipt' ? () => void verifyReceipt(id) : undefined} /> : null}

      {running || result || steps.length > 0 ? (
        <div className="mt-6 grid items-start gap-6 lg:grid-cols-[minmax(0,26rem)_minmax(0,1fr)]">
          {receipt ? (
            <ReceiptSlip receipt={receipt} check={check} />
          ) : mode === 'bundle' ? (
            <div className="border border-rule bg-card p-4">
              <p className="label-caps">Bundle</p>
              <p className="data mt-1 break-all">{bundleName}</p>
              <p className="mt-2 text-sm text-muted-foreground">
                {result ? `${plural(result.checked, 'receipt')} checked.` : 'Checking every receipt in the bundle…'}
              </p>
            </div>
          ) : (
            <div />
          )}
          <div className="flex min-w-0 flex-col gap-4">
            {result ? <ResultPanel result={result} what={mode === 'receipt' ? 'This receipt' : `All ${plural(result.checked, 'receipt')} in this bundle`} /> : null}
            <MerkleClimb steps={steps} running={running} />
          </div>
        </div>
      ) : (
        <div className="mt-8 max-w-xl border-l-2 border-rule pl-4 text-muted-foreground">
          <p className="font-medium text-foreground">What this proves</p>
          <p className="mt-1">
            Every decision is a receipt in an append-only log. A proof shows the path from one receipt to the log's root, and the root is signed
            twice: once with Ed25519 and once with ML-DSA-65. If a single byte of the log were changed, the path would no longer reach the signed
            root.
          </p>
        </div>
      )}
    </>
  )
}
