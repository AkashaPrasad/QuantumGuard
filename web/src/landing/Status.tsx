import { useQuery } from '@tanstack/react-query'
import { Check, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { qk, useClient } from '@/app/client-context'
import { Ident } from '@/components/qg/ident'
import { Skeleton } from '@/components/ui/skeleton'
import { detectNativePq } from '@/crypto/native'
import { exactTime } from '@/lib/format'
import { useDocumentTitle } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { PublicLayout } from './PublicLayout'

function Row({ label, ok, children }: { label: string; ok?: boolean | null; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[1.5rem_minmax(0,11rem)_minmax(0,1fr)] items-baseline gap-2 border-b border-border py-2.5 last:border-b-0">
      <span aria-hidden>
        {ok === true ? <Check className="size-4 text-allow" /> : ok === false ? <X className="size-4 text-deny" /> : null}
      </span>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={cn('min-w-0', ok === false && 'text-deny')}>{children}</dd>
    </div>
  )
}

/** Public status page: what this server says about itself, and what this browser can do. */
export default function Status() {
  useDocumentTitle('Status')
  const client = useClient()
  const health = useQuery({ queryKey: ['health'], queryFn: () => client.health(), refetchInterval: 15_000 })
  const meta = useQuery({ queryKey: qk.meta, queryFn: () => client.meta() })
  const directory = useQuery({ queryKey: qk.directory, queryFn: () => client.directory(), refetchInterval: 15_000 })
  const checkpoint = useQuery({ queryKey: qk.checkpoint, queryFn: () => client.checkpoint(), refetchInterval: 15_000 })
  const [native, setNative] = useState<{ mlkem: boolean; mldsa: boolean } | null>(null)
  useEffect(() => {
    void detectNativePq().then(setNative, () => setNative({ mlkem: false, mldsa: false }))
  }, [])
  const wait = <Skeleton className="h-4 w-40" />
  const down = <>Not reachable from this browser.</>

  return (
    <PublicLayout>
      <div className="mx-auto max-w-[760px] px-4 py-12 sm:px-6">
        <p className="label-caps">Status</p>
        <h1 className="mt-2 font-display text-5xl font-normal tracking-normal">What this server says about itself</h1>
        <p className="mt-3 text-muted-foreground">Read from the public routes, which need no session. Refreshes every 15 seconds.</p>

        <h2 className="mt-10 mb-2 text-lg">Service</h2>
        <dl className="border border-rule bg-card px-4" data-testid="status-service">
          <Row label="API" ok={health.isPending ? null : health.data?.status === 'ok'}>
            {health.isPending ? wait : health.data?.status === 'ok' ? 'Answering' : down}
          </Row>
          <Row label="Suite and version" ok={meta.isPending ? null : !!meta.data}>
            {meta.isPending ? wait : meta.data ? <span className="data">{meta.data.suite} · {meta.data.version} · {meta.data.commit.slice(0, 10)}</span> : down}
          </Row>
          <Row label="Device list" ok={directory.isPending ? null : !!directory.data}>
            {directory.isPending ? wait : directory.data ? (
              <span>
                <span className="data">epoch {directory.data.epoch}</span>, signed {exactTime(directory.data.issued_at)}
              </span>
            ) : down}
          </Row>
          <Row label="Evidence log" ok={checkpoint.isPending ? null : !!checkpoint.data}>
            {checkpoint.isPending ? wait : checkpoint.data ? (
              <span className="flex flex-wrap items-center gap-x-2">
                <span className="data">{checkpoint.data.tree_size} entries</span>
                <span>root</span>
                <Ident value={checkpoint.data.root_hash} label="root hash" />
                <span className="text-muted-foreground">at {exactTime(checkpoint.data.ts)}</span>
              </span>
            ) : down}
          </Row>
          <Row label="Policy bundle" ok={meta.isPending ? null : !!meta.data}>
            {meta.isPending ? wait : meta.data ? <Ident value={meta.data.policy_bundle_hash} label="policy bundle hash" /> : down}
          </Row>
        </dl>

        <h2 className="mt-10 mb-2 text-lg">This browser</h2>
        <dl className="border border-rule bg-card px-4" data-testid="status-browser">
          <Row label="Secure context" ok={window.isSecureContext}>
            {window.isSecureContext ? 'Yes. Web Crypto is available for symmetric operations.' : 'No. The built-in JavaScript provider is used for everything; it gives the same results.'}
          </Row>
          <Row label="Native ML-KEM-768" ok={native?.mlkem ?? null}>
            {native ? (native.mlkem ? 'Advertised by this browser.' : 'Not advertised. The audited JavaScript library is used.') : wait}
          </Row>
          <Row label="Native ML-DSA-65" ok={native?.mldsa ?? null}>
            {native ? (native.mldsa ? 'Advertised by this browser.' : 'Not advertised. The audited JavaScript library is used.') : wait}
          </Row>
        </dl>
        <p className="mt-3 text-sm text-muted-foreground">
          Device keys are created with the JavaScript provider in every browser today and stored wrapped under your passphrase. That is a stated limit: they are not
          hardware-backed.
        </p>
      </div>
    </PublicLayout>
  )
}
