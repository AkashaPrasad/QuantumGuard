import { useMemo, useState } from 'react'
import { Chip } from '@/components/qg/chips'
import { Input } from '@/components/ui/input'
import { useDocumentTitle } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { PublicLayout } from './PublicLayout'

// The API reference is rendered from the contract exported by the server (spec/openapi.json),
// bundled at build time. No documentation viewer is loaded from another origin.
interface Operation {
  summary?: string
  description?: string
  tags?: string[]
  security?: unknown[]
  responses?: Record<string, { description?: string }>
}
interface OpenApi {
  info?: { title?: string; version?: string }
  paths?: Record<string, Record<string, Operation>>
}
const specs = import.meta.glob<OpenApi>('../../../spec/openapi.json', { eager: true, import: 'default' })
const spec = Object.values(specs)[0] ?? null
const METHODS = ['get', 'post', 'put', 'patch', 'delete'] as const
const TONE = { get: 'neutral', post: 'accent', put: 'accent', patch: 'caution', delete: 'deny' } as const

export default function Docs() {
  useDocumentTitle('API reference')
  const [q, setQ] = useState('')
  const operations = useMemo(() => {
    const out: { method: (typeof METHODS)[number]; path: string; op: Operation }[] = []
    for (const [path, item] of Object.entries(spec?.paths ?? {})) for (const m of METHODS) if (item[m]) out.push({ method: m, path, op: item[m]! })
    return out
  }, [])
  const needle = q.trim().toLowerCase()
  const shown = operations.filter((o) => !needle || o.path.toLowerCase().includes(needle) || (o.op.summary ?? '').toLowerCase().includes(needle))

  return (
    <PublicLayout>
      <div className="mx-auto max-w-[900px] px-4 py-12 sm:px-6">
        <p className="label-caps">Docs</p>
        <h1 className="mt-2 font-display text-5xl font-normal tracking-normal">API reference</h1>
        <p className="mt-3 max-w-[68ch] text-muted-foreground">
          The console is a client of this API and has no private routes. Every route except the few marked public needs a session, a per-request code and a policy decision.
          The full contract, with shapes and error tables, is <span className="data">spec/API.md</span> in the repository; the protocol is <span className="data">spec/SUITE.md</span>.
        </p>

        {spec ? (
          <>
            <div className="mt-8 flex items-center gap-3">
              <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter routes" aria-label="Filter routes" className="h-9 max-w-xs" />
              <p className="data text-sm text-muted-foreground" aria-live="polite">
                {shown.length} of {operations.length} · v{spec.info?.version}
              </p>
            </div>
            <ul className="mt-3 border border-border" data-testid="docs-routes">
              {shown.map(({ method, path, op }) => {
                const open = Array.isArray(op.security) && op.security.length === 0
                return (
                  <li key={`${method} ${path}`} className="border-b border-border px-3 py-2.5 last:border-b-0">
                    <details>
                      <summary className="flex cursor-pointer flex-wrap items-center gap-2">
                        <Chip tone={TONE[method]} className="w-16 justify-center">
                          {method}
                        </Chip>
                        <code className="data text-[0.8125rem] break-all">{path}</code>
                        {open ? <Chip tone="allow">public</Chip> : null}
                        <span className="text-muted-foreground max-sm:hidden">{op.summary}</span>
                      </summary>
                      <div className="mt-2 pl-[4.5rem] text-sm">
                        {op.description ? <p className="max-w-[68ch] text-muted-foreground">{op.description}</p> : null}
                        <dl className="mt-2 grid grid-cols-[4rem_1fr] gap-x-3 gap-y-0.5">
                          {Object.entries(op.responses ?? {}).map(([code, r]) => (
                            <div key={code} className="contents">
                              <dt className={cn('data', code.startsWith('2') ? 'text-allow' : 'text-muted-foreground')}>{code}</dt>
                              <dd>{r.description}</dd>
                            </div>
                          ))}
                        </dl>
                      </div>
                    </details>
                  </li>
                )
              })}
            </ul>
          </>
        ) : (
          <p className="mt-8 border border-dashed border-rule p-4 text-muted-foreground" data-testid="docs-absent">
            The route list is generated from the server's exported contract when the site is built. This build was made without it; read{' '}
            <span className="data">spec/API.md</span> in the repository.
          </p>
        )}

        <h2 id="notices" className="mt-12 scroll-mt-24 text-lg">
          Third-party notices
        </h2>
        <p className="mt-1.5 max-w-[68ch] text-muted-foreground">
          Every reused component and library is listed with its source, licence and what was changed in <span className="data">THIRD_PARTY_NOTICES.md</span> and{' '}
          <span className="data">web/COMPONENTS.md</span> in the repository.
        </p>
      </div>
    </PublicLayout>
  )
}
