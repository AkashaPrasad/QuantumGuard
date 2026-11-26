import { ArrowRight, Check, GitBranch, Minus } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Link, useLocation } from 'react-router'
import type { EnrolStep, VerifyStep } from '@/client/client'
import type { Receipt } from '@/client/types'
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion'
import { Button } from '@/components/ui/button'
import { useDocumentTitle, useReducedMotion } from '@/lib/hooks'
import { cn } from '@/lib/utils'
import { EncryptChunks } from '@/motion/EncryptChunks'
import { KeyIssue } from '@/motion/KeyIssue'
import { MerkleClimb } from '@/motion/MerkleClimb'
import { RevokeCut } from '@/motion/RevokeCut'
import { WrapBeams } from '@/motion/WrapBeams'
import { LIMITS, PROBLEMS, PRODUCT, QUESTIONS, SUITE, ZONES } from './content'
import { Lattice } from './Lattice'
import { LINKS } from './links'
import { PublicLayout } from './PublicLayout'

// Measured numbers are read from bench/latest.json when the site is built. Absent file: the section says so.
const benchFiles = import.meta.glob<Record<string, unknown>>('../../../bench/latest.json', { eager: true, import: 'default' })
const bench = Object.values(benchFiles)[0] ?? null

/** Counts 0..last, one step per interval, starting when the element scrolls into view. */
function useSequence(last: number, intervalMs: number) {
  const ref = useRef<HTMLDivElement>(null)
  const reduced = useReducedMotion()
  const [n, setN] = useState(reduced ? last : -1)
  useEffect(() => {
    if (reduced) return setN(last)
    const el = ref.current
    if (!el) return
    let timer: ReturnType<typeof setInterval> | undefined
    const io = new IntersectionObserver(
      ([entry]) => {
        if (!entry?.isIntersecting || timer) return
        timer = setInterval(() => setN((v) => (v >= last ? (clearInterval(timer), v) : v + 1)), intervalMs)
      },
      { threshold: 0.5 },
    )
    io.observe(el)
    return () => {
      io.disconnect()
      clearInterval(timer)
    }
  }, [last, intervalMs, reduced])
  return { ref, n }
}

function Section({ id, index, label, title, lead, children, className }: { id: string; index: string; label: string; title: string; lead?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section id={id} aria-labelledby={`${id}-title`} className={cn('scroll-mt-24 border-t border-rule', className)}>
      <div className="mx-auto grid max-w-[1120px] grid-cols-[minmax(0,1fr)] gap-x-10 gap-y-6 px-4 py-14 sm:px-6 lg:grid-cols-[18rem_minmax(0,1fr)] lg:py-20">
        <div className="lg:sticky lg:top-24 lg:self-start">
          <p className="label-caps">
            <span className="text-primary">{index}</span> · {label}
          </p>
          <h2 id={`${id}-title`} className="mt-2 font-display text-4xl leading-[1.05] font-normal tracking-normal">
            {title}
          </h2>
          {lead ? <p className="mt-3 text-muted-foreground">{lead}</p> : null}
        </div>
        <div className="min-w-0">{children}</div>
      </div>
    </section>
  )
}

const ENROL_ORDER: EnrolStep[] = ['generating_keys', 'proving_possession', 'certificate_issued', 'sealing_keystore', 'session_started']
const DEMO_DEVICES = [
  { device_id: 'a', device_name: 'Laptop', owner: 'you' },
  { device_id: 'b', device_name: 'Phone', owner: 'you' },
  { device_id: 'c', device_name: 'Workstation', owner: 'a colleague' },
]
const SAMPLE_RECEIPT = { leaf_index: 412 } as Receipt
const DEMO_PROOF: VerifyStep[] = [
  { kind: 'receipt', receipt: SAMPLE_RECEIPT, leaf_hash: 'k3Jx0QmV7aT1uYp9bLwE4hZc' },
  { kind: 'node', level: 1, hash: 'Pq8sXw2NfL0vRt6yGmA3dKjU', sibling: 'Zb5cHn1MeO7iWq4xTsV9rYlD', side: 'right' },
  { kind: 'node', level: 2, hash: 'Ty4uIo9PaS2dFg6hJk8lZx0C', sibling: 'Vb3nMq7WeR5tYu1iOp4aSd6F', side: 'left' },
  { kind: 'node', level: 3, hash: 'Gh8jKl2ZxC6vBn0mQw4eRt7Y', sibling: 'Ui1oPa5sDf9gHj3kLz7xCv2B', side: 'right' },
  { kind: 'root', computed: 'Nm6qWe0rTy4uIo8pAs2dFg5H', signed: 'Nm6qWe0rTy4uIo8pAs2dFg5H', ok: true },
  { kind: 'signature', alg: 'ed25519', ok: true },
  { kind: 'signature', alg: 'mldsa', ok: true },
]

function Step({ n, title, body, children }: { n: number; title: string; body: string; children: ReactNode }) {
  return (
    <li className="grid gap-4 border-t border-border py-6 first:border-t-0 first:pt-0 md:grid-cols-[minmax(0,15rem)_minmax(0,1fr)] md:gap-8">
      <div>
        <p className="data text-primary">0{n}</p>
        <h3 className="mt-1 text-lg">{title}</h3>
        <p className="mt-1.5 text-muted-foreground">{body}</p>
      </div>
      <div className="min-w-0">{children}</div>
    </li>
  )
}

function HowItWorks() {
  const enrol = useSequence(ENROL_ORDER.length - 1, 900)
  const protect = useSequence(9, 380)
  const revoke = useSequence(0, 300)
  const prove = useSequence(DEMO_PROOF.length - 1, 420)
  const chunks = 6
  return (
    <ol>
      <Step n={1} title="Enrol a device" body="The device creates two key pairs. The public halves go into a signed directory; the private halves never leave it.">
        <div ref={enrol.ref}>
          <KeyIssue step={enrol.n >= 0 ? ENROL_ORDER[enrol.n]! : null} />
        </div>
      </Step>
      <Step n={2} title="Protect a file" body="The file is encrypted block by block on the device, and its key is wrapped separately for every device allowed to open it.">
        <div ref={protect.ref} className="grid gap-3">
          <div className="border border-rule bg-card p-4">
            <EncryptChunks name="Trial-protocol-draft-7.pdf" chunk={Math.max(0, Math.min(protect.n, chunks))} chunks={chunks} done={protect.n >= chunks} />
          </div>
          <div className="border border-rule bg-card p-4">
            <WrapBeams targets={DEMO_DEVICES} wrapped={new Set(DEMO_DEVICES.slice(0, Math.max(0, protect.n - chunks)).map((d) => d.device_id))} />
          </div>
        </div>
      </Step>
      <Step n={3} title="Lose a device" body="Report it from another device. Its key slots and sessions are deleted and a new device list is signed, in one transaction.">
        <div ref={revoke.ref} className="min-h-28">
          {revoke.n >= 0 ? <RevokeCut deviceName="Phone" epoch={15} slotsDeleted={7} /> : null}
        </div>
      </Step>
      <Step n={4} title="Prove what happened" body="Every decision is a receipt in a log whose root is signed twice. Anyone can follow the proof from a receipt to that root.">
        <div ref={prove.ref}>
          <MerkleClimb steps={DEMO_PROOF.slice(0, prove.n + 1)} running={false} />
        </div>
      </Step>
      <li className="pt-2 text-sm text-muted-foreground">These four figures are the ones used inside the console, shown here with sample values.</li>
    </ol>
  )
}

function Architecture() {
  const [open, setOpen] = useState<string>('backend:Key release')
  const current = ZONES.flatMap((z) => z.parts.map((p) => ({ key: `${z.id}:${p[0]}`, zone: z.title, name: p[0], text: p[1] }))).find((p) => p.key === open)
  return (
    <div>
      <div className="grid gap-3 lg:grid-cols-[1fr_0.8fr_1.6fr]">
        {ZONES.map((z) => (
          <div key={z.id} className={cn('border bg-card p-3', z.id === 'edge' ? 'border-dashed border-rule' : 'border-rule')}>
            <p className="label-caps">{z.title}</p>
            <p className="mt-1 mb-3 text-sm text-muted-foreground">{z.trust}</p>
            <div className="flex flex-wrap gap-1.5">
              {z.parts.map((p) => {
                const key = `${z.id}:${p[0]}`
                return (
                  <button
                    key={key}
                    type="button"
                    aria-pressed={open === key}
                    onClick={() => setOpen(key)}
                    className={cn('h-9 border px-2.5 text-left', open === key ? 'border-primary bg-accent text-accent-foreground' : 'border-input bg-background hover:bg-muted')}
                  >
                    {p[0]}
                  </button>
                )
              })}
            </div>
          </div>
        ))}
      </div>
      <div className="mt-3 border-l-2 border-primary bg-card p-4" aria-live="polite">
        <p className="label-caps">
          {current?.zone} · {current?.name}
        </p>
        <p className="mt-1 text-base">{current?.text}</p>
      </div>
      <p className="mt-3 text-sm text-muted-foreground">Choose a component to read what it does. The edge is drawn dashed because it is treated as untrusted.</p>
    </div>
  )
}

type Bench = Record<string, unknown>
const num = (v: unknown, ...path: string[]): number | null => {
  let cur: unknown = v
  for (const k of path) cur = cur && typeof cur === 'object' ? (cur as Bench)[k] : undefined
  return typeof cur === 'number' ? cur : null
}
const fmt = (n: number | null, digits = 1) => (n === null ? 'not measured' : n >= 100 ? n.toFixed(0) : n.toFixed(n < 1 ? 3 : digits))

function Performance() {
  if (!bench) {
    return (
      <p className="border border-dashed border-rule p-4 text-muted-foreground" data-testid="bench-absent">
        Measured numbers are built into this page from <span className="data">bench/latest.json</span> when the site is built. This build was made before the
        benchmark ran, so no numbers are shown rather than estimated ones.
      </p>
    )
  }
  const b = bench as Bench
  const str = (k: string) => (typeof b[k] === 'string' ? (b[k] as string) : null)
  const machine = b.machine && typeof b.machine === 'object' ? (b.machine as Bench) : {}
  // The headline rows: what was measured, against the target set before building.
  const rows: { what: string; value: number | null; unit: string; target: number | null }[] = [
    { what: 'Time to enforce a revocation (p95)', value: num(b, 'time_to_enforce_ms', 'p95'), unit: 'ms', target: num(b, 'targets', 'time_to_enforce_ms') },
    { what: 'Policy decision (p95)', value: num(b, 'policy_decision_ms', 'p95'), unit: 'ms', target: num(b, 'targets', 'policy_decision_p95_ms') },
    { what: 'Key slot release (p95)', value: num(b, 'slot_release_ms', 'p95'), unit: 'ms', target: num(b, 'targets', 'slot_release_p95_ms') },
    { what: 'Added latency per request, against an unprotected route (p95)', value: num(b, 'added_latency_ms', 'p95'), unit: 'ms', target: num(b, 'targets', 'added_latency_p95_ms') },
    { what: 'Cold start', value: num(b, 'cold_start_s'), unit: 's', target: num(b, 'targets', 'cold_start_s') },
    { what: 'Container image, unpacked', value: num(b, 'image_size_mb', 'value'), unit: 'MB', target: num(b, 'targets', 'image_size_mb') },
  ]
  const more: [string, string][] = [
    ['Session handshake (median)', `${fmt(num(b, 'session_handshake_ms', 'median'))} ms`],
    ['Protect a file', `${fmt(num(b, 'throughput_mb_s', 'protect'), 0)} MB/s`],
    ['Open a file', `${fmt(num(b, 'throughput_mb_s', 'open'), 0)} MB/s`],
    ['Hybrid key exchange, encapsulate (median)', `${fmt(num(b, 'crypto_ms', 'xwing_encaps', 'median'))} ms`],
    ['ML-DSA-65 sign / verify (median)', `${fmt(num(b, 'crypto_ms', 'mldsa_sign', 'median'))} / ${fmt(num(b, 'crypto_ms', 'mldsa_verify', 'median'))} ms`],
    ['Signing 1,000 receipts as one checkpoint', `${fmt(num(b, 'checkpoint_signing_ms_per_1000_receipts', 'batched'))} ms`],
    ['Size added per file', `${fmt(num(b, 'throughput_mb_s', 'size_overhead', 'per_file_bytes'), 0)} bytes per 16 MiB`],
    ['Size added per request', `${fmt(num(b, 'throughput_mb_s', 'size_overhead', 'per_request_header_bytes'), 0)} bytes`],
  ]
  return (
    <div data-testid="bench-present">
      <div className="overflow-x-auto border border-border">
        <table className="w-full min-w-[30rem] text-left">
          <thead>
            <tr className="border-b border-border">
              <th className="label-caps p-3 font-medium">Measured</th>
              <th className="label-caps p-3 text-right font-medium">Result</th>
              <th className="label-caps p-3 text-right font-medium">Target</th>
              <th className="label-caps p-3 font-medium">Met</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const met = r.value !== null && r.target !== null ? r.value <= r.target : null
              return (
                <tr key={r.what} className="border-b border-border last:border-b-0">
                  <th scope="row" className="p-3 align-top font-normal">
                    {r.what}
                  </th>
                  <td className="data p-3 text-right align-top font-medium whitespace-nowrap">
                    {fmt(r.value)} {r.value !== null ? r.unit : ''}
                  </td>
                  <td className="data p-3 text-right align-top whitespace-nowrap text-muted-foreground">{r.target !== null ? `under ${r.target} ${r.unit}` : ''}</td>
                  <td className="p-3 align-top">
                    {met === null ? (
                      <span className="text-muted-foreground">Not measured</span>
                    ) : met ? (
                      <span className="inline-flex items-center gap-1 text-allow">
                        <Check className="size-4" aria-hidden />
                        Yes
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-deny">
                        <Minus className="size-4" aria-hidden />
                        No
                      </span>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      <dl className="mt-6 grid grid-cols-[minmax(0,1fr)] gap-x-8 sm:grid-cols-[repeat(2,minmax(0,1fr))]">
        {more.map(([k, v]) => (
          <div key={k} className="flex items-baseline justify-between gap-4 border-b border-border py-2">
            <dt className="min-w-0 text-muted-foreground">{k}</dt>
            <dd className="data shrink-0 font-medium whitespace-nowrap">{v}</dd>
          </div>
        ))}
      </dl>
      <p className="mt-4 text-sm text-muted-foreground">
        Measured by <span className="data">make bench</span>
        {str('commit') ? (
          <>
            {' '}
            at commit <span className="data">{str('commit')!.slice(0, 10)}</span>
          </>
        ) : null}
        {str('generated_at') ? <>, {str('generated_at')!.slice(0, 10)}</> : null}
        {typeof machine.platform === 'string' ? <>, on {String(machine.platform)} with {String(machine.cpu_count ?? '?')} cores</> : null}. A target that was missed is shown as
        missed. Run it yourself to compare.
      </p>
    </div>
  )
}

/** The public page. Static: no API calls, no third-party origins. Flow: build plan 12.5. */
export default function Landing({ section }: { section?: string }) {
  useDocumentTitle('')
  const location = useLocation()
  useEffect(() => {
    const id = section ?? location.hash.replace('#', '')
    if (!id) return
    const el = document.getElementById(id)
    el?.scrollIntoView({ block: 'start' })
  }, [section, location.hash])

  return (
    <PublicLayout>
      <section className="bg-lattice">
        <div className="mx-auto grid max-w-[1120px] items-center gap-8 px-4 py-14 sm:px-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)] lg:py-24">
          <div className="bg-background py-2 lg:pr-6">
            <p className="label-caps">Post-quantum file protection · zero-trust device control</p>
            <h1 className="mt-4 font-display text-6xl leading-[0.98] font-normal tracking-normal sm:text-7xl">
              Lose the laptop.
              <br />
              <em>Keep the files.</em>
            </h1>
            <p className="mt-6 max-w-[58ch] text-base text-foreground/85">
              QuantumGuard encrypts files on the device with hybrid post-quantum keys and decides every key release at the moment of use. Report a device lost and it is cut off in
              milliseconds, with a list of what it could have opened and a record anyone can verify.
            </p>
            <div className="mt-7 flex flex-wrap gap-2">
              <Button asChild size="lg" className="h-11 px-5" data-testid="hero-launch">
                <Link to="/app">
                  Launch console
                  <ArrowRight aria-hidden />
                </Link>
              </Button>
              {LINKS.repo ? (
                <Button asChild size="lg" variant="outline" className="h-11 px-5" data-testid="hero-github">
                  <a href={LINKS.repo} rel="noreferrer">
                    <GitBranch aria-hidden />
                    View on GitHub
                  </a>
                </Button>
              ) : null}
            </div>
          </div>
          <div className="relative">
            <Lattice className="aspect-square w-full" />
            <div className="border border-rule bg-card p-4 lg:absolute lg:right-0 lg:-bottom-6 lg:max-w-xs">
              <p className="label-caps">The claim you can test</p>
              <ul className="mt-2 flex flex-col gap-1.5 text-sm">
                {['No request from a revoked device receives key material.', 'Every file it ever received a key for is listed and re-keyed.', 'Every decision verifies offline with public keys only.'].map((c) => (
                  <li key={c} className="flex gap-2">
                    <Check className="mt-0.5 size-4 shrink-0 text-allow" aria-hidden />
                    {c}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </section>

      <Section id="problem" index="01" label="The problem" title="Four things that go wrong the day a device goes missing">
        <ul className="grid gap-x-8 gap-y-6 sm:grid-cols-2">
          {PROBLEMS.map((p) => (
            <li key={p.title} className="border-t-2 border-foreground pt-3">
              <h3 className="text-lg">{p.title}</h3>
              <p className="mt-1.5 text-muted-foreground">{p.body}</p>
            </li>
          ))}
        </ul>
      </Section>

      <Section id="how-it-works" index="02" label="How it works" title="Enrol, protect, lose, prove" lead="Each figure moves when the real event happens in the console.">
        <HowItWorks />
      </Section>

      <Section id="product" index="03" label="Product" title="What is in the prototype" lead="Every feature here is also a security control. Billing, public sign-up and password resets are left out on purpose.">
        <div className="grid gap-x-8 gap-y-8 sm:grid-cols-2">
          {PRODUCT.map((g) => (
            <div key={g.group}>
              <h3 className="label-caps border-b border-rule pb-2 text-foreground">{g.group}</h3>
              <dl className="mt-3 flex flex-col gap-3">
                {g.items.map(([t, d]) => (
                  <div key={t}>
                    <dt className="font-medium">{t}</dt>
                    <dd className="text-muted-foreground">{d}</dd>
                  </div>
                ))}
              </dl>
            </div>
          ))}
        </div>
      </Section>

      <Section id="architecture" index="04" label="Architecture" title="Three zones, one of them untrusted" lead="The same container runs with docker compose on your own machine and behind the public demo.">
        <Architecture />
      </Section>

      <Section id="security" index="05" label="Security" title="Suite QG-1" lead="One fixed suite. There is no negotiation, so there is nothing to downgrade.">
        <div className="overflow-x-auto border border-border">
          <table className="w-full min-w-[36rem] text-left">
            <thead>
              <tr className="border-b border-border">
                <th className="label-caps p-3 font-medium">Job</th>
                <th className="label-caps p-3 font-medium">Algorithm</th>
                <th className="label-caps p-3 font-medium">Against a quantum computer</th>
              </tr>
            </thead>
            <tbody>
              {SUITE.map(([job, alg, status]) => (
                <tr key={job} className="border-b border-border last:border-b-0">
                  <th scope="row" className="p-3 align-top font-medium">
                    {job}
                  </th>
                  <td className="data p-3 align-top text-[0.8125rem]">{alg}</td>
                  <td className="p-3 align-top text-muted-foreground">{status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-6 max-w-[68ch]">
          <h3 className="text-lg">Why hybrid</h3>
          <p className="mt-1.5 text-muted-foreground">
            ML-KEM-768 is standardised but young. X25519 is old and well studied but falls to a large quantum computer. Combined in the published X-Wing construction, a file key is safe
            unless both are broken. We wrote no primitives: the library provides them, our code composes them and passes the construction's official test vectors.
          </p>
        </div>
      </Section>

      <Section id="limits" index="06" label="Limits" title="What we do not protect" lead="The limits are part of the product. They are the same list as in the threat model.">
        <ul className="flex flex-col">
          {LIMITS.map((l) => (
            <li key={l} className="flex gap-3 border-b border-border py-3 first:pt-0 last:border-b-0">
              <Minus className="mt-1 size-4 shrink-0 text-deny" aria-hidden />
              <span className="text-base">{l}</span>
            </li>
          ))}
        </ul>
      </Section>

      <Section id="performance" index="07" label="Measured performance" title="Numbers from this build">
        <Performance />
      </Section>

      <Section id="questions" index="08" label="Questions" title="Asked plainly">
        <Accordion type="single" collapsible className="border-t border-border">
          {QUESTIONS.map(([q, a], i) => (
            <AccordionItem key={q} value={`q${i}`} className="border-b border-border">
              <AccordionTrigger className="py-3.5 text-base">{q}</AccordionTrigger>
              <AccordionContent className="max-w-[68ch] pb-4 text-sm text-muted-foreground">{a}</AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
        <div className="mt-10 flex flex-wrap items-center justify-between gap-4 border border-rule bg-card p-5">
          <p className="font-display text-3xl">See it cut a device off.</p>
          <Button asChild size="lg" className="h-11 px-5">
            <Link to="/app">
              Launch console
              <ArrowRight aria-hidden />
            </Link>
          </Button>
        </div>
      </Section>
    </PublicLayout>
  )
}
