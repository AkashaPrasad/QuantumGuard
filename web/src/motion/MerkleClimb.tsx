import { Check, FileText, Signature, X } from 'lucide-react'
import type { ReactNode } from 'react'
import type { VerifyStep } from '@/client/client'
import { shortId } from '@/lib/format'
import { useReducedMotion } from '@/lib/hooks'
import { cn } from '@/lib/utils'

function Rung({ ok, icon, title, detail, enter }: { ok: boolean | null; icon: ReactNode; title: string; detail?: ReactNode; enter: boolean }) {
  return (
    <li className={cn('relative flex items-start gap-3 pb-3 pl-0 last:pb-0', enter && 'animate-enter')}>
      <span
        className={cn(
          'z-10 mt-0.5 flex size-6 shrink-0 items-center justify-center border bg-card',
          ok === false ? 'border-deny text-deny' : ok === true ? 'border-allow text-allow' : 'border-primary text-primary',
        )}
        aria-hidden
      >
        {icon}
      </span>
      <div className="min-w-0 flex-1">
        <p className={cn('font-medium', ok === false && 'text-deny')}>{title}</p>
        {detail ? <p className="data truncate text-[0.75rem] text-muted-foreground">{detail}</p> : null}
      </div>
    </li>
  )
}

/**
 * Verification, drawn as a climb: the receipt at the bottom, one rung per tree
 * level, the signed root and its two signatures at the top. Each rung appears
 * when the verifier on this device has actually finished that step.
 * With reduced motion the same steps are listed top to bottom without movement.
 */
export function MerkleClimb({ steps, running }: { steps: VerifyStep[]; running: boolean }) {
  const reduced = useReducedMotion()
  return (
    <div className="border border-rule bg-card p-4" data-testid="verify-steps">
      <p className="label-caps mb-3">{reduced ? 'Steps checked on this device' : 'Proof, from the receipt up to the signed root'}</p>
      <ol
        aria-live="polite"
        className={cn(
          'relative flex before:absolute before:top-2 before:bottom-2 before:left-[0.72rem] before:w-px before:bg-rule',
          reduced ? 'flex-col' : 'flex-col-reverse',
        )}
      >
        {steps.map((s, i) => {
          const key = `${s.kind}-${i}`
          if (s.kind === 'receipt')
            return <Rung key={key} enter={!reduced} ok={null} icon={<FileText className="size-3.5" />} title={`Receipt hashed as log entry #${s.receipt.leaf_index}`} detail={shortId(s.leaf_hash, 10)} />
          if (s.kind === 'node')
            return (
              <Rung
                key={key}
                enter={!reduced}
                ok={null}
                icon={<span className="data text-[0.625rem]">{s.level}</span>}
                title={`Level ${s.level}: combined with the ${s.side} neighbour`}
                detail={`${shortId(s.hash, 8)}  +  ${shortId(s.sibling, 8)}`}
              />
            )
          if (s.kind === 'root')
            return (
              <Rung
                key={key}
                enter={!reduced}
                ok={s.ok}
                icon={s.ok ? <Check className="size-3.5" /> : <X className="size-3.5" />}
                title={s.ok ? 'Computed root matches the signed checkpoint' : 'Computed root does not match the signed checkpoint'}
                detail={s.ok ? shortId(s.signed, 10) : `computed ${shortId(s.computed, 6)}  signed ${shortId(s.signed, 6)}`}
              />
            )
          return (
            <Rung
              key={key}
              enter={!reduced}
              ok={s.ok}
              icon={s.ok ? <Signature className="size-3.5" /> : <X className="size-3.5" />}
              title={`${s.alg === 'ed25519' ? 'Ed25519' : 'ML-DSA-65'} signature on the checkpoint ${s.ok ? 'is valid' : 'is not valid'}`}
            />
          )
        })}
        {steps.length === 0 ? <li className="pl-9 text-muted-foreground">{running ? 'Fetching the proof…' : 'Nothing checked yet.'}</li> : null}
      </ol>
    </div>
  )
}
