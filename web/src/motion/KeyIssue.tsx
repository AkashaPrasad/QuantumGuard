import { motion } from 'motion/react'
import type { EnrolStep } from '@/client/client'
import { useReducedMotion } from '@/lib/hooks'

const ORDER: EnrolStep[] = ['generating_keys', 'proving_possession', 'certificate_issued', 'sealing_keystore', 'session_started']

const CAPTION: Record<EnrolStep, string> = {
  generating_keys: 'Two key pairs are being created on this device.',
  proving_possession: 'This device is proving it holds both private keys.',
  certificate_issued: 'Public halves are now in the signed directory. Private halves stay here.',
  sealing_keystore: 'Private keys are being locked under your passphrase.',
  session_started: 'Private keys are locked on this device. The directory lists the public halves.',
}

/**
 * Enrolment, drawn: each key pair is a filled square (private) and an outlined
 * square (public). Public halves travel to the directory; private halves drop
 * into the device, which then locks. Every stage is driven by a real event.
 */
export function KeyIssue({ step }: { step: EnrolStep | null }) {
  const reduced = useReducedMotion()
  const stage = step ? ORDER.indexOf(step) + 1 : 0
  const t = reduced ? { duration: 0 } : { duration: 0.55, ease: [0.22, 0.8, 0.3, 1] as const }
  const pairs = [
    { y: 50, label: 'signing' },
    { y: 78, label: 'exchange' },
  ]
  const moved = stage >= 3
  return (
    <figure className="border border-rule bg-card" data-testid="key-issue" data-stage={stage}>
      <svg viewBox="0 0 360 128" className="block w-full" role="img" aria-label={step ? CAPTION[step] : 'Waiting to create keys'}>
        <text x="16" y="20" className="fill-muted-foreground font-mono text-[8px] tracking-[0.08em] uppercase">
          This device
        </text>
        <text x="344" y="20" textAnchor="end" className="fill-muted-foreground font-mono text-[8px] tracking-[0.08em] uppercase">
          Signed directory
        </text>
        <motion.rect
          x="16"
          y="28"
          width="112"
          height="76"
          fill="none"
          strokeWidth={stage >= 4 ? 2 : 1}
          className={stage >= 4 ? 'stroke-foreground' : 'stroke-rule'}
          strokeDasharray={stage >= 4 ? '0' : '4 3'}
        />
        <rect x="232" y="28" width="112" height="76" fill="none" strokeWidth="1" className="stroke-rule" />
        {/* The exchange: visible only while possession is being proved. */}
        <motion.line
          x1="132"
          x2="228"
          y1="66"
          y2="66"
          strokeWidth="1.5"
          strokeDasharray="5 5"
          className="stroke-primary"
          initial={false}
          animate={{ opacity: stage === 2 ? 1 : 0, strokeDashoffset: stage === 2 && !reduced ? [0, -40] : 0 }}
          transition={stage === 2 && !reduced ? { strokeDashoffset: { repeat: Infinity, duration: 0.9, ease: 'linear' } } : t}
        />
        {pairs.map((p, i) => (
          <g key={p.label}>
            {/* private half */}
            <motion.rect
              width="12"
              height="12"
              y={p.y}
              className="fill-foreground"
              initial={false}
              animate={{ x: moved ? 52 + i * 22 : 166, opacity: stage >= 1 ? 1 : 0, scale: stage >= 1 ? 1 : 0.4 }}
              transition={{ ...t, delay: reduced ? 0 : i * 0.12 }}
            />
            {/* public half */}
            <motion.rect
              width="12"
              height="12"
              y={p.y}
              fill="none"
              strokeWidth="1.5"
              className="stroke-primary"
              initial={false}
              animate={{ x: moved ? 270 + i * 22 : 182, opacity: stage >= 1 ? 1 : 0, scale: stage >= 1 ? 1 : 0.4 }}
              transition={{ ...t, delay: reduced ? 0 : i * 0.12 }}
            />
            <motion.text
              x="180"
              y={p.y + 24}
              textAnchor="middle"
              className="fill-muted-foreground font-mono text-[7px]"
              initial={false}
              animate={{ opacity: stage >= 1 && !moved ? 1 : 0 }}
              transition={t}
            >
              {p.label}
            </motion.text>
          </g>
        ))}
        <motion.text
          x="72"
          y="96"
          textAnchor="middle"
          className="fill-foreground font-mono text-[7px] tracking-[0.08em] uppercase"
          initial={false}
          animate={{ opacity: stage >= 4 ? 1 : 0 }}
          transition={t}
        >
          locked
        </motion.text>
        <motion.text
          x="288"
          y="96"
          textAnchor="middle"
          className="fill-primary font-mono text-[7px] tracking-[0.08em] uppercase"
          initial={false}
          animate={{ opacity: moved ? 1 : 0 }}
          transition={t}
        >
          published
        </motion.text>
      </svg>
      <figcaption className="border-t border-border px-3 py-2 text-sm text-muted-foreground" aria-live="polite">
        {step ? CAPTION[step] : 'Nothing has been created yet.'}
      </figcaption>
    </figure>
  )
}
