import { motion } from 'motion/react'
import { useReducedMotion } from '@/lib/hooks'

export type PulsePhase = 'waiting' | 'up' | 'down' | 'back'

export interface PulseState {
  /** Signed device list epoch and evidence log size: the durable state a restart must not lose. */
  epoch: number | null
  logSize: number | null
}

const CAPTION: Record<PulsePhase, string> = {
  waiting: 'Checking the server.',
  up: 'The server is answering. This page checks it every second.',
  down: 'The server is not answering. Nothing is being released while it is down.',
  back: 'The server is back. Its signed device list and evidence log are compared with before the outage.',
}

/**
 * The server's heartbeat, drawn: a pulse travels from this browser to the server every second while it answers.
 * When it stops answering the link breaks and the server box goes dark; when it answers again the durable state
 * (device list epoch, evidence log size) is compared with what it was before. Every stage is a real health check.
 */
export function ServerPulse({ phase, before, after, downSeconds }: {
  phase: PulsePhase
  before: PulseState
  after: PulseState
  downSeconds: number | null
}) {
  const reduced = useReducedMotion()
  const t = reduced ? { duration: 0 } : { duration: 0.5, ease: [0.22, 0.8, 0.3, 1] as const }
  const alive = phase === 'up' || phase === 'back'
  const kept = phase === 'back' && before.epoch !== null && after.epoch === before.epoch &&
    before.logSize !== null && after.logSize !== null && after.logSize >= before.logSize
  return (
    <figure className="border border-rule bg-card" data-testid="server-pulse" data-phase={phase}>
      <svg viewBox="0 0 360 128" className="block w-full" role="img" aria-label={CAPTION[phase]}>
        <text x="16" y="20" className="fill-muted-foreground font-mono text-[8px] tracking-[0.08em] uppercase">This browser</text>
        <text x="344" y="20" textAnchor="end" className="fill-muted-foreground font-mono text-[8px] tracking-[0.08em] uppercase">Server</text>
        <rect x="16" y="28" width="96" height="76" fill="none" strokeWidth="1" className="stroke-rule" />
        {/* the server: solid while it answers, dashed and dark while it does not */}
        <motion.rect
          x="248" y="28" width="96" height="76" strokeWidth={alive ? 2 : 1}
          className={phase === 'down' ? 'fill-deny/10 stroke-deny' : 'fill-none stroke-foreground'}
          strokeDasharray={phase === 'down' ? '4 3' : '0'}
          initial={false}
          animate={{ opacity: phase === 'waiting' ? 0.4 : 1, x: phase === 'down' && !reduced ? [248, 244, 252, 246, 250, 248] : 248 }}
          transition={phase === 'down' && !reduced ? { x: { duration: 0.5 } } : t}
        />
        <motion.text
          x="296" y="72" textAnchor="middle" className={phase === 'down' ? 'fill-deny font-mono text-[11px]' : 'fill-foreground font-mono text-[11px]'}
          initial={false} animate={{ opacity: 1 }} transition={t}
        >
          {phase === 'down' ? 'not answering' : phase === 'back' ? 'restarted' : phase === 'up' ? 'answering' : '…'}
        </motion.text>
        {/* the link: a travelling pulse while alive, a broken red line while down */}
        <line x1="116" x2="244" y1="66" y2="66" strokeWidth="1" className={phase === 'down' ? 'stroke-deny' : 'stroke-rule'}
          strokeDasharray={phase === 'down' ? '3 6' : '0'} />
        {alive && !reduced ? (
          <motion.circle
            r="4" cy="66" className={phase === 'back' ? 'fill-allow' : 'fill-primary'}
            initial={{ cx: 116, opacity: 0 }}
            animate={{ cx: [116, 244], opacity: [0, 1, 1, 0] }}
            transition={{ duration: 1, repeat: Infinity, ease: 'easeInOut' }}
          />
        ) : null}
        {phase === 'down' ? (
          <motion.g initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={t}>
            <line x1="172" x2="188" y1="58" y2="74" strokeWidth="2.5" className="stroke-deny" />
            <line x1="188" x2="172" y1="58" y2="74" strokeWidth="2.5" className="stroke-deny" />
          </motion.g>
        ) : null}
        {/* durable state carried across the restart */}
        <text x="64" y="58" textAnchor="middle" className="fill-muted-foreground font-mono text-[7px] uppercase">device list</text>
        <text x="64" y="70" textAnchor="middle" className="fill-foreground font-mono text-[10px]" data-testid="pulse-epoch">
          {before.epoch === null ? '–' : `epoch ${before.epoch}`}{phase === 'back' && after.epoch !== null ? ` → ${after.epoch}` : ''}
        </text>
        <text x="64" y="84" textAnchor="middle" className="fill-muted-foreground font-mono text-[7px] uppercase">evidence log</text>
        <text x="64" y="96" textAnchor="middle" className="fill-foreground font-mono text-[10px]" data-testid="pulse-log">
          {before.logSize === null ? '–' : `${before.logSize}`}{phase === 'back' && after.logSize !== null ? ` → ${after.logSize}` : ''}
        </text>
        {phase === 'back' ? (
          <motion.text
            x="180" y="118" textAnchor="middle" className={kept ? 'fill-allow font-mono text-[9px]' : 'fill-deny font-mono text-[9px]'}
            initial={{ opacity: 0, y: 124 }} animate={{ opacity: 1, y: 118 }} transition={t} data-testid="pulse-verdict"
          >
            {kept ? `state intact after restart${downSeconds !== null ? ` (down ${downSeconds} s)` : ''}` : 'state changed across the restart'}
          </motion.text>
        ) : null}
      </svg>
      <figcaption className="border-t border-rule px-3 py-2 text-sm text-muted-foreground" aria-live="polite">{CAPTION[phase]}</figcaption>
    </figure>
  )
}
