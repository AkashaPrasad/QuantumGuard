import { motion } from 'motion/react'
import { useReducedMotion } from '@/lib/hooks'

/**
 * Revocation, drawn: the line from the key slots to the lost device is cut,
 * the slots held for it dissolve, and the directory epoch ticks up.
 * Rendered only after the revoke transaction has answered.
 */
export function RevokeCut({ deviceName, epoch, slotsDeleted }: { deviceName: string; epoch: number; slotsDeleted: number }) {
  const reduced = useReducedMotion()
  const t = (delay: number, duration = 0.45) => (reduced ? { duration: 0 } : { delay, duration, ease: [0.22, 0.8, 0.3, 1] as const })
  return (
    <figure className="border border-rule bg-card" data-testid="revoke-cut">
      <svg
        viewBox="0 0 360 104"
        className="block w-full"
        role="img"
        aria-label={`The key slots for ${deviceName} were deleted and the directory moved to epoch ${epoch}.`}
      >
        <text x="16" y="18" className="fill-muted-foreground font-mono text-[8px] tracking-[0.08em] uppercase">
          Key slots on the server
        </text>
        <text x="344" y="18" textAnchor="end" className="fill-muted-foreground font-mono text-[8px] tracking-[0.08em] uppercase">
          {deviceName.length > 26 ? `${deviceName.slice(0, 25)}…` : deviceName}
        </text>
        {/* the slots held for this device */}
        {[0, 1, 2].map((i) => (
          <motion.rect
            key={i}
            x={20 + i * 20}
            y={38}
            width="14"
            height="20"
            fill="none"
            strokeWidth="1.5"
            className="stroke-foreground"
            initial={{ opacity: 1, strokeDasharray: '0 0' }}
            animate={{ opacity: 0.18, strokeDasharray: '2 3' }}
            transition={t(0.35 + i * 0.1)}
          />
        ))}
        {/* the beam, in two halves that pull apart */}
        <motion.line y1="48" y2="48" x1="86" strokeWidth="1.5" className="stroke-deny" initial={{ x2: 180 }} animate={{ x2: 164 }} transition={t(0.1)} />
        <motion.line y1="48" y2="48" x2="262" strokeWidth="1.5" className="stroke-deny" initial={{ x1: 180 }} animate={{ x1: 196 }} transition={t(0.1)} />
        <motion.g initial={{ opacity: 0, scale: 0.4 }} animate={{ opacity: 1, scale: 1 }} transition={t(0.2, 0.3)} style={{ transformOrigin: '180px 48px' }}>
          <line x1="174" y1="42" x2="186" y2="54" strokeWidth="2" className="stroke-deny" />
          <line x1="186" y1="42" x2="174" y2="54" strokeWidth="2" className="stroke-deny" />
        </motion.g>
        {/* the device */}
        <rect x="270" y="32" width="50" height="32" fill="none" strokeWidth="1.5" className="stroke-muted-foreground" strokeDasharray="3 3" />
        <line x1="262" y1="68" x2="328" y2="68" strokeWidth="1.5" className="stroke-muted-foreground" />
        <text x="295" y="52" textAnchor="middle" className="fill-deny font-mono text-[7px] tracking-[0.08em] uppercase">
          revoked
        </text>
        {/* epoch counter */}
        <text x="16" y="90" className="fill-muted-foreground font-mono text-[8px]">
          directory epoch
        </text>
        <motion.text x="92" y="90" className="fill-muted-foreground font-mono text-[8px]" initial={{ opacity: 1, y: 90 }} animate={{ opacity: 0, y: 82 }} transition={t(0.55, 0.3)}>
          {epoch - 1}
        </motion.text>
        <motion.text x="92" className="fill-foreground font-mono text-[8px] font-medium" initial={{ opacity: 0, y: 98 }} animate={{ opacity: 1, y: 90 }} transition={t(0.6, 0.3)}>
          {epoch}
        </motion.text>
        <text x="344" y="90" textAnchor="end" className="fill-muted-foreground font-mono text-[8px]">
          {slotsDeleted} {slotsDeleted === 1 ? 'slot' : 'slots'} deleted
        </text>
      </svg>
    </figure>
  )
}
