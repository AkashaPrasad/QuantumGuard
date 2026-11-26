import { Lock } from 'lucide-react'
import { useMemo } from 'react'
import { Progress } from '@/components/ui/progress'
import { useReducedMotion } from '@/lib/hooks'
import { cn } from '@/lib/utils'

const GLYPHS = '0123456789abcdef'
const MAX_CELLS = 48

/** Deterministic stand-in for ciphertext: the same position always shows the same glyph. */
function scramble(name: string, upTo: number): string {
  let out = ''
  for (let i = 0; i < name.length; i++) {
    const c = name[i]!
    out += i < upTo && c !== '.' && c !== ' ' ? GLYPHS[(c.charCodeAt(0) * 7 + i * 13) % GLYPHS.length] : c
  }
  return out
}

/**
 * Encryption, drawn: the file as a row of blocks that seal one by one while its
 * name turns to ciphertext, then settles once every block is sealed.
 * `chunk` and `chunks` are the real per-chunk progress.
 */
export function EncryptChunks({ name, chunk, chunks, done }: { name: string; chunk: number; chunks: number; done: boolean }) {
  const reduced = useReducedMotion()
  const cells = Math.min(Math.max(chunks, 1), MAX_CELLS)
  const sealed = done ? cells : Math.floor((chunk / Math.max(chunks, 1)) * cells)
  const fraction = done ? 1 : chunk / Math.max(chunks, 1)
  const shown = useMemo(() => (done ? name : scramble(name, Math.round(fraction * name.length))), [name, fraction, done])
  const pct = Math.round(fraction * 100)

  if (reduced) {
    return (
      <div data-testid="encrypt-chunks">
        <p className="data truncate">{name}</p>
        <Progress value={pct} className="mt-2 h-1.5" aria-label="Encrypting" />
      </div>
    )
  }
  return (
    <div data-testid="encrypt-chunks" data-sealed={sealed} aria-hidden>
      <p className={cn('data flex items-center gap-1.5 truncate text-base', done ? 'text-foreground' : 'text-muted-foreground')}>
        {done ? <Lock className="size-4 shrink-0 text-allow" /> : null}
        <span className="truncate">{shown}</span>
      </p>
      <div className="mt-3 flex flex-wrap gap-1">
        {Array.from({ length: cells }, (_, i) => (
          <span
            key={i}
            className={cn(
              'size-3.5 border transition-colors duration-200',
              i < sealed ? 'border-foreground bg-foreground' : i === sealed && !done ? 'border-primary bg-accent' : 'border-rule',
            )}
          />
        ))}
      </div>
    </div>
  )
}
