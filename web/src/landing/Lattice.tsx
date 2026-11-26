import { useEffect, useRef } from 'react'
import { useReducedMotion } from '@/lib/hooks'

const N = 6 // points per edge
const SPAN = 1.7

/**
 * The hero figure: a slowly turning cubic lattice of points, a nod to the
 * lattice problems behind ML-KEM. One point is marked: the short vector
 * nobody else can find. Decorative only; a single still frame when motion is reduced.
 * Drawn on a 2D canvas: no 3D library is needed for seven hundred squares.
 */
export function Lattice({ className }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null)
  const reduced = useReducedMotion()

  useEffect(() => {
    const canvas = ref.current
    const ctx = canvas?.getContext('2d')
    if (!canvas || !ctx) return
    let raf = 0
    let visible = true
    let ink = '#161a22'
    let accent = '#2438c7'
    const readColours = () => {
      const cs = getComputedStyle(document.documentElement)
      ink = cs.getPropertyValue('--foreground').trim() || ink
      accent = cs.getPropertyValue('--primary').trim() || accent
    }
    readColours()

    const points: [number, number, number][] = []
    for (let x = 0; x < N; x++) for (let y = 0; y < N; y++) for (let z = 0; z < N; z++) points.push([x, y, z].map((v) => (v / (N - 1) - 0.5) * SPAN) as [number, number, number])
    const marked = (N * N * 2 + N * 3 + 2) % points.length

    const draw = (t: number) => {
      const dpr = Math.min(devicePixelRatio || 1, 2)
      const w = canvas.clientWidth
      const h = canvas.clientHeight
      if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(h * dpr)) {
        canvas.width = Math.round(w * dpr)
        canvas.height = Math.round(h * dpr)
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.clearRect(0, 0, w, h)
      const a = t * 0.00012 + 0.6
      const b = 0.42
      const scale = Math.min(w, h) * 0.36
      const projected = points.map(([x, y, z], i) => {
        const x1 = x * Math.cos(a) + z * Math.sin(a)
        const z1 = -x * Math.sin(a) + z * Math.cos(a)
        const y1 = y * Math.cos(b) - z1 * Math.sin(b)
        const z2 = y * Math.sin(b) + z1 * Math.cos(b)
        const p = 3.2 / (3.2 + z2)
        return { x: w / 2 + x1 * scale * p, y: h / 2 + y1 * scale * p, depth: z2, p, i }
      })
      projected.sort((m, n) => n.depth - m.depth)
      for (const q of projected) {
        const near = (1.2 - q.depth) / 2.4
        const size = (q.i === marked ? 7 : 2.6) * q.p
        ctx.globalAlpha = q.i === marked ? 1 : 0.14 + near * 0.6
        ctx.fillStyle = q.i === marked ? accent : ink
        ctx.fillRect(q.x - size / 2, q.y - size / 2, size, size)
      }
      ctx.globalAlpha = 1
    }

    const loop = (t: number) => {
      if (visible) draw(t)
      raf = requestAnimationFrame(loop)
    }
    if (reduced) draw(0)
    else raf = requestAnimationFrame(loop)

    const io = new IntersectionObserver(([e]) => (visible = e?.isIntersecting ?? true))
    io.observe(canvas)
    const mo = new MutationObserver(() => {
      readColours()
      if (reduced) draw(0)
    })
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    const onResize = () => reduced && draw(0)
    addEventListener('resize', onResize)
    return () => {
      cancelAnimationFrame(raf)
      io.disconnect()
      mo.disconnect()
      removeEventListener('resize', onResize)
    }
  }, [reduced])

  return <canvas ref={ref} className={className} aria-hidden />
}
