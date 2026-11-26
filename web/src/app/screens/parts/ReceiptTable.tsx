import type { Receipt } from '@/client/types'
import { DecisionChip } from '@/components/qg/chips'
import { Time } from '@/components/qg/ident'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { actionWords, shortId } from '@/lib/format'

export function ReceiptTable({ items, onOpen }: { items: Receipt[]; onOpen: (r: Receipt) => void }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="label-caps">Time</TableHead>
          <TableHead className="label-caps">What happened</TableHead>
          <TableHead className="label-caps max-md:hidden">Resource</TableHead>
          <TableHead className="label-caps">Decision</TableHead>
          <TableHead className="label-caps max-sm:hidden">Log entry</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((r) => (
          <TableRow key={r.id} className="h-11 cursor-pointer" onClick={() => onOpen(r)} data-testid={`receipt-row-${r.id}`}>
            <TableCell>
              <Time value={r.ts} className="data text-[0.8125rem]" />
            </TableCell>
            <TableCell>
              <button type="button" className="text-left font-medium hover:underline focus-visible:underline" onClick={(e) => { e.stopPropagation(); onOpen(r) }} aria-label={`Open receipt: ${actionWords(r.action)}`}>
                {actionWords(r.action)}
              </button>
            </TableCell>
            <TableCell className="max-w-64 truncate text-muted-foreground max-md:hidden" title={r.resource}>
              {r.resource}
            </TableCell>
            <TableCell>
              <DecisionChip decision={r.decision} />
            </TableCell>
            <TableCell className="data text-[0.8125rem] max-sm:hidden" title={shortId(r.id)}>
              #{r.leaf_index}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

export type DecisionFilter = 'all' | 'allow' | 'deny'

export function DecisionSegment({ value, onChange }: { value: DecisionFilter; onChange: (v: DecisionFilter) => void }) {
  const opts: { v: DecisionFilter; label: string }[] = [
    { v: 'all', label: 'All' },
    { v: 'allow', label: 'Allowed' },
    { v: 'deny', label: 'Denied' },
  ]
  return (
    <div role="group" aria-label="Filter by decision" className="inline-flex h-9 border border-input">
      {opts.map((o) => (
        <button
          key={o.v}
          type="button"
          aria-pressed={value === o.v}
          onClick={() => onChange(o.v)}
          data-testid={`filter-decision-${o.v}`}
          className={`px-3 text-sm not-first:border-l not-first:border-input ${value === o.v ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'}`}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}
