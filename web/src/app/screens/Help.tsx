import { Link } from 'react-router'
import { PageHeader, Section } from '@/components/qg/page'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useDocumentTitle } from '@/lib/hooks'
import { useMe } from '../client-context'

const LIMITS = [
  'Anything a device already decrypted before it was revoked. We list it; we cannot recall it.',
  'A person who is tricked into opening a file for an attacker, or malware on a device that is currently authorised and unlocked.',
  'A weak passphrase on a stolen device, beyond the cost that slow key derivation imposes and the time it buys to revoke.',
  'Hardware-level key protection. This prototype stores keys in software.',
  'Metadata. The server knows who opened which file and when; that is what makes the exposure report possible.',
  'Availability against a determined flood. Rate limits and failing closed protect data, not uptime.',
  'Side-channel attacks on the cryptographic libraries.',
]

const KEYS: [string, string][] = [
  ['Cmd/Ctrl+K', 'Open the command palette'],
  ['Esc', 'Close dialogs and the tour'],
  ['Tab / Shift+Tab', 'Move to the next or previous control'],
  ['Enter', 'Activate the focused control'],
]

const link = 'text-primary underline underline-offset-2'

export default function Help() {
  useDocumentTitle('Help and tour')
  const { has } = useMe()
  return (
    <>
      <PageHeader title="Help and tour" description="How to find your way around, what to do if a device is lost, and what this product does not do." />

      <Section title="Take the tour again" className="mt-0">
        <div data-tour="help-tour" className="flex flex-wrap gap-2 border border-border bg-card p-4">
          <Button className="h-9" data-testid="help-replay-tour" onClick={() => window.dispatchEvent(new CustomEvent('qg:start-tour'))}>
            Take the tour again
          </Button>
          {has('operator') ? (
            <Button variant="outline" className="h-9" data-testid="help-guided-demo" onClick={() => window.dispatchEvent(new CustomEvent('qg:start-tour', { detail: 'lose-a-device' }))}>
              Guided demo: lose a device
            </Button>
          ) : null}
        </div>
      </Section>

      <Section title="If you lose a device">
        <ol className="max-w-[68ch] list-decimal space-y-1.5 pl-5">
          <li>Open Devices on another device of yours and choose Report lost next to the one you no longer have.</li>
          <li>Say when you last had it, then confirm. Access is removed at once and the keys it held stop working.</li>
          <li>Read what was affected. Files it opened after that time are listed, and they get new keys.</li>
        </ol>
        <p className="mt-3 text-sm">
          <Link to="/app/devices" className={link}>Go to your devices</Link>
        </p>
      </Section>

      <Section title="What QuantumGuard does not protect">
        <ul className="max-w-[68ch] list-disc space-y-1.5 pl-5" data-testid="help-limits">
          {LIMITS.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      </Section>

      <Section title="Keyboard">
        <div className="overflow-x-auto border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="label-caps">Keys</TableHead>
                <TableHead className="label-caps">What they do</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {KEYS.map(([k, d]) => (
                <TableRow key={k} className="h-11">
                  <TableCell className="data">{k}</TableCell>
                  <TableCell>{d}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </Section>

      <Section title="Links">
        <ul className="space-y-1">
          <li><Link to="/app/ops/policy" className={link}>Policy</Link></li>
          <li><Link to="/app/evidence/verify" className={link}>Verify</Link></li>
          <li><Link to="/docs" className={link}>API reference</Link></li>
          <li><Link to="/status" className={link}>Status</Link></li>
        </ul>
      </Section>
    </>
  )
}
