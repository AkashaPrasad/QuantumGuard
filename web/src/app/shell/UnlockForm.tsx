import { Eye, EyeOff, LockKeyhole } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import type { LocalDevice } from '@/client/client'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { isCode } from '@/lib/errors'
import { useClient } from '../client-context'

/** The passphrase form, shared by the unlock page and the lock overlay. */
export function UnlockForm({ device, onUnlocked }: { device: LocalDevice; onUnlocked?: () => void }) {
  const client = useClient()
  const [passphrase, setPassphrase] = useState('')
  const [show, setShow] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const input = useRef<HTMLInputElement>(null)

  useEffect(() => {
    input.current?.focus()
  }, [])

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!passphrase || busy) return
    setBusy(true)
    setError(null)
    try {
      await client.unlock(passphrase)
      setPassphrase('')
      onUnlocked?.()
    } catch (err) {
      setError(err)
      requestAnimationFrame(() => {
        input.current?.focus()
        input.current?.select()
      })
    } finally {
      setBusy(false)
    }
  }

  const wrong = isCode(error, 'QG_LOCAL_PASSPHRASE')
  return (
    <form onSubmit={submit} className="flex flex-col gap-4" noValidate>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="unlock-passphrase">Passphrase for {device.device_name}</Label>
        <div className="relative">
          <Input
            ref={input}
            id="unlock-passphrase"
            data-testid="unlock-passphrase"
            type={show ? 'text' : 'password'}
            autoComplete="current-password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            disabled={busy}
            aria-invalid={wrong || undefined}
            aria-describedby={wrong ? 'unlock-error' : undefined}
            className="h-10 pr-10"
          />
          <button
            type="button"
            onClick={() => setShow((s) => !s)}
            className="absolute inset-y-0 right-0 inline-flex w-10 items-center justify-center text-muted-foreground hover:text-foreground"
            aria-label={show ? 'Hide passphrase' : 'Show passphrase'}
            aria-pressed={show}
          >
            {show ? <EyeOff className="size-4" aria-hidden /> : <Eye className="size-4" aria-hidden />}
          </button>
        </div>
        {wrong ? (
          <p id="unlock-error" data-testid="unlock-error" role="alert" className="text-sm text-deny">
            That passphrase did not unlock this device. Passphrases are case sensitive.
          </p>
        ) : null}
      </div>
      {error && !wrong ? <ErrorNotice error={error} testId="unlock-error" /> : null}
      <Button type="submit" size="lg" className="h-10" disabled={!passphrase || busy} data-testid="unlock-submit">
        <LockKeyhole aria-hidden />
        {busy ? 'Unlocking…' : 'Unlock'}
      </Button>
    </form>
  )
}
