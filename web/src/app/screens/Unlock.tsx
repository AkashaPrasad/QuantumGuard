import { useState } from 'react'
import { Link, Navigate, useLocation } from 'react-router'
import { Button } from '@/components/ui/button'
import { useDocumentTitle } from '@/lib/hooks'
import { useClient, useMe } from '../client-context'
import { RevokedPage } from '../guards'
import { homeFor } from '../nav'
import { StandalonePage } from '../shell/StandalonePage'
import { UnlockForm } from '../shell/UnlockForm'

/** Flow: web/flows/sign-in.md */
export default function Unlock() {
  useDocumentTitle('Unlock')
  const client = useClient()
  const { state, roles } = useMe()
  const location = useLocation()
  const [forget, setForget] = useState(false)
  const from = (location.state as { from?: string } | null)?.from

  if (state.kind === 'none') return <Navigate to="/app/enrol" replace />
  if (state.kind === 'revoked') return <RevokedPage />
  if (state.kind === 'unlocked') return <Navigate to={from ?? homeFor(roles)} replace />

  return (
    <StandalonePage>
      <p className="label-caps">{state.device.user_name}</p>
      <h1 className="mt-1 text-2xl">Unlock this device</h1>
      <p className="mt-2 mb-6 text-muted-foreground">
        Your keys are stored here, locked by your passphrase. The passphrase is checked on this device and never sent anywhere.
      </p>
      <UnlockForm device={state.device} />
      <div className="mt-8 border-t border-rule pt-4 text-sm text-muted-foreground">
        {forget ? (
          <div className="border border-deny/40 bg-deny-soft/60 p-3 text-foreground">
            <p>
              This removes the locked keys for <strong className="font-medium">{state.device.device_name}</strong> from this browser. You
              would need a new enrolment code to use it again.
            </p>
            <div className="mt-3 flex gap-2">
              <Button variant="danger" size="sm" onClick={() => void client.forgetDevice()} data-testid="forget-confirm">
                Forget this device
              </Button>
              <Button variant="outline" size="sm" onClick={() => setForget(false)}>
                Keep it
              </Button>
            </div>
          </div>
        ) : (
          <p>
            Not {state.device.user_name}?{' '}
            <button type="button" className="text-primary underline underline-offset-2" onClick={() => setForget(true)} data-testid="unlock-forget">
              Forget this device
            </button>{' '}
            and <Link className="text-primary underline underline-offset-2" to="/">go back to the public site</Link>.
          </p>
        )}
      </div>
    </StandalonePage>
  )
}
