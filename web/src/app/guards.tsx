import { ShieldOff } from 'lucide-react'
import { useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { Link, Navigate, useLocation } from 'react-router'
import type { Role } from '@/client/types'
import { EmptyState } from '@/components/qg/page'
import { Button } from '@/components/ui/button'
import { exactTime } from '@/lib/format'
import { useClient, useMe } from './client-context'
import { homeFor } from './nav'
import { StandalonePage } from './shell/StandalonePage'

/** Full-page state for a device the server has revoked. */
export function RevokedPage() {
  const client = useClient()
  const { device } = useMe()
  const [confirm, setConfirm] = useState(false)
  return (
    <StandalonePage>
      <div data-testid="revoked-page" role="alert">
        <ShieldOff className="size-6 text-deny" aria-hidden />
        <h1 className="mt-3 text-2xl">Access removed from this device</h1>
        <p className="mt-2 text-muted-foreground">
          {device ? <strong className="font-medium text-foreground">{device.device_name}</strong> : 'This device'} was reported lost or
          revoked. It can no longer open files, and the keys it held for them have been deleted on the server.
        </p>
        <dl className="mt-5 border border-rule bg-card p-4 text-sm">
          <dt className="label-caps">What to do</dt>
          <dd className="mt-1">
            If you reported it yourself, nothing more is needed here. If this is a mistake, contact your operator: a revoked device is
            never restored, it is enrolled again as a new one.
          </dd>
          <dt className="label-caps mt-3">Checked</dt>
          <dd className="data mt-1">{exactTime(new Date().toISOString())}</dd>
        </dl>
        <div className="mt-5 flex flex-col gap-2">
          {confirm ? (
            <div className="border border-deny/40 bg-deny-soft/60 p-3">
              <p className="text-sm">This removes the locked keys stored in this browser. It cannot be undone.</p>
              <div className="mt-3 flex gap-2">
                <Button variant="danger" onClick={() => void client.forgetDevice()} data-testid="forget-confirm">
                  Forget this device
                </Button>
                <Button variant="outline" onClick={() => setConfirm(false)}>
                  Keep it
                </Button>
              </div>
            </div>
          ) : (
            <Button variant="outline" onClick={() => setConfirm(true)} data-testid="unlock-forget">
              Forget this device
            </Button>
          )}
        </div>
      </div>
    </StandalonePage>
  )
}

/** Sends people to enrol or unlock; keeps an already-open page mounted under the lock overlay. */
export function RequireDevice({ children }: { children: ReactNode }) {
  const { state } = useMe()
  const location = useLocation()
  const everUnlocked = useRef(false)
  if (state.kind === 'unlocked') everUnlocked.current = true
  if (state.kind === 'none') return <Navigate to="/app/enrol" replace />
  if (state.kind === 'revoked') return <RevokedPage />
  if (state.kind === 'locked' && !everUnlocked.current)
    return <Navigate to="/app/unlock" replace state={{ from: location.pathname + location.search }} />
  return <>{children}</>
}

export function RequireRole({ roles, children }: { roles: Role[]; children: ReactNode }) {
  const me = useMe()
  if (me.has(...roles)) return <>{children}</>
  return (
    <EmptyState
      testId="role-required"
      title="Not available for your role"
      body="This page needs a role you do not hold. If you think you should have it, ask an admin to request the change."
      action={
        <Button asChild>
          <Link to={homeFor(me.roles)}>Back to your work</Link>
        </Button>
      }
    />
  )
}

export function AppIndex() {
  const { roles } = useMe()
  return <Navigate to={homeFor(roles)} replace />
}
