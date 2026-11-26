import { createContext, useContext, useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import type { DeviceState, QgClient } from '@/client/client'
import type { Role } from '@/client/types'

const ClientContext = createContext<QgClient | null>(null)

export function ClientProvider({ client, children }: { client: QgClient; children: ReactNode }) {
  return <ClientContext.Provider value={client}>{children}</ClientContext.Provider>
}

export function useClient(): QgClient {
  const client = useContext(ClientContext)
  if (!client) throw new Error('useClient must be used inside ClientProvider')
  return client
}

export function useDeviceState(): DeviceState {
  const client = useClient()
  const [state, setState] = useState<DeviceState>(() => client.getState())
  useEffect(() => {
    setState(client.getState())
    return client.subscribe(setState)
  }, [client])
  return state
}

/** The person on this device, once unlocked. */
export function useMe() {
  const state = useDeviceState()
  const device = state.kind === 'none' ? null : state.device
  const roles: Role[] = device?.roles ?? []
  return {
    state,
    device,
    roles,
    unlocked: state.kind === 'unlocked',
    has: (...wanted: Role[]) => wanted.some((r) => roles.includes(r)),
  }
}

export const qk = {
  meta: ['meta'] as const,
  directory: ['directory'] as const,
  checkpoint: ['checkpoint'] as const,
  files: (params?: unknown) => ['files', params ?? {}] as const,
  file: (id: string) => ['file', id] as const,
  pending: ['pending-work'] as const,
  devices: (scope: string) => ['devices', scope] as const,
  incidents: (status?: string) => ['incidents', status ?? 'all'] as const,
  incident: (id: string) => ['incident', id] as const,
  exposure: (id: string) => ['exposure', id] as const,
  invites: ['invites'] as const,
  changes: (status?: string) => ['changes', status ?? 'all'] as const,
  alerts: (params?: unknown) => ['alerts', params ?? {}] as const,
  alert: (id: string) => ['alert', id] as const,
  receipts: (params?: unknown) => ['receipts', params ?? {}] as const,
  receipt: (id: string) => ['receipt', id] as const,
  services: ['services'] as const,
  keySet: ['key-set'] as const,
  policy: ['policy'] as const,
  overview: ['overview'] as const,
  signals: ['signals'] as const,
  messages: ['messages'] as const,
  bench: ['bench'] as const,
}
