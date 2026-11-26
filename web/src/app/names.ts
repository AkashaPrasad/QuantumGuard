import { useQuery } from '@tanstack/react-query'
import { useMemo } from 'react'
import { qk, useClient } from './client-context'

/** Names for ids, read from the signed directory. Falls back to the id itself. */
export function useNames() {
  const client = useClient()
  const { data } = useQuery({ queryKey: qk.directory, queryFn: () => client.directory(), staleTime: 15_000 })
  return useMemo(() => {
    const users = new Map((data?.users ?? []).map((u) => [u.user_id, u]))
    const devices = new Map((data?.devices ?? []).map((d) => [d.device_id, d]))
    return {
      directory: data ?? null,
      user: (id: string | null | undefined) => (id ? (users.get(id)?.name ?? null) : null),
      device: (id: string | null | undefined) => (id ? (devices.get(id)?.name ?? null) : null),
      userOfDevice: (id: string | null | undefined) => {
        const d = id ? devices.get(id) : undefined
        return d ? (users.get(d.user_id)?.name ?? null) : null
      },
    }
  }, [data])
}
