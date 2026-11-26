import { useQueryClient } from '@tanstack/react-query'
import { useCallback, useRef, useState } from 'react'
import type { OpenProgress } from '@/client/client'
import { saveBlob } from '@/lib/download'
import { useClient } from '../../client-context'

export type OpenState =
  | { kind: 'working'; progress: OpenProgress }
  | { kind: 'opened'; receipt_id: string; verified: boolean }
  | { kind: 'failed'; error: unknown }

function words(p: OpenProgress): string {
  switch (p.phase) {
    case 'requesting':
      return 'Asking'
    case 'released':
      return 'Released'
    case 'unwrapped':
      return 'Unwrapped'
    case 'decrypting':
      return `Decrypting ${Math.min(p.chunk + 1, p.chunks)} of ${p.chunks}`
    default:
      return 'Done'
  }
}

/** One click opens a file: ask, receive the slot, unwrap, decrypt, save. Flow: web/flows/open-file.md */
export function useOpenFile() {
  const client = useClient()
  const qc = useQueryClient()
  const [states, setStates] = useState<Record<string, OpenState>>({})
  const busy = useRef(new Set<string>())

  const open = useCallback(
    async (fileId: string) => {
      if (busy.current.has(fileId)) return
      busy.current.add(fileId)
      const set = (s: OpenState) => setStates((m) => ({ ...m, [fileId]: s }))
      set({ kind: 'working', progress: { phase: 'requesting' } })
      try {
        const opened = await client.openFile(fileId, (progress) => set({ kind: 'working', progress }))
        saveBlob(opened.blob, opened.name)
        set({ kind: 'opened', receipt_id: opened.receipt_id, verified: opened.verified })
      } catch (error) {
        set({ kind: 'failed', error })
      } finally {
        busy.current.delete(fileId)
        void qc.invalidateQueries({ queryKey: ['receipts'] })
        void qc.invalidateQueries({ queryKey: ['file', fileId] })
      }
    },
    [client, qc],
  )

  return { states, open, words }
}
