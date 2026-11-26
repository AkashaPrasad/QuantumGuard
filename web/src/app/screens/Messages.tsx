import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { ErrorNotice } from '@/components/qg/error-notice'
import { Time } from '@/components/qg/ident'
import { EmptyState, PageHeader, RowsSkeleton, Section } from '@/components/qg/page'
import { useToast } from '@/components/qg/toast'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { NativeSelect } from '@/components/qg/native-select'
import { Textarea } from '@/components/ui/textarea'
import { useDocumentTitle, useOnline } from '@/lib/hooks'
import { qk, useClient, useMe } from '../client-context'
import { useNames } from '../names'

function Compose() {
  const client = useClient()
  const qc = useQueryClient()
  const toast = useToast()
  const online = useOnline()
  const me = useMe()
  const names = useNames()
  const [to, setTo] = useState('')
  const [text, setText] = useState('')
  const recipients = (names.directory?.users ?? []).filter((u) => u.user_id !== me.device?.user_id && u.status !== 'disabled')
  const send = useMutation({
    mutationFn: () => client.sendMessage(to, text.trim()),
    onSuccess: () => {
      toast({ tone: 'done', title: 'Message sent', body: `To ${names.user(to) ?? 'recipient'}` })
      setText('')
      void qc.invalidateQueries()
    },
  })
  const canSend = online && !send.isPending && !!to && text.trim().length > 0
  return (
    <form
      className="flex max-w-xl flex-col gap-4 border border-border bg-card p-4"
      data-testid="messages-compose"
      onSubmit={(e) => {
        e.preventDefault()
        if (canSend) send.mutate()
      }}
    >
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="message-to">To</Label>
        <NativeSelect
          id="message-to"
          data-testid="message-to"
          value={to}
          onValueChange={setTo}
          options={[
            { value: '', label: 'Choose a person', disabled: true },
            ...recipients.map((u) => ({ value: u.user_id, label: u.name })),
          ]}
        />
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="message-text">Message</Label>
        <Textarea id="message-text" value={text} onChange={(e) => setText(e.target.value)} rows={4} maxLength={2000} data-testid="message-text" />
      </div>
      {send.error ? <ErrorNotice error={send.error} onRetry={() => send.mutate()} /> : null}
      <div>
        <Button type="submit" className="h-10" disabled={!canSend} data-testid="message-send">
          {send.isPending ? 'Sending…' : 'Send'}
        </Button>
        {!online ? <span className="ml-3 text-sm text-muted-foreground">You are offline.</span> : null}
      </div>
    </form>
  )
}

export default function Messages() {
  useDocumentTitle('Messages')
  const client = useClient()
  const meta = useQuery({ queryKey: qk.meta, queryFn: () => client.meta() })
  const enabled = meta.data?.features.messaging === true
  const messages = useQuery({ queryKey: qk.messages, queryFn: () => client.listMessages(), enabled, refetchInterval: 10000 })
  const list = messages.data ?? []

  return (
    <>
      <PageHeader title="Messages" description="Each message is encrypted separately for every device of the recipient. A revoked device is left out of new messages." />
      {meta.isPending ? (
        <RowsSkeleton rows={3} />
      ) : meta.error ? (
        <ErrorNotice error={meta.error} onRetry={() => void meta.refetch()} />
      ) : !enabled ? (
        <EmptyState title="Messaging is switched off on this server" body="An admin can turn it on in the server settings." testId="messages-off" />
      ) : (
        <>
          <Compose />
          <Section title="Received" className="mt-10">
            {messages.isPending ? (
              <RowsSkeleton rows={3} />
            ) : messages.error ? (
              <ErrorNotice error={messages.error} onRetry={() => void messages.refetch()} />
            ) : list.length === 0 ? (
              <EmptyState title="No messages yet" body="Messages sent to you appear here, decrypted on this device." testId="messages-empty" />
            ) : (
              <ul className="flex flex-col gap-2" data-testid="messages-list">
                {list.map((m) => (
                  <li key={m.message_id} className="border border-border bg-card p-4" data-testid={`message-${m.message_id}`}>
                    <p className="flex flex-wrap items-baseline gap-x-3 text-sm">
                      <span className="font-medium">{m.from.name}</span>
                      <Time value={m.sent_at} className="text-muted-foreground" />
                    </p>
                    <p className="mt-1.5 whitespace-pre-wrap">{m.text}</p>
                    {m.verified ? (
                      <p className="mt-2 flex items-center gap-1.5 text-sm text-allow">
                        <ShieldCheck className="size-4" aria-hidden />
                        Signature checked on this device
                      </p>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </Section>
        </>
      )}
    </>
  )
}
