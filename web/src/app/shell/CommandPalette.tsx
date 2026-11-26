import { FilePlus2, LockKeyhole, MonitorX, ShieldCheck } from 'lucide-react'
import { useEffect } from 'react'
import { useNavigate } from 'react-router'
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from '@/components/ui/command'
import { useClient } from '../client-context'
import type { NavGroup } from '../nav'

export function CommandPalette({
  open,
  onOpenChange,
  groups,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  groups: NavGroup[]
}) {
  const navigate = useNavigate()
  const client = useClient()

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        onOpenChange(!open)
      }
    }
    addEventListener('keydown', onKey)
    return () => removeEventListener('keydown', onKey)
  }, [open, onOpenChange])

  const go = (to: string) => {
    onOpenChange(false)
    navigate(to)
  }

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange} title="Search or run a command" description="Go to a page or start an action">
      <Command>
      <CommandInput placeholder="Go to a page or start an action" data-testid="command-input" />
      <CommandList>
        <CommandEmpty>Nothing matches. Try "files", "lost" or "verify".</CommandEmpty>
        <CommandGroup heading="Actions">
          <CommandItem onSelect={() => go('/app/files?protect=1')} data-testid="command-protect">
            <FilePlus2 aria-hidden />
            Protect a file
          </CommandItem>
          <CommandItem onSelect={() => go('/app/devices?report=1')} data-testid="command-report-lost">
            <MonitorX aria-hidden />
            Report a lost device
          </CommandItem>
          <CommandItem onSelect={() => go('/app/evidence/verify')} data-testid="command-verify">
            <ShieldCheck aria-hidden />
            Verify a receipt
          </CommandItem>
          <CommandItem
            onSelect={() => {
              onOpenChange(false)
              client.lock()
            }}
          >
            <LockKeyhole aria-hidden />
            Lock this device now
          </CommandItem>
        </CommandGroup>
        {groups.map((g) => (
          <div key={g.label}>
            <CommandSeparator />
            <CommandGroup heading={g.label}>
              {g.items.map((i) => (
                <CommandItem key={i.to} onSelect={() => go(i.to)}>
                  <i.icon aria-hidden />
                  {i.label}
                </CommandItem>
              ))}
            </CommandGroup>
          </div>
        ))}
      </CommandList>
      </Command>
    </CommandDialog>
  )
}
