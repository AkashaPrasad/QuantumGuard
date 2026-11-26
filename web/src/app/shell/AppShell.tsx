import { useQuery, useQueryClient } from '@tanstack/react-query'
import { LockKeyhole, Monitor, Moon, Search, Sun, WifiOff } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useLocation } from 'react-router'
import { DeviceStatusChip } from '@/components/qg/chips'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
  useSidebar,
} from '@/components/ui/sidebar'
import { countdown, initials } from '@/lib/format'
import { useOnline } from '@/lib/hooks'
import { qk, useClient, useMe } from '../client-context'
import { visibleNav } from '../nav'
import type { Theme } from '../theme'
import { useTheme } from '../theme'
import { CommandPalette } from './CommandPalette'
import { PendingWorkBanner } from './PendingWorkBanner'
import { UnlockForm } from './UnlockForm'
import { useIdleLock } from './useIdleLock'
import { Wordmark } from './Wordmark'

const ROLE_LABEL = { employee: 'Employee', admin: 'Admin', operator: 'Operator', auditor: 'Auditor' } as const

function DeviceChip() {
  const client = useClient()
  const { device, state } = useMe()
  const { data: directory } = useQuery({ queryKey: qk.directory, queryFn: () => client.directory(), staleTime: 15_000 })
  if (!device) return null
  return (
    <NavLink
      to="/app/devices"
      data-tour="device-chip"
      data-testid="device-chip"
      className="mt-3 block border border-sidebar-border bg-background/60 p-2.5 hover:border-rule"
    >
      <div className="label-caps">This device</div>
      <div className="mt-0.5 truncate font-medium">{device.device_name}</div>
      <div className="mt-1.5 flex items-center justify-between gap-2">
        <DeviceStatusChip status={state.kind === 'revoked' ? 'revoked' : 'active'} />
        <span className="data text-[0.75rem] text-muted-foreground" title="The newest signed device list this device has seen">
          epoch {directory?.epoch ?? '…'}
        </span>
      </div>
    </NavLink>
  )
}

function Nav({ onNavigate }: { onNavigate: () => void }) {
  const client = useClient()
  const { roles, has, unlocked } = useMe()
  const location = useLocation()
  const { data: meta } = useQuery({ queryKey: qk.meta, queryFn: () => client.meta(), staleTime: 60_000 })
  const seesAlerts = has('operator', 'auditor')
  const { data: alerts } = useQuery({
    queryKey: qk.alerts({ status: 'open' }),
    queryFn: () => client.listAlerts({ status: 'open' }),
    enabled: unlocked && seesAlerts,
    refetchInterval: 10_000,
  })
  const groups = visibleNav(roles, { messaging: meta?.features.messaging ?? false })
  return (
    <>
      {groups.map((group) => (
        <SidebarGroup key={group.label}>
          <SidebarGroupLabel className="label-caps">{group.label}</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {group.items.map((item) => {
                const active =
                  location.pathname === item.to ||
                  (item.to !== '/app/evidence' && location.pathname.startsWith(`${item.to}/`))
                const badge = item.to === '/app/ops/alerts' ? (alerts?.length ?? 0) : 0
                return (
                  <SidebarMenuItem key={item.to}>
                    <SidebarMenuButton asChild isActive={active} className="h-9">
                      <NavLink to={item.to} data-tour={item.tour} onClick={onNavigate}>
                        <item.icon aria-hidden />
                        <span>{item.label}</span>
                      </NavLink>
                    </SidebarMenuButton>
                    {badge > 0 ? (
                      <SidebarMenuBadge className="data bg-deny-soft text-deny" aria-label={`${badge} open alerts`}>
                        {badge}
                      </SidebarMenuBadge>
                    ) : null}
                  </SidebarMenuItem>
                )
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      ))}
    </>
  )
}

function ShellSidebar() {
  const { setOpenMobile } = useSidebar()
  return (
    <Sidebar collapsible="offcanvas">
      <SidebarHeader className="p-3">
        <NavLink to="/" aria-label="QuantumGuard home" className="px-1 pt-1">
          <Wordmark />
        </NavLink>
        <DeviceChip />
      </SidebarHeader>
      <SidebarContent>
        <nav aria-label="Console">
          <Nav onNavigate={() => setOpenMobile(false)} />
        </nav>
      </SidebarContent>
      <SidebarFooter className="p-3">
        <p className="text-[0.75rem] leading-snug text-muted-foreground">
          Synthetic data only. Every decision here has a receipt you can verify.
        </p>
      </SidebarFooter>
    </Sidebar>
  )
}

const THEME_ICON = { light: Sun, dark: Moon, system: Monitor } as const

function TopBar({ onOpenPalette, idleLeft }: { onOpenPalette: () => void; idleLeft: number }) {
  const client = useClient()
  const { device, roles } = useMe()
  const { theme, setTheme } = useTheme()
  const ThemeIcon = THEME_ICON[theme]
  return (
    <header className="sticky top-0 z-20 flex h-14 shrink-0 items-center gap-2 border-b border-rule bg-background/95 px-3 backdrop-blur-sm sm:px-5">
      <SidebarTrigger aria-label="Toggle navigation" />
      <button
        type="button"
        onClick={onOpenPalette}
        data-testid="command-open"
        className="ml-1 inline-flex h-9 min-w-0 flex-1 items-center gap-2 border border-border bg-paper-raised px-2.5 text-left text-muted-foreground hover:border-rule hover:text-foreground sm:max-w-80"
      >
        <Search className="size-4 shrink-0" aria-hidden />
        <span className="truncate">Search or run a command</span>
        <kbd className="data ml-auto border border-border px-1 text-[0.6875rem] max-sm:hidden">⌘K</kbd>
      </button>
      <div className="ml-auto flex items-center gap-1.5">
        <span
          className="data text-[0.75rem] text-muted-foreground max-md:hidden"
          title="This device locks itself after ten minutes without input"
          data-testid="session-clock"
        >
          locks in {countdown(idleLeft)}
        </span>
        <Button variant="outline" size="sm" onClick={() => client.lock()} data-testid="lock-now" className="h-9">
          <LockKeyhole aria-hidden />
          <span className="max-sm:sr-only">Lock</span>
        </Button>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              data-testid="user-menu"
              className="inline-flex size-9 items-center justify-center bg-foreground text-[0.75rem] font-semibold text-background"
              aria-label={`Account menu for ${device?.user_name ?? 'this person'}`}
            >
              {initials(device?.user_name ?? '?')}
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-60">
            <DropdownMenuLabel>
              <div className="font-medium text-foreground">{device?.user_name}</div>
              <div className="mt-0.5 font-normal text-muted-foreground">{roles.map((r) => ROLE_LABEL[r]).join(', ')}</div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuLabel className="label-caps flex items-center gap-1.5">
              <ThemeIcon className="size-3" aria-hidden />
              Theme
            </DropdownMenuLabel>
            <DropdownMenuRadioGroup value={theme} onValueChange={(v) => setTheme(v as Theme)}>
              <DropdownMenuRadioItem value="light" data-testid="theme-light">
                Light
              </DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="dark" data-testid="theme-dark">
                Dark
              </DropdownMenuRadioItem>
              <DropdownMenuRadioItem value="system">Match this device</DropdownMenuRadioItem>
            </DropdownMenuRadioGroup>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => client.lock()}>
              <LockKeyhole aria-hidden />
              Lock this device
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}

function OfflineBanner() {
  const online = useOnline()
  if (online) return null
  return (
    <div role="status" data-testid="offline-banner" className="flex items-center gap-2 border-b border-rule bg-muted px-4 py-2 text-sm sm:px-6">
      <WifiOff className="size-4 shrink-0" aria-hidden />
      You are offline. Nothing is sent until the connection returns.
    </div>
  )
}

/** Shown over the current page when the device locks; the page underneath keeps its input. */
function LockOverlay() {
  const { state } = useMe()
  if (state.kind !== 'locked') return null
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="lock-title"
      data-testid="lock-overlay"
      className="fixed inset-0 z-[60] flex items-start justify-center bg-background/90 px-4 pt-[18vh] backdrop-blur-sm"
    >
      <div className="w-full max-w-sm border border-rule bg-card p-6 shadow-lift">
        <LockKeyhole className="size-5 text-primary" aria-hidden />
        <h2 id="lock-title" className="mt-3 text-xl">
          This device is locked
        </h2>
        <p className="mt-1 mb-5 text-muted-foreground">
          It locks itself after ten minutes without input. Unlock to carry on where you were; nothing you typed was lost.
        </p>
        <UnlockForm device={state.device} />
      </div>
    </div>
  )
}

export function AppShell() {
  const { roles, unlocked } = useMe()
  const client = useClient()
  const qc = useQueryClient()
  const [palette, setPalette] = useState(false)
  const idleLeft = useIdleLock(unlocked)
  const { data: meta } = useQuery({ queryKey: qk.meta, queryFn: () => client.meta(), staleTime: 60_000 })
  const wasUnlocked = useRef(unlocked)

  // Coming back from a lock: everything on screen may be stale.
  useEffect(() => {
    if (unlocked && !wasUnlocked.current) void qc.invalidateQueries()
    wasUnlocked.current = unlocked
  }, [unlocked, qc])

  return (
    <SidebarProvider>
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[80] focus:bg-primary focus:px-3 focus:py-2 focus:text-primary-foreground"
      >
        Skip to content
      </a>
      <ShellSidebar />
      <SidebarInset className="min-w-0" inert={!unlocked}>
        <TopBar onOpenPalette={() => setPalette(true)} idleLeft={idleLeft} />
        {meta?.demo ? (
          <div className="border-b border-rule bg-accent px-4 py-1.5 text-sm text-accent-foreground sm:px-6" data-testid="demo-banner">
            Public demo. Synthetic data only. Reset daily.
          </div>
        ) : null}
        <OfflineBanner />
        <PendingWorkBanner />
        <main id="main" tabIndex={-1} className="mx-auto w-full max-w-[1120px] flex-1 px-4 py-6 outline-none sm:px-6 sm:py-8">
          <Outlet />
        </main>
      </SidebarInset>
      <CommandPalette
        open={palette && unlocked}
        onOpenChange={setPalette}
        groups={visibleNav(roles, { messaging: meta?.features.messaging ?? false })}
      />
      <LockOverlay />
    </SidebarProvider>
  )
}
