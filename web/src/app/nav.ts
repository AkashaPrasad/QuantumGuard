import {
  ClipboardCheck,
  FolderLock,
  Gauge,
  KeyRound,
  LifeBuoy,
  ListTree,
  MessageSquareLock,
  MonitorCog,
  MonitorSmartphone,
  ReceiptText,
  ScrollText,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Siren,
  Users,
} from 'lucide-react'
import type { ComponentType } from 'react'
import type { Role } from '@/client/types'

export interface NavItem {
  to: string
  label: string
  icon: ComponentType<{ className?: string }>
  roles?: Role[] // absent: everyone
  tour?: string
  feature?: 'messaging'
}

export interface NavGroup {
  label: string
  items: NavItem[]
}

export const NAV: NavGroup[] = [
  {
    label: 'My work',
    items: [
      { to: '/app/files', label: 'Files', icon: FolderLock, tour: 'nav-files' },
      { to: '/app/devices', label: 'Devices', icon: MonitorSmartphone, tour: 'nav-devices' },
      { to: '/app/activity', label: 'Activity', icon: ReceiptText, tour: 'nav-activity' },
      { to: '/app/messages', label: 'Messages', icon: MessageSquareLock, feature: 'messaging' },
    ],
  },
  {
    label: 'Organisation',
    items: [
      { to: '/app/overview', label: 'Overview', icon: Gauge, roles: ['admin', 'operator', 'auditor'], tour: 'nav-overview' },
      { to: '/app/admin/people', label: 'People', icon: Users, roles: ['admin'], tour: 'nav-people' },
      { to: '/app/admin/changes', label: 'Change requests', icon: ClipboardCheck, roles: ['admin', 'operator', 'auditor'], tour: 'nav-changes' },
      { to: '/app/admin/services', label: 'Services', icon: KeyRound, roles: ['admin', 'operator', 'auditor'] },
      { to: '/app/admin/settings', label: 'Settings', icon: Settings, roles: ['admin'], tour: 'nav-settings' },
    ],
  },
  {
    label: 'Security',
    items: [
      { to: '/app/ops/devices', label: 'All devices', icon: MonitorCog, roles: ['operator', 'admin', 'auditor'], tour: 'nav-ops-devices' },
      { to: '/app/ops/alerts', label: 'Alerts', icon: Siren, roles: ['operator', 'auditor'], tour: 'nav-alerts' },
      { to: '/app/ops/incidents', label: 'Incidents', icon: ShieldAlert, roles: ['operator', 'auditor'], tour: 'nav-incidents' },
      { to: '/app/ops/policy', label: 'Policy', icon: ScrollText, tour: 'nav-policy' },
    ],
  },
  {
    label: 'Evidence',
    items: [
      { to: '/app/evidence', label: 'Log', icon: ListTree, roles: ['auditor', 'operator'], tour: 'nav-evidence' },
      { to: '/app/evidence/verify', label: 'Verify', icon: ShieldCheck, tour: 'nav-verify' },
    ],
  },
  { label: 'Support', items: [{ to: '/app/help', label: 'Help and tour', icon: LifeBuoy, tour: 'nav-help' }] },
]

export function visibleNav(roles: Role[], features: { messaging: boolean }): NavGroup[] {
  return NAV.map((g) => ({
    ...g,
    items: g.items.filter(
      (i) => (!i.roles || i.roles.some((r) => roles.includes(r))) && (!i.feature || features[i.feature]),
    ),
  })).filter((g) => g.items.length > 0)
}

export function homeFor(roles: Role[]): string {
  return roles.some((r) => r === 'admin' || r === 'operator' || r === 'auditor') ? '/app/overview' : '/app/files'
}
