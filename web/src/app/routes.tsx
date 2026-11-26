import { lazy, Suspense } from 'react'
import type { ReactNode } from 'react'
import { Navigate, Route, Routes } from 'react-router'
import type { Role } from '@/client/types'
import { RowsSkeleton } from '@/components/qg/page'
import { AppIndex, RequireDevice, RequireRole } from './guards'
import { AppShell } from './shell/AppShell'

// The public site is its own chunk; the console never loads it, and the reverse.
const Landing = lazy(() => import('@/landing/Landing'))
const Docs = lazy(() => import('@/landing/Docs'))
const Status = lazy(() => import('@/landing/Status'))

const Enrol = lazy(() => import('./screens/Enrol'))
const Unlock = lazy(() => import('./screens/Unlock'))
const Files = lazy(() => import('./screens/Files'))
const Devices = lazy(() => import('./screens/Devices'))
const Activity = lazy(() => import('./screens/Activity'))
const Messages = lazy(() => import('./screens/Messages'))
const Help = lazy(() => import('./screens/Help'))
const Overview = lazy(() => import('./screens/Overview'))
const People = lazy(() => import('./screens/People'))
const Changes = lazy(() => import('./screens/Changes'))
const Services = lazy(() => import('./screens/Services'))
const Settings = lazy(() => import('./screens/Settings'))
const OpsDevices = lazy(() => import('./screens/OpsDevices'))
const Alerts = lazy(() => import('./screens/Alerts'))
const Incidents = lazy(() => import('./screens/Incidents'))
const IncidentDetail = lazy(() => import('./screens/IncidentDetail'))
const Policy = lazy(() => import('./screens/Policy'))
const Evidence = lazy(() => import('./screens/Evidence'))
const Verify = lazy(() => import('./screens/Verify'))
const NotFound = lazy(() => import('./screens/NotFound'))

const wait = <RowsSkeleton rows={6} />

function role(roles: Role[], node: ReactNode) {
  return <RequireRole roles={roles}>{node}</RequireRole>
}

export function AppRoutes() {
  return (
    <Suspense fallback={<div className="p-6">{wait}</div>}>
      <Routes>
        <Route path="/" element={<Landing />} />
        {/* The public sections are one page; these addresses scroll to their section. */}
        <Route path="/how-it-works" element={<Landing section="how-it-works" />} />
        <Route path="/product" element={<Landing section="product" />} />
        <Route path="/architecture" element={<Landing section="architecture" />} />
        <Route path="/security" element={<Landing section="security" />} />
        <Route path="/docs" element={<Docs />} />
        <Route path="/status" element={<Status />} />

        <Route path="/app/enrol" element={<Enrol />} />
        <Route path="/app/unlock" element={<Unlock />} />
        <Route
          path="/app"
          element={
            <RequireDevice>
              <AppShell />
            </RequireDevice>
          }
        >
          <Route index element={<AppIndex />} />
          <Route path="files" element={<Files />} />
          <Route path="files/:fileId" element={<Files />} />
          <Route path="devices" element={<Devices />} />
          <Route path="activity" element={<Activity />} />
          <Route path="messages" element={<Messages />} />
          <Route path="help" element={<Help />} />
          <Route path="overview" element={role(['admin', 'operator', 'auditor'], <Overview />)} />
          <Route path="admin/overview" element={<Navigate to="/app/overview" replace />} />
          <Route path="ops/overview" element={<Navigate to="/app/overview" replace />} />
          <Route path="admin/people" element={role(['admin'], <People />)} />
          <Route path="admin/changes" element={role(['admin', 'operator', 'auditor'], <Changes />)} />
          <Route path="admin/services" element={role(['admin', 'operator', 'auditor'], <Services />)} />
          <Route path="admin/settings" element={role(['admin'], <Settings />)} />
          <Route path="ops/devices" element={role(['operator', 'admin', 'auditor'], <OpsDevices />)} />
          <Route path="ops/alerts" element={role(['operator', 'auditor'], <Alerts />)} />
          <Route path="ops/incidents" element={role(['operator', 'auditor'], <Incidents />)} />
          {/* An employee may open the incident for their own device, so no role gate here. */}
          <Route path="ops/incidents/:incidentId" element={<IncidentDetail />} />
          <Route path="ops/policy" element={<Policy />} />
          <Route path="evidence" element={role(['auditor', 'operator'], <Evidence />)} />
          <Route path="evidence/verify" element={<Verify />} />
          <Route path="*" element={<NotFound />} />
        </Route>
        <Route path="*" element={<NotFound standalone />} />
      </Routes>
    </Suspense>
  )
}
