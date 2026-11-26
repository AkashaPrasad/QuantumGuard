import type { Role } from '@/client/types'

export type TourId = 'role' | 'lose-a-device'

export interface TourStep {
  /** Value of the `data-tour` attribute on the element to point at. */
  anchor: string
  /** Route the anchor lives on, when it is not in the shell itself. Absent: the shell shows it everywhere. */
  route?: string
  /** Only people with one of these roles see the step. Absent: everyone who gets the tour. */
  roles?: Role[]
  title: string
  text: string
  side?: 'top' | 'right' | 'bottom' | 'left'
}

export const STAFF_ROLES: Role[] = ['admin', 'operator', 'auditor']

export const EMPLOYEE_STEPS: TourStep[] = [
  {
    anchor: 'device-chip',
    title: 'This device',
    text: 'This chip names the device you are on, its status and the newest signed device list it has seen.',
    side: 'right',
  },
  {
    anchor: 'nav-files',
    title: 'Files',
    text: 'Files lists your protected files; open one to read it on this device.',
    side: 'right',
  },
  {
    anchor: 'files-protect',
    route: '/app/files',
    title: 'Protect a file',
    text: 'Protect a file locks it with a new key on this device before anything is sent.',
    side: 'bottom',
  },
  {
    anchor: 'nav-devices',
    title: 'Devices and Report lost',
    text: 'Devices lists every device signed in as you; if one is lost, choose Report lost next to it and say when you last had it.',
    side: 'right',
  },
  {
    anchor: 'nav-activity',
    title: 'Activity and receipts',
    text: 'Activity shows a receipt for each decision about your files, so you can see what happened and when.',
    side: 'right',
  },
  {
    anchor: 'nav-help',
    title: 'Help',
    text: 'Help repeats this tour, explains what to do if a device is lost, and lists what this product does not do.',
    side: 'right',
  },
]

export const STAFF_STEPS: TourStep[] = [
  {
    anchor: 'overview-figures',
    route: '/app/overview',
    title: 'Overview',
    text: 'These figures show active devices, files awaiting new keys, open alerts, open incidents and the last time to enforce.',
    side: 'bottom',
  },
  {
    anchor: 'nav-people',
    roles: ['admin'],
    title: 'People and roles',
    text: 'People is where you invite someone or change a role; a role change waits for a second person to approve it.',
    side: 'right',
  },
  {
    anchor: 'nav-changes',
    title: 'Change requests',
    text: 'Change requests lists the role changes and recovery releases that are waiting for approval.',
    side: 'right',
  },
  {
    anchor: 'nav-ops-devices',
    title: 'All devices',
    text: 'All devices lists every device in the organisation; operators can choose Revoke on one to cut it off at once.',
    side: 'right',
  },
  {
    anchor: 'nav-alerts',
    roles: ['operator', 'auditor'],
    title: 'Alerts',
    text: 'Alerts lists the unusual requests the system flagged, with the decision it made for each.',
    side: 'right',
  },
  {
    anchor: 'nav-incidents',
    roles: ['operator', 'auditor'],
    title: 'Incidents and the exposure report',
    text: 'Incidents opens the page for each lost device, with its timeline and the exposure report of which files it could have seen.',
    side: 'right',
  },
  {
    anchor: 'nav-verify',
    title: 'Evidence and Verify',
    text: 'Verify checks a receipt, or an exported proof bundle, on this device without trusting the server.',
    side: 'right',
  },
  {
    anchor: 'nav-policy',
    title: 'Policy and settings',
    text: 'Policy shows the rules that decide who may open what; Settings, for admins, is in the Organisation group.',
    side: 'right',
  },
]

/** Guided demo for operators. It points and explains; the person does every click themselves. */
export const LOSE_A_DEVICE_STEPS: TourStep[] = [
  {
    anchor: 'ops-devices',
    route: '/app/ops/devices',
    title: '1. Revoke the lost device',
    text: 'Pick the device that was lost and choose Revoke; when the result shows, close it and press Next.',
    side: 'top',
  },
  {
    anchor: 'nav-incidents',
    title: '2. Open Incidents',
    text: 'Open Incidents, then open the incident that the revoke just created, and press Next.',
    side: 'right',
  },
  {
    anchor: 'incident-figures',
    title: '3. The figures',
    text: 'These four figures give the time to enforce, how many files were exposed or held, and the attempts denied since.',
    side: 'bottom',
  },
  {
    anchor: 'incident-timeline',
    title: '4. The timeline',
    text: 'The timeline lists each event from the report to the new keys, oldest first, each with its time and receipt.',
    side: 'top',
  },
  {
    anchor: 'incident-exposure',
    title: '5. The exposure groups',
    text: 'Exposed files were opened at or after the loss time; Held files had their key sent earlier; Never released files stayed closed.',
    side: 'top',
  },
  {
    anchor: 'incident-export',
    title: '6. Keep the proof',
    text: 'Export proof bundle saves a file you can check later; choose it yourself if you want one, then press Next.',
    side: 'left',
  },
  {
    anchor: 'nav-verify',
    title: '7. Verify it',
    text: 'Open Verify and drop the bundle there; this device checks every receipt in it with no network request.',
    side: 'right',
  },
]

export function stepsFor(tour: TourId, roles: Role[]): TourStep[] {
  const base =
    tour === 'lose-a-device'
      ? LOSE_A_DEVICE_STEPS
      : roles.some((r) => STAFF_ROLES.includes(r))
        ? STAFF_STEPS
        : EMPLOYEE_STEPS
  return base.filter((s) => !s.roles || s.roles.some((r) => roles.includes(r)))
}
