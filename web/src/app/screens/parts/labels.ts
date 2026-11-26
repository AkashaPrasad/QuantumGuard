import type { Change, ResponseAction, Role } from '@/client/types'

export const ROLE_LABEL: Record<Role, string> = {
  employee: 'Employee',
  auditor: 'Auditor',
  operator: 'Operator',
  admin: 'Admin',
}

export const ROLE_ORDER: Role[] = ['employee', 'auditor', 'operator', 'admin']

/** The sentence a change request reads as: "Grant Operator to Daniel Mensah". */
export function changeSentence(c: Change, fileName?: (id: string) => string | null): string {
  if (c.type === 'role_grant') return `Grant ${c.role ? ROLE_LABEL[c.role] : 'a role'} to ${c.target_user.name}`
  if (c.type === 'role_revoke') return `Remove ${c.role ? ROLE_LABEL[c.role] : 'a role'} from ${c.target_user.name}`
  const f = c.file_id ? (fileName?.(c.file_id) ?? c.file_id) : 'a file'
  return `Release recovery slot for ${f}`
}

export const RESPONSE_PHRASE: Record<ResponseAction, string> = {
  end_session: 'Session ended',
  quarantine_device: 'Device paused',
  quarantine_identity: 'Identity paused for sensitive files',
  throttle: 'Slowed down for 5 minutes',
  require_fresh_session: 'Fresh unlock required',
  hold_enrolment: 'Enrolment held',
  freeze_key_release: 'Key release frozen',
  deny: 'Denied',
  none: 'None',
}
