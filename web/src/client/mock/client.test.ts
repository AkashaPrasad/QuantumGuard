import { describe, expect, it } from 'vitest'
import { QgError } from '../client'
import type { EnrolStep, ProtectProgress, VerifyStep } from '../client'
import { createMockClient } from './client'
import { PASSPHRASE, PEOPLE } from './seed'

const PASS = PASSPHRASE
const person = (key: string) => PEOPLE.find((p) => p.key === key)!

async function rejection(p: Promise<unknown>): Promise<QgError> {
  try {
    await p
  } catch (e) {
    expect(e).toBeInstanceOf(QgError)
    return e as QgError
  }
  throw new Error('expected rejection')
}

async function unlocked(persona: 'aiko' | 'mira' | 'priya' | 'jonas') {
  const c = createMockClient({ persona, latencyMs: 0 })
  await c.unlock(PASS)
  return c
}

describe('seed', () => {
  it('uses well-formed user ids', () => {
    for (const p of PEOPLE) expect(p.user_id).toMatch(/^usr_[A-Za-z0-9_-]{22}$/)
  })
})

describe('enrolment and unlock', () => {
  it('enrols with a valid code and emits steps in order', async () => {
    const c = createMockClient({ persona: 'none', latencyMs: 0 })
    expect(c.getState().kind).toBe('none')
    const steps: EnrolStep[] = []
    const dev = await c.enrol({ code: 'kestrel-aiko', device_name: 'Test phone', passphrase: 'a long passphrase' }, (s) => steps.push(s))
    expect(steps).toEqual(['generating_keys', 'proving_possession', 'certificate_issued', 'sealing_keystore', 'session_started'])
    expect(dev.user_name).toBe('Aiko Tanaka')
    expect(c.getState().kind).toBe('unlocked')
    c.lock()
    expect(await c.unlock('a long passphrase')).toMatchObject({ first_session: false })
    // single use
    const again = createMockClient({ persona: 'none', latencyMs: 0 })
    await again.enrol({ code: 'KESTREL-MIRA', device_name: 'x', passphrase: 'another long one' })
    expect((await rejection(again.forgetDevice().then(() => again.enrol({ code: 'KESTREL-MIRA', device_name: 'y', passphrase: 'another long one' })))).reason).toBe('invite_invalid')
  })

  it('refuses a bad or expired code and a weak passphrase', async () => {
    const c = createMockClient({ persona: 'none', latencyMs: 0 })
    for (const code of ['EXPIRED-CODE', 'NOPE']) {
      const e = await rejection(c.enrol({ code, device_name: 'd', passphrase: 'long enough pass' }))
      expect(e.code).toBe('QG_INVALID_INPUT')
      expect(e.reason).toBe('invite_invalid')
    }
    const weak = await rejection(c.enrol({ code: 'KESTREL-AIKO', device_name: 'd', passphrase: 'short' }))
    expect(weak.reason).toBe('passphrase_weak')
  })

  it('rejects a wrong passphrase', async () => {
    const c = createMockClient({ persona: 'aiko', latencyMs: 0 })
    expect((await rejection(c.unlock('wrong wrong wrong'))).code).toBe('QG_LOCAL_PASSPHRASE')
    expect((await c.unlock(PASS)).first_session).toBe(true)
  })

  it('requires an unlocked session', async () => {
    const c = createMockClient({ persona: 'aiko', latencyMs: 0 })
    expect((await rejection(c.listFiles())).code).toBe('QG_NO_SESSION')
  })
})

describe('files', () => {
  it('protects a file, emits phases, and lists it', async () => {
    const c = await unlocked('aiko')
    const phases: ProtectProgress['phase'][] = []
    const file = new File([new Uint8Array(2_500_000)], 'Mock-sample-plate.csv')
    const res = await c.protectFile(
      { file, classification: 'confidential', recipient_user_ids: [person('mira').user_id] },
      (p) => phases.push(p.phase),
    )
    expect(phases[0]).toBe('encrypting')
    expect(phases.filter((p) => p === 'encrypting')).toHaveLength(3)
    expect(phases).toContain('uploading')
    expect(phases).toContain('wrapping')
    expect(phases.slice(-2)).toEqual(['committing', 'done'])
    const list = await c.listFiles({ q: 'mock-sample' })
    expect(list.map((f) => f.file_id)).toEqual([res.file.file_id])
    const opened = await c.openFile(res.file.file_id)
    expect(await opened.blob.text()).toContain('Mock content')
  })

  it('cancels protect through AbortSignal', async () => {
    const c = await unlocked('aiko')
    const ctl = new AbortController()
    ctl.abort()
    const e = await rejection(c.protectFile({ file: new File(['x'], 'a.txt'), classification: 'internal', recipient_user_ids: [] }, undefined, ctl.signal))
    expect(e.code).toBe('QG_LOCAL_CANCELLED')
  })

  it('reports a catch-up share for a second device without a slot', async () => {
    const c = await unlocked('aiko')
    const tablet = (await c.listFiles()).find((f) => f.name === 'Assay-results-batch-41.xlsx')!
    // Aiko's tablet lacks a slot; the laptop has one, so open works and a pending share exists.
    expect(tablet.can_open).toBe(true)
    expect((await c.pendingWork()).shares.length).toBeGreaterThan(0)
  })
})

describe('incidents', () => {
  it('report lost creates an incident that reaches contained after runPendingWork', async () => {
    const c = await unlocked('priya')
    const phone = (await c.listDevices('mine')).find((d) => d.name === "Priya's Phone")!
    const lostAt = new Date(Date.now() - 3 * 3_600_000).toISOString()
    const res = await c.reportLost(phone.device_id, { lost_at: lostAt })
    expect(res.time_to_enforce_ms).toBeGreaterThanOrEqual(20)
    expect(res.time_to_enforce_ms).toBeLessThanOrEqual(60)
    expect((await c.reportLost(phone.device_id, { lost_at: lostAt })).incident_id).toBe(res.incident_id)
    const before = await c.getIncident(res.incident_id)
    expect(before.status).not.toBe('closed')
    const e = await rejection(c.closeIncident(res.incident_id))
    expect(e.reason).toBe(before.counts.pending > 0 ? 'rekey_pending' : e.reason)
    await c.runPendingWork()
    expect((await c.pendingWork()).rekeys).toEqual([])
    const after = await c.getIncident(res.incident_id)
    expect(after.status).toBe('contained')
    expect(after.counts.pending).toBe(0)
    expect(after.timeline.map((s) => s.step)).toContain('rekey_done')
    expect((await c.closeIncident(res.incident_id)).status).toBe('closed')
  })

  it('refuses reporting the current device', async () => {
    const c = await unlocked('priya')
    const cur = (await c.listDevices()).find((d) => d.is_current)!
    const e = await rejection(c.reportLost(cur.device_id, { lost_at: new Date().toISOString() }))
    expect(e.code).toBe('QG_DENY_POLICY')
  })
})

describe('roles and changes', () => {
  it('refuses approving your own change', async () => {
    const c = await unlocked('mira')
    const ch = await c.requestChange({ type: 'role_grant', target_user_id: person('aiko').user_id, role: 'operator', reason: 'Cover leave' })
    expect(ch.approvals_required).toBe(2)
    const e = await rejection(c.approveChange(ch.id))
    expect(e.code).toBe('QG_DENY_POLICY')
    expect(e.reason).toBe('self_approval')
  })

  it('refuses an employee listing alerts', async () => {
    const c = await unlocked('aiko')
    const e = await rejection(c.listAlerts())
    expect(e.code).toBe('QG_DENY_POLICY')
    expect(e.reason).toBe('role_required')
  })

  it('lets an operator list the seeded alerts', async () => {
    const c = await unlocked('priya')
    const alerts = await c.listAlerts()
    expect(alerts.map((a) => a.rule_id).sort()).toEqual(['QG-R001', 'QG-R005', 'QG-R009'])
  })
})

describe('controls', () => {
  it('setOffline makes calls reject with QG_OFFLINE', async () => {
    const c = await unlocked('aiko')
    c.control.setOffline(true)
    expect((await rejection(c.listFiles())).code).toBe('QG_OFFLINE')
    expect((await rejection(c.meta())).code).toBe('QG_OFFLINE')
    c.control.setOffline(false)
    await expect(c.listFiles()).resolves.toBeInstanceOf(Array)
  })

  it('expireSession, failNext and revokeCurrentDevice', async () => {
    const c = await unlocked('aiko')
    c.control.failNext('QG_RATE_LIMITED', 'slow_down')
    expect((await rejection(c.listFiles())).reason).toBe('slow_down')
    await c.listFiles()
    c.control.expireSession()
    expect(c.getState().kind).toBe('locked')
    expect((await rejection(c.listFiles())).code).toBe('QG_NO_SESSION')
    await c.unlock(PASS)
    c.control.revokeCurrentDevice()
    expect(c.getState().kind).toBe('revoked')
    expect((await rejection(c.listFiles())).code).toBe('QG_DENY_REVOKED')
  })
})

describe('verification', () => {
  it('verifies a receipt with believable steps', async () => {
    const c = await unlocked('jonas')
    const page = await c.listReceipts({ limit: 5 })
    const steps: VerifyStep[] = []
    const res = await c.verifyReceipt(page.items[0].id, (s) => steps.push(s))
    expect(res.ok).toBe(true)
    expect(steps[0].kind).toBe('receipt')
    const nodes = steps.filter((s) => s.kind === 'node').length
    expect(nodes).toBeGreaterThanOrEqual(5)
    expect(nodes).toBeLessThanOrEqual(7)
    expect(steps.filter((s) => s.kind === 'signature')).toHaveLength(2)
  })

  it('passes an exported bundle and fails a tampered one', async () => {
    const c = await unlocked('priya')
    const incs = await c.listIncidents()
    const bundle = await c.exportBundle(incs[0].id)
    expect((await c.verifyBundle(bundle)).ok).toBe(true)

    const edited = JSON.parse(JSON.stringify(bundle)) as Record<string, unknown>
    edited.incident_id = 'inc_edited'
    ;(edited.exposure as Record<string, unknown>).compromise_time = '2020-01-01T00:00:00.000Z'
    const steps: VerifyStep[] = []
    const bad = await c.verifyBundle(edited, (s) => steps.push(s))
    expect(bad.ok).toBe(false)
    expect(bad.failed_index).not.toBeNull()
    expect(steps.find((s) => s.kind === 'root')).toMatchObject({ ok: false })

    const flagged = await c.verifyBundle({ receipts: [], tampered: true })
    expect(flagged.ok).toBe(false)
    expect(flagged.failed_index).not.toBeNull()
  })
})
