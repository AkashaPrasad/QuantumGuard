import type { Page } from '@playwright/test'
import { PASSPHRASE, device, expect, goto, invitePerson, issueCodes, openFileText, protect, startEnrol, test } from './helpers'

async function unlockPage(page: Page, passphrase: string) {
  await page.getByTestId('unlock-passphrase').fill(passphrase)
  await page.getByTestId('unlock-submit').click()
}

test('wrong enrolment code; reload locks and unlock restores; wrong passphrase; lock overlay; enrolment held during a loss report', async ({ live }) => {
  test.setTimeout(150_000)
  // A person of their own: the hold this test causes must not reach anyone else.
  const mira = await device(live, 'Mira Okafor', 'Mira desk (resilience)')
  const code = await invitePerson(mira.page, 'Rui Costa')
  await goto(mira.page, 'People')
  const ruiId = (await mira.page.locator('[data-testid^="person-row-"]').filter({ hasText: 'Rui Costa' }).getAttribute('data-testid'))!.replace('person-row-', '')
  const rui = await live.newDevice()

  // A wrong code is refused and kept for correction; the right one then works from the same page.
  live.refusals.expect({ code: 'QG_INVALID_INPUT', reason: 'invite_invalid' })
  await startEnrol(rui.page, 'K7QM-2XVD-9RTA-HB4N', 'Rui laptop')
  await expect(rui.page.getByTestId('enrol-error')).toContainText('That code did not work')
  await expect(rui.page.getByTestId('enrol-code')).toHaveValue('K7QM-2XVD-9RTA-HB4N')
  await rui.page.getByTestId('enrol-code').fill(code!)
  await rui.page.getByTestId('enrol-next').click()
  await rui.page.getByTestId('enrol-next').click()
  await rui.page.getByTestId('enrol-passphrase').fill(PASSPHRASE)
  await rui.page.getByTestId('enrol-passphrase-confirm').fill(PASSPHRASE)
  await rui.page.getByTestId('enrol-create').click()
  await rui.page.getByTestId('enrol-done').click()
  await expect(rui.page.getByTestId('user-menu')).toBeVisible()

  // Reload: the keys are gone from memory, so the device is locked; the passphrase brings it back.
  await rui.page.reload()
  await expect(rui.page).toHaveURL(/\/app\/unlock/)
  await unlockPage(rui.page, 'not the passphrase at all')
  await expect(rui.page.getByTestId('unlock-error')).toBeVisible()
  await unlockPage(rui.page, PASSPHRASE)
  await expect(rui.page.getByTestId('user-menu')).toBeVisible()
  await protect(rui.page, 'cold-room-log.txt', 'cold room 4 C all night')

  // Lock now: the overlay covers the page, and unlocking keeps the page where it was.
  await rui.page.getByTestId('lock-now').click()
  const overlay = rui.page.getByTestId('lock-overlay')
  await expect(overlay).toBeVisible()
  await overlay.getByTestId('unlock-passphrase').fill(PASSPHRASE)
  await overlay.getByTestId('unlock-submit').click()
  await expect(overlay).toBeHidden()
  expect(await openFileText(rui.page, 'cold-room-log.txt')).toBe('cold room 4 C all night')

  // The operator revokes the laptop as lost an hour ago: the file it opened is exposed and nobody else can
  // re-key it, so the loss report stays open, and a new enrolment for Rui is held.
  live.refusals.expect({ code: 'QG_DENY_REVOKED' }, { code: 'QG_QUARANTINED', reason: 'enrolment_held' })
  await rui.page.goto('about:blank')
  const priya = await device(live, 'Priya Raman', 'Priya desk (resilience)')
  await goto(priya.page, 'All devices')
  await priya.page.getByRole('button', { name: 'Revoke Rui laptop' }).click()
  await priya.page.getByTestId('revoke-preset-hour').check({ force: true })
  await priya.page.getByTestId('revoke-reason').fill('laptop left in a taxi')
  await priya.page.getByTestId('revoke-confirm').click()
  await expect(priya.page.getByTestId('revoke-result')).toBeVisible()

  const held = await live.newDevice()
  await startEnrol(held.page, issueCodes([ruiId])['Rui Costa']!.code, 'Rui new laptop')
  const err = held.page.getByTestId('enrol-error')
  await expect(err).toContainText('Enrolment is on hold')
  await expect(err).toContainText('A device of yours was reported lost')
})
