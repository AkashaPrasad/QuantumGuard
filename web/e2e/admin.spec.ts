import { expect, test, MOBILE, expectNoHorizontalScroll, goto, unlockAs } from './helpers'
import type { Page } from '@playwright/test'

async function chooseRole(page: Page, testId: string, label: string) {
  await page.getByTestId(testId).selectOption({ label })
}

const inviteRow = (page: Page, name: string) => page.locator('[data-testid^="invite-row-"]').filter({ hasText: name })

async function requestGrant(page: Page, person: string, role: string, reason: string) {
  await goto(page, 'People')
  await page.getByRole('button', { name: `More actions for ${person}` }).click()
  await page.getByRole('menuitem', { name: 'Change role' }).click()
  await expect(page.getByRole('dialog', { name: `Change role for ${person}` })).toBeVisible()
  await chooseRole(page, 'change-role', role)
  await page.getByTestId('change-reason').fill(reason)
  await page.getByTestId('change-submit').click()
  await expect(page.getByRole('dialog', { name: `Change requested for ${person}` })).toBeVisible()
}

test.describe('admin (Mira)', () => {
  test.beforeEach(async ({ page }) => {
    await unlockAs(page, 'mira')
  })

  test('invite an employee: the code is shown once', async ({ page }) => {
    await goto(page, 'People')
    await page.getByTestId('people-invite').click()
    await page.getByTestId('invite-name').fill('Sam Rivera')
    await page.getByTestId('invite-submit').click()
    const dialog = page.getByRole('dialog', { name: 'Enrolment code for Sam Rivera' })
    await expect(dialog.getByTestId('invite-code')).toHaveText(/^QG-[A-Z0-9]+$/)
    await expect(dialog).toContainText('This code is shown once.')
    await expect(dialog.getByTestId('invite-countdown')).toContainText('Works once')
    await dialog.getByRole('button', { name: 'Close' }).first().click()
    await expect(page.getByTestId('invite-code')).toHaveCount(0)
    await expect(inviteRow(page, 'Sam Rivera')).toContainText('Pending')
  })

  test('keyboard only: type a name, press Enter, get a code', async ({ page }) => {
    await goto(page, 'People')
    await page.getByTestId('people-invite').focus()
    await page.keyboard.press('Enter')
    await expect(page.getByTestId('invite-name')).toBeFocused()
    await page.keyboard.type('Kay Ndlovu')
    await page.keyboard.press('Enter')
    await expect(page.getByTestId('invite-code')).toBeVisible()
  })

  test('invite an operator: "Sent for approval" with a link to Change requests', async ({ page }) => {
    await goto(page, 'People')
    await page.getByTestId('people-invite').click()
    await page.getByTestId('invite-name').fill('Ola Berg')
    await chooseRole(page, 'invite-role', 'Operator')
    await expect(page.getByText('Needs approval from a second admin before the code is issued.')).toBeVisible()
    await page.getByTestId('invite-submit').click()
    const dialog = page.getByRole('dialog', { name: 'Sent for approval' })
    await expect(dialog).toBeVisible()
    await expect(page.getByTestId('invite-code')).toHaveCount(0)
    await dialog.getByRole('link', { name: 'Change requests' }).click()
    await expect(page).toHaveURL(/\/app\/admin\/changes$/)
    await expect(page.getByTestId('changes-list')).toContainText('Grant Operator to Ola Berg')
  })

  test('the name must have two characters', async ({ page }) => {
    await goto(page, 'People')
    await page.getByTestId('people-invite').click()
    await expect(page.getByTestId('invite-submit')).toBeDisabled()
    await page.getByTestId('invite-name').fill('A')
    await expect(page.getByTestId('invite-submit')).toBeDisabled()
    await page.getByTestId('invite-name').fill('Al')
    await expect(page.getByTestId('invite-submit')).toBeEnabled()
  })

  test('cancel a pending code', async ({ page }) => {
    await goto(page, 'People')
    const row = inviteRow(page, 'Daniel Mensah')
    await expect(row).toContainText('Pending')
    await row.getByRole('button', { name: 'Cancel code for Daniel Mensah' }).click()
    await expect(row).toContainText('Cancelled')
    await expect(row.getByRole('button', { name: /Cancel code/ })).toHaveCount(0)
    await expect(page.getByText('Code cancelled')).toBeVisible()
  })

  test('request a role change', async ({ page }) => {
    await requestGrant(page, 'Daniel Mensah', 'Auditor', 'Daniel joins the quarterly review')
    await page.getByRole('dialog').getByRole('link', { name: 'Change requests' }).click()
    await expect(page.getByTestId('changes-list')).toContainText('Grant Auditor to Daniel Mensah')
  })

  test('a role that is already held is refused with a message', async ({ page }) => {
    await goto(page, 'People')
    await page.getByRole('button', { name: 'More actions for Jonas Weber' }).click()
    await page.getByRole('menuitem', { name: 'Change role' }).click()
    await chooseRole(page, 'change-role', 'Auditor')
    await page.getByTestId('change-reason').fill('duplicate on purpose')
    await page.getByTestId('change-submit').click()
    await expect(page.getByRole('dialog').getByTestId('error-notice')).toContainText('That was already done')
  })

  test('Change requests: self-approval is prevented, with a note', async ({ page }) => {
    await requestGrant(page, 'Daniel Mensah', 'Auditor', 'Daniel joins the quarterly review')
    await page.getByRole('dialog').getByRole('link', { name: 'Change requests' }).click()
    await page.getByRole('button', { name: 'Grant Auditor to Daniel Mensah' }).click()
    const sheet = page.getByTestId('change-sheet')
    await expect(sheet).toContainText('0 of 1 approvals')
    await expect(sheet.getByTestId('change-self-note')).toHaveText('A different admin must approve this.')
    await expect(sheet.getByTestId('change-approve')).toBeDisabled()
  })

  test('a request Mira already approved says so and cannot be approved twice', async ({ page }) => {
    await goto(page, 'Change requests')
    await page.getByRole('button', { name: 'Grant Operator to Aiko Tanaka' }).click()
    const sheet = page.getByTestId('change-sheet')
    await expect(sheet).toContainText('1 of 2 approvals')
    await expect(sheet).toContainText('You have already approved this.')
    await expect(sheet.getByTestId('change-approve')).toBeDisabled()
  })

  test('reject a request with a reason', async ({ page }) => {
    await goto(page, 'Change requests')
    await page.getByRole('button', { name: 'Grant Operator to Aiko Tanaka' }).click()
    const sheet = page.getByTestId('change-sheet')
    await sheet.getByTestId('change-reject').click()
    await expect(sheet.getByTestId('change-reject-confirm')).toBeDisabled()
    await sheet.getByLabel('Reason for rejecting').fill('Priya is back on Monday')
    await sheet.getByTestId('change-reject-confirm').click()
    await expect(page.getByText('Change rejected')).toBeVisible()
    await expect(sheet.getByText('Rejected')).toBeVisible()
    await page.keyboard.press('Escape')
    await page.getByRole('group', { name: 'Filter by status' }).getByRole('button', { name: 'Rejected' }).click()
    await expect(page.getByTestId('changes-list')).toContainText('Grant Operator to Aiko Tanaka')
  })

  test('applied requests are listed under Applied', async ({ page }) => {
    await goto(page, 'Change requests')
    await page.getByRole('group', { name: 'Filter by status' }).getByRole('button', { name: 'Applied' }).click()
    await expect(page.getByTestId('changes-list')).toContainText('Grant Auditor to Jonas Weber')
  })

  test('services: rotate a key', async ({ page }) => {
    await goto(page, 'Services')
    const svc = page.locator('[data-testid^="service-row-"]').filter({ hasText: 'Sample tracking service' })
    await expect(svc.locator('[data-testid^="service-key-"]')).toHaveCount(3)
    await svc.getByRole('button', { name: 'Rotate key' }).click()
    const dialog = page.getByRole('dialog', { name: 'Rotate the key for Sample tracking service' })
    await expect(dialog.getByTestId('rotate-submit')).toBeDisabled()
    await expect(dialog.getByTestId('rotate-emergency')).toHaveCount(0) // emergency is for operators
    await dialog.getByTestId('rotate-reason').fill('scheduled quarterly rotation')
    await dialog.getByTestId('rotate-submit').click()
    await expect(page.getByText('Key rotated for Sample tracking service')).toBeVisible()
    await expect(svc.locator('[data-testid^="service-key-"]')).toHaveCount(4)
    await expect(svc.getByText('Active', { exact: true })).toHaveCount(1)
    await expect(svc.getByText('Retiring', { exact: true })).toHaveCount(1)
  })

  test('services: add a service', async ({ page }) => {
    await goto(page, 'Services')
    await page.getByTestId('service-add').click()
    await page.getByTestId('service-name').fill('Freezer telemetry')
    await page.getByTestId('service-add-submit').click()
    await expect(page.getByTestId('services-list')).toContainText('Freezer telemetry')
  })

  test('settings renders the limits and server keys', async ({ page }) => {
    await goto(page, 'Settings')
    const org = page.getByTestId('settings-organisation')
    await expect(org).toContainText('Largest file')
    await expect(org).toContainText('256 MB')
    await expect(org).toContainText('Permission to read lasts')
    await expect(org).toContainText('1 minute')
    await expect(org).toContainText('Unlocked session lasts')
    await expect(org).toContainText('10 minutes idle')
    await expect(page.getByTestId('settings-server-keys')).toContainText('Recovery public key')
  })

  test('settings: the recovery request needs a file and a reason', async ({ page }) => {
    await goto(page, 'Settings')
    await expect(page.getByTestId('recovery-submit')).toBeDisabled()
    await chooseRoleLike(page)
    await page.getByTestId('recovery-reason').fill('Every device that could open it is gone')
    await page.getByTestId('recovery-submit').click()
    await expect(page.getByText('Recovery requested')).toBeVisible()
    await expect(page.locator('[data-testid^="recovery-row-"]')).toHaveCount(1)
  })

  test('settings: theme buttons switch the theme', async ({ page }) => {
    await goto(page, 'Settings')
    await page.getByTestId('theme-dark').click()
    await expect(page.locator('html')).toHaveClass(/dark/)
    await page.getByTestId('theme-light').click()
    await expect(page.locator('html')).not.toHaveClass(/dark/)
  })
})

async function chooseRoleLike(page: Page) {
  const select = page.getByTestId('recovery-file')
  await select.selectOption({ index: 1 })
}

test.describe('admin on a narrow screen', () => {
  test.use({ viewport: MOBILE })
  for (const label of ['People', 'Change requests', 'Services', 'Settings']) {
    test(`${label} fits without sideways scrolling`, async ({ page }) => {
      await unlockAs(page, 'mira')
      await goto(page, label)
      await expect(page.getByRole('heading', { name: label, level: 1 })).toBeVisible()
      await expectNoHorizontalScroll(page)
    })
  }
  test('the invite dialog fits', async ({ page }) => {
    await unlockAs(page, 'mira')
    await goto(page, 'People')
    await page.getByTestId('people-invite').click()
    await page.getByTestId('invite-name').fill('Sam Rivera')
    await page.getByTestId('invite-submit').click()
    await expect(page.getByTestId('invite-code')).toBeVisible()
    await expectNoHorizontalScroll(page)
  })
})
