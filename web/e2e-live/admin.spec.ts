import type { Page } from '@playwright/test'
import { device, enrol, expect, goto, invitePerson, test } from './helpers'

const inviteRow = (page: Page, name: string) => page.locator('[data-testid^="invite-row-"]').filter({ hasText: name })
const personRow = (page: Page, name: string) => page.locator('[data-testid^="person-row-"]').filter({ hasText: name })
const changeRow = (page: Page, text: string) => page.locator('[data-testid^="change-row-"]').filter({ hasText: text })

async function openChange(page: Page, text: string) {
  await goto(page, 'Change requests')
  await page.getByRole('group', { name: 'Filter by status' }).getByRole('button', { name: 'All' }).click()
  await changeRow(page, text).first().click()
  const sheet = page.getByTestId('change-sheet')
  await expect(sheet).toBeVisible()
  return sheet
}

test('invite a new employee and enrol them; invite an operator creates a change; cancel a pending code', async ({ live }) => {
  const mira = await device(live, 'Mira Okafor', 'Mira desk (admin)')

  // A new employee gets a code at once and enrols with it.
  const code = await invitePerson(mira.page, 'Sam Rivera')
  expect(code).toMatch(/^[0-9A-Z]{4}(-[0-9A-Z]{4}){3}$/)
  const sam = await live.newDevice()
  await enrol(sam.page, code!, 'Sam laptop')
  await expect(sam.page.getByRole('heading', { name: 'Files', level: 1 })).toBeVisible()
  // Sam renames the new device (a new directory epoch on the server).
  await goto(sam.page, 'Devices')
  await sam.page.locator('[data-testid^="device-row-"]').filter({ hasText: 'Sam laptop' }).getByRole('button', { name: 'Rename' }).click()
  await sam.page.getByRole('textbox', { name: 'Device name' }).fill('Sam work laptop')
  await sam.page.getByRole('button', { name: 'Save' }).click()
  await expect(sam.page.locator('[data-testid^="device-row-"]').filter({ hasText: 'Sam work laptop' })).toBeVisible()
  await expect(sam.page.getByTestId('device-chip')).toContainText('Sam work laptop')
  // The People page caches its lists for a few seconds; come back until the used code shows.
  await expect(async () => {
    await goto(mira.page, 'Files')
    await goto(mira.page, 'People')
    await expect(inviteRow(mira.page, 'Sam Rivera')).toContainText('Used', { timeout: 2_000 })
  }).toPass({ timeout: 20_000 })
  await expect(personRow(mira.page, 'Sam Rivera')).toContainText('Employee')

  // An operator needs a second admin first: a change, no code.
  expect(await invitePerson(mira.page, 'Ola Berg', 'Operator')).toBeNull()
  await goto(mira.page, 'Change requests')
  await expect(mira.page.getByTestId('changes-list')).toContainText('Ola Berg')

  // A pending code can be cancelled.
  await invitePerson(mira.page, 'Kay Ndlovu')
  const row = inviteRow(mira.page, 'Kay Ndlovu')
  await expect(row).toContainText('Pending')
  await row.getByRole('button', { name: 'Cancel code for Kay Ndlovu' }).click()
  await expect(row).toContainText('Cancelled')
  await expect(row.getByRole('button', { name: /Cancel code/ })).toHaveCount(0)
})

test('role grant needs a second admin; reject with a reason; the dialog offers only applicable roles', async ({ live }) => {
  const mira = await device(live, 'Mira Okafor', 'Mira desk (roles)')
  const tomas = await device(live, 'Tomas Lindqvist', 'Tomas desk (roles)')
  const code = await invitePerson(mira.page, 'Noor Haddad')
  const noor = await live.newDevice()
  await enrol(noor.page, code!, 'Noor laptop')

  // Granting offers only roles Noor does not hold; removing only the one she holds.
  await goto(mira.page, 'People')
  await mira.page.getByRole('button', { name: 'More actions for Noor Haddad' }).click()
  await mira.page.getByRole('menuitem', { name: 'Change role' }).click()
  const dialog = mira.page.getByRole('dialog', { name: 'Change role for Noor Haddad' })
  const options = () => dialog.getByTestId('change-role').locator('option').allTextContents()
  expect(await options()).toEqual(['Auditor', 'Operator', 'Admin'])
  await dialog.getByText('Remove a role').click()
  expect(await options()).toEqual(['Employee'])
  await dialog.getByText('Grant a role').click()

  // Mira requests Operator for Noor; she cannot approve her own request.
  await dialog.getByTestId('change-role').selectOption({ label: 'Operator' })
  await dialog.getByTestId('change-reason').fill('Noor joins the on-call rota')
  await dialog.getByTestId('change-submit').click()
  await expect(mira.page.getByRole('dialog', { name: 'Change requested for Noor Haddad' })).toBeVisible()
  await mira.page.keyboard.press('Escape')
  const mine = await openChange(mira.page, 'Noor Haddad')
  await expect(mine).toContainText('0 of 1 approvals')
  await expect(mine.getByTestId('change-self-note')).toBeVisible()
  await expect(mine.getByTestId('change-approve')).toBeDisabled()

  // Tomas checks the signed statement and approves; the directory shows the role.
  const theirs = await openChange(tomas.page, 'Noor Haddad')
  await theirs.getByTestId('change-approve').click()
  await expect(theirs).toContainText('Applied')
  await tomas.page.keyboard.press('Escape')
  await mira.page.keyboard.press('Escape')
  await expect(mine).toBeHidden()
  // Mira's page caches the directory for a few seconds; come back until the new epoch shows.
  await expect(async () => {
    await goto(mira.page, 'Files')
    await goto(mira.page, 'People')
    await expect(personRow(mira.page, 'Noor Haddad')).toContainText('Operator', { timeout: 2_000 })
  }).toPass({ timeout: 20_000 })

  // The privileged invite (created by the server, unsigned) is rejected by Tomas with a reason.
  expect(await invitePerson(mira.page, 'Ilse Brandt', 'Admin')).toBeNull()
  const invite = await openChange(tomas.page, 'Ilse Brandt')
  await invite.getByTestId('change-reject').click()
  await invite.getByLabel('Reason for rejecting').fill('Hiring for this role is paused')
  await invite.getByTestId('change-reject-confirm').click()
  await expect(invite.getByText('Rejected')).toBeVisible()
  await tomas.page.keyboard.press('Escape')
  await tomas.page.getByRole('group', { name: 'Filter by status' }).getByRole('button', { name: 'Rejected' }).click()
  await expect(changeRow(tomas.page, 'Ilse Brandt')).toBeVisible()
})
