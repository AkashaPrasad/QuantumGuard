import { PASSPHRASE, device, expect, goto, test } from './helpers'

const TABLET = 'Daniel ops tablet'

test('operator: revoke with a reason, incident page, correct the loss time, close; QG-R001 alert, acknowledge, lift', async ({ live }) => {
  test.setTimeout(120_000)
  live.refusals.expect({ code: 'QG_DENY_REVOKED' })
  const priya = await device(live, 'Priya Raman', 'Priya desk (ops)')
  const tablet = await device(live, 'Daniel Mensah', TABLET)

  // Revoke from All devices with a reason.
  await goto(priya.page, 'All devices')
  await priya.page.getByTestId('ops-devices-filter').fill('ops tablet')
  await priya.page.getByRole('button', { name: `Revoke ${TABLET}` }).click()
  const dialog = priya.page.getByTestId('revoke-dialog')
  await expect(dialog.getByTestId('revoke-confirm')).toBeDisabled()
  await dialog.getByTestId('revoke-preset-hour').check({ force: true })
  await dialog.getByTestId('revoke-reason').fill('reported stolen by phone')
  await dialog.getByTestId('revoke-confirm').click()
  const result = priya.page.getByTestId('revoke-result')
  await expect(result).toContainText(`Access removed from ${TABLET}`)
  await expect(result.getByTestId('revoke-enforce-ms')).toHaveText(/^\d+\s*ms$/)

  // The incident page: timeline, then correct the loss time (re-scope), then close.
  await priya.page.getByTestId('revoke-open-incident').click()
  await expect(priya.page).toHaveURL(/\/app\/ops\/incidents\/inc_/)
  await expect(priya.page.getByRole('heading', { level: 1 })).toContainText(TABLET)
  await expect(priya.page.getByTestId('incident-step-reported')).toBeVisible()
  await expect(priya.page.getByTestId('incident-step-revoked')).toBeVisible()
  await priya.page.getByTestId('incident-correct-time').click()
  const correct = priya.page.getByTestId('revoke-dialog')
  await expect(correct).toContainText(`Correct the loss time for ${TABLET}`)
  await correct.getByTestId('revoke-preset-yesterday').check({ force: true })
  await correct.getByTestId('revoke-reason').fill('owner remembered the right time')
  await correct.getByRole('button', { name: 'Recalculate scope' }).click()
  await expect(priya.page.getByTestId('revoke-result')).toContainText('Scope recalculated')
  await priya.page.getByTestId('revoke-done').click()
  await expect(priya.page.getByTestId('incident-step-rescoped')).toBeVisible()
  await expect(priya.page.getByTestId('incident-status')).toContainText('Contained')
  await priya.page.getByTestId('incident-close').click()
  await expect(priya.page.getByTestId('incident-status')).toContainText('Closed')
  await expect(priya.page.getByTestId('incident-step-closed')).toBeVisible()

  // The revoked tablet tries again and is refused; QG-R001 fires.
  await tablet.page.reload()
  await tablet.page.getByTestId('unlock-passphrase').fill(PASSPHRASE)
  await tablet.page.getByTestId('unlock-submit').click()
  await expect(tablet.page.getByTestId('revoked-page')).toBeVisible()

  await goto(priya.page, 'Alerts')
  // The newest open QG-R001 alert about Daniel (the list names the person; a revoked device is no longer in the directory).
  const row = priya.page.locator('[data-testid^="alert-row-"][data-status="open"]').filter({ hasText: 'QG-R001' }).filter({ hasText: 'Daniel Mensah' }).first()
  await expect(row).toBeVisible({ timeout: 20_000 })
  await row.click()
  const sheet = priya.page.getByTestId('alert-sheet')
  await expect(sheet.getByTestId('alert-why')).toContainText('revoked')
  await expect(sheet.getByTestId('alert-evidence').getByRole('link', { name: /Check receipt/ }).first()).toBeVisible()
  await expect(sheet.getByTestId('alert-response')).toBeVisible()

  // Lift the response (the device stays revoked; lifting only clears the automatic deny), then acknowledge.
  await sheet.getByTestId('alert-lift').click()
  await priya.page.getByTestId('alert-lift-reason').fill('device is revoked; the deny is redundant')
  await priya.page.getByTestId('alert-lift-confirm').click()
  await expect(sheet.getByTestId('alert-response')).toContainText(/[Ll]ifted/)
  await expect(sheet.getByTestId('alert-lift')).toHaveCount(0)
  await sheet.getByTestId('alert-note').fill('the tablet was already revoked')
  await sheet.getByTestId('alert-ack').click()
  await expect(sheet.getByTestId('alert-ack')).toHaveCount(0)
  await expect(sheet).toContainText('Acknowledged')
})
