import type { Page } from '@playwright/test'
import { device, expect, goto, startEnrol, test } from './helpers'

const rows = (page: Page) => page.locator('[data-testid^="receipt-row-"]')

test('auditor: log, filters, find by id, verify with the stamp', async ({ live }) => {
  // A refused enrolment puts a deny in the log whatever ran before.
  live.refusals.expect({ code: 'QG_INVALID_INPUT', reason: 'invite_invalid' })
  const stranger = await live.newDevice()
  await startEnrol(stranger.page, 'ZZZZ-ZZZZ-ZZZZ-ZZZZ', 'Stranger laptop')
  await expect(stranger.page.getByTestId('enrol-error')).toContainText('That code did not work')

  const jonas = await device(live, 'Jonas Weber', 'Jonas desk')
  await goto(jonas.page, 'Log')
  await expect(jonas.page.getByTestId('evidence-list')).toBeVisible()
  await expect(jonas.page.getByTestId('evidence-checkpoint')).toContainText('Signed with Ed25519 and ML-DSA-65.')
  await expect(rows(jonas.page).first()).toBeVisible()
  const all = await rows(jonas.page).count()

  await jonas.page.getByTestId('filter-decision-deny').click()
  await expect(rows(jonas.page).first()).toContainText('Denied')
  for (const row of await rows(jonas.page).all()) await expect(row).toContainText('Denied')
  await jonas.page.getByTestId('filter-decision-allow').click()
  await expect(rows(jonas.page).first()).toContainText('Allowed')
  for (const row of await rows(jonas.page).all()) await expect(row).not.toContainText('Denied')
  await jonas.page.getByTestId('filter-decision-all').click()
  await expect.poll(() => rows(jonas.page).count()).toBeGreaterThanOrEqual(all)

  await jonas.page.getByTestId('filter-action').selectOption({ index: 1 })
  const label = (await jonas.page.getByTestId('filter-action').locator('option:checked').textContent())!.trim()
  await expect(rows(jonas.page).first()).toContainText(label)
  await jonas.page.getByTestId('filter-action').selectOption({ index: 0 })

  // Find the newest receipt by its id and verify it from its sheet.
  await rows(jonas.page).first().getByRole('button').click()
  const sheet = jonas.page.getByTestId('receipt-sheet')
  const id = (await sheet.getByTestId('receipt-slip').getAttribute('data-receipt-id'))!
  expect(id).toMatch(/^rcp_/)
  await jonas.page.keyboard.press('Escape')
  await jonas.page.getByTestId('evidence-find-input').fill(id)
  await jonas.page.getByTestId('evidence-find').click()
  await jonas.page.getByTestId('evidence-lookup').getByRole('button', { name: `Open receipt ${id}` }).click()
  await expect(sheet.getByTestId('receipt-slip')).toHaveAttribute('data-receipt-id', id)
  await sheet.getByTestId('receipt-verify').click()
  await expect(sheet.getByTestId('receipt-stamp')).toContainText('Verified on this device', { timeout: 30_000 })
})

test('policy page: the rules, and a bundle hash equal to meta.policy_bundle_hash', async ({ live, request }) => {
  const meta = (await (await request.get('/api/v1/meta')).json()) as { policy_bundle_hash: string }
  const jonas = await device(live, 'Jonas Weber', 'Jonas desk (policy)')
  await goto(jonas.page, 'Policy')
  await expect(jonas.page.getByTestId('policy-header')).toContainText(meta.policy_bundle_hash)
  await expect(jonas.page.getByTestId('policy-rule-P-SELF-SERVICE')).toBeVisible()
  await expect(jonas.page.getByTestId('policy-rule-D-DECOY')).toContainText('Deny')
  expect(await jonas.page.locator('[data-testid^="policy-rule-"]').count()).toBeGreaterThan(10)
})
