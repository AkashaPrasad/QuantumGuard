import { readFile, writeFile } from 'node:fs/promises'
import type { Page } from '@playwright/test'
import { PASSPHRASE, device, expect, fileRow, goto, openFileText, protect, test, visit } from './helpers'

// The hero journey against the real server: two people, three devices (plus the operator who exports the proof).

const FILE = 'assay-results-batch-41.txt'
const TEXT = 'batch 41: all wells within tolerance'
const deviceRow = (page: Page, name: string) => page.locator('[data-testid^="device-row-"]').filter({ hasText: name })

async function unlock(page: Page): Promise<void> {
  await page.goto('/app/files')
  await page.getByTestId('unlock-passphrase').fill(PASSPHRASE)
  await page.getByTestId('unlock-submit').click()
  await expect(page.getByTestId('user-menu')).toBeVisible()
}

test('hero journey: protect, share, lose a device, re-key, contain, prove', async ({ live }, testInfo) => {
  test.setTimeout(180_000)
  // The lost phone keeps asking after it is cut off; those refusals are the point.
  live.refusals.expect({ code: 'QG_DENY_REVOKED' })

  const laptop = await device(live, 'Aiko Tanaka', 'Aiko laptop')
  const colleague = await device(live, 'Daniel Mensah', 'Daniel laptop')

  // Protect on the laptop for Daniel; Daniel opens it.
  await protect(laptop.page, FILE, TEXT, { with: ['Daniel Mensah'], level: 'confidential' })
  await expect(fileRow(laptop.page, FILE)).toContainText('Confidential')
  expect(await openFileText(colleague.page, FILE)).toBe(TEXT)

  // A second device for Aiko catches up: the laptop shares to it by itself.
  const phone = await device(live, 'Aiko Tanaka', 'Aiko phone')
  await expect(laptop.page.getByTestId('rekey-done')).toContainText('Your other device can now open your files', { timeout: 30_000 })
  expect(await openFileText(phone.page, FILE)).toBe(TEXT)

  // Daniel steps away (his tab closes), so the laptop is the one that re-keys.
  await colleague.page.goto('about:blank')

  // Report the phone lost an hour ago, from the laptop.
  await goto(laptop.page, 'Devices')
  await deviceRow(laptop.page, 'Aiko phone').getByRole('button', { name: 'Report lost' }).click()
  const dialog = laptop.page.getByTestId('revoke-dialog')
  await dialog.getByTestId('report-preset-hour').check({ force: true })
  await dialog.getByTestId('report-note').fill('left on the train')
  await dialog.getByTestId('report-confirm').click()
  const result = laptop.page.getByTestId('report-result')
  await expect(result).toContainText('Access removed from Aiko phone')
  await expect(result.getByTestId('report-enforce-ms')).toHaveText(/^\d+\s*ms$/)
  await expect(result.getByTestId('revoke-scope')).toContainText(/1 file was opened after that time/)

  // The lost phone is cut off: its next request is refused and it shows the access-removed page.
  await phone.page.reload()
  await phone.page.getByTestId('unlock-passphrase').fill(PASSPHRASE)
  await phone.page.getByTestId('unlock-submit').click()
  await expect(phone.page.getByTestId('revoked-page')).toContainText('Access removed from this device')
  expect((await live.refusals.with('QG_DENY_REVOKED')).length).toBeGreaterThan(0)

  // The laptop re-keys the exposed file by itself.
  await laptop.page.getByTestId('revoke-done').click()
  await expect(laptop.page.getByTestId('rekey-done')).toContainText('All affected files have new keys', { timeout: 60_000 })

  // The incident reaches contained, with the phone's attempts counted.
  await goto(laptop.page, 'Devices')
  await deviceRow(laptop.page, 'Aiko phone').getByRole('link').first().click()
  await expect(laptop.page).toHaveURL(/\/app\/ops\/incidents\/inc_/)
  const incidentUrl = laptop.page.url()
  await expect(laptop.page.getByTestId('incident-status')).toContainText('Contained')
  await expect(laptop.page.getByTestId('incident-step-rekey_done')).toBeVisible()
  // The page refreshes a settled incident every 15 s.
  await expect(laptop.page.getByTestId('incident-step-denied_attempt').first()).toBeVisible({ timeout: 20_000 })
  const deniedFigure = laptop.page.locator('div.label-caps', { hasText: 'Attempts denied' }).locator('xpath=following-sibling::div[1]')
  await expect(deniedFigure).toHaveText(/^[1-9]\d*$/)

  // Daniel comes back and still opens the re-keyed file.
  await unlock(colleague.page)
  expect(await openFileText(colleague.page, FILE)).toBe(TEXT)
  await expect(fileRow(colleague.page, FILE)).not.toContainText('New key pending')

  // The receipt of that open verifies on Daniel's device with the stamp.
  await fileRow(colleague.page, FILE).getByTestId('file-receipt-link').click()
  await expect(colleague.page.getByTestId('verify-result')).toContainText('Verified on this device', { timeout: 30_000 })
  await expect(colleague.page.getByTestId('receipt-stamp')).toBeVisible()

  // The operator exports the proof bundle and verifies it; a tampered copy fails at an entry.
  const ops = await device(live, 'Priya Raman', 'Priya desk')
  await visit(ops.page, new URL(incidentUrl).pathname)
  await expect(ops.page.getByTestId('incident-status')).toContainText('Contained')
  const download = ops.page.waitForEvent('download')
  await ops.page.getByTestId('incident-export').click()
  const saved = await (await download).path()
  await ops.page.getByTestId('incident-verify').click()
  await expect(ops.page.getByTestId('verify-result')).toHaveAttribute('data-ok', 'true', { timeout: 30_000 })
  await expect(ops.page.getByTestId('verify-result')).toContainText('Verified on this device')

  const bundle = JSON.parse(await readFile(saved, 'utf8')) as { entries: { leaf_index: number; receipt: { decision: string } }[] }
  expect(bundle.entries.length).toBeGreaterThan(1)
  const target = bundle.entries[1]!
  target.receipt.decision = target.receipt.decision === 'allow' ? 'deny' : 'allow'
  const tampered = testInfo.outputPath('tampered-bundle.json')
  await writeFile(tampered, JSON.stringify(bundle))
  await goto(ops.page, 'Verify')
  await ops.page.getByRole('group', { name: 'What to verify' }).getByRole('button', { name: 'A proof bundle' }).click()
  await ops.page.getByTestId('verify-file-input').setInputFiles(tampered)
  await expect(ops.page.getByTestId('verify-result')).toHaveAttribute('data-ok', 'false', { timeout: 30_000 })
  await expect(ops.page.getByTestId('verify-failed-index')).toHaveText(`#${target.leaf_index}`)
})
