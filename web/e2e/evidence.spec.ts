import { readFile, writeFile } from 'node:fs/promises'
import { expect, test, MOBILE, PASSPHRASE, expectNoHorizontalScroll, goto, seedTour, unlockAs } from './helpers'
import type { Page } from '@playwright/test'

const rows = (page: Page) => page.locator('[data-testid^="receipt-row-"]')

async function firstReceiptId(page: Page): Promise<string> {
  await rows(page).first().getByRole('button').click()
  const id = await page.getByTestId('receipt-sheet').getByTestId('receipt-slip').getAttribute('data-receipt-id')
  await page.keyboard.press('Escape')
  await expect(page.getByTestId('receipt-sheet')).toBeHidden()
  return id!
}

test.describe('evidence (Jonas)', () => {
  test.beforeEach(async ({ page }) => {
    await unlockAs(page, 'jonas')
    await goto(page, 'Log')
    await expect(page.getByTestId('evidence-list')).toBeVisible()
  })

  test('the log renders with the checkpoint panel', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Evidence log', level: 1 })).toBeVisible()
    const cp = page.getByTestId('evidence-checkpoint')
    await expect(cp).toContainText('Tree size')
    await expect(cp).toContainText('Root hash')
    await expect(cp).toContainText('Signed with Ed25519 and ML-DSA-65.')
    expect(await rows(page).count()).toBeGreaterThan(10)
  })

  test('filter by decision', async ({ page }) => {
    const all = await rows(page).count()
    await page.getByTestId('filter-decision-deny').click()
    await expect(page.getByTestId('filter-decision-deny')).toHaveAttribute('aria-pressed', 'true')
    await expect(rows(page).first()).toContainText('Denied')
    await expect.poll(async () => rows(page).count()).toBeLessThan(all)
    for (const row of await rows(page).all()) await expect(row).toContainText('Denied')
    await page.getByTestId('filter-decision-allow').click()
    await expect(rows(page).first()).toContainText('Allowed')
    for (const row of await rows(page).all()) await expect(row).not.toContainText('Denied')
  })

  test('filter by action', async ({ page }) => {
    const all = await rows(page).count()
    await page.getByTestId('filter-action').selectOption({ label: 'Key released to open a file' })
    await expect(rows(page).first()).toContainText('Key released to open a file')
    await expect.poll(async () => rows(page).count()).toBeLessThan(all)
    const labels = await rows(page).evaluateAll((els) => els.map((e) => e.querySelectorAll('td')[1]?.textContent?.trim() ?? ''))
    expect(labels.length).toBeGreaterThan(0)
    expect([...new Set(labels)]).toEqual(['Key released to open a file'])
  })

  test('find a receipt by id', async ({ page }) => {
    const id = await firstReceiptId(page)
    await page.getByTestId('evidence-find-input').fill(id)
    await page.getByTestId('evidence-find').click()
    await page.getByTestId('evidence-lookup').getByRole('button', { name: `Open receipt ${id}` }).click()
    await expect(page.getByTestId('receipt-sheet').getByTestId('receipt-slip')).toHaveAttribute('data-receipt-id', id)
  })

  test('an unknown id says not found', async ({ page }) => {
    await page.getByTestId('evidence-find-input').fill('rcp_doesnotexist')
    await page.keyboard.press('Enter')
    await expect(page.getByTestId('evidence-lookup').getByTestId('error-notice')).toContainText('Not found')
  })

  test('a row sheet verifies and shows the stamp', async ({ page }) => {
    await rows(page).first().getByRole('button').click()
    const sheet = page.getByTestId('receipt-sheet')
    await expect(sheet.getByTestId('receipt-stamp')).toHaveCount(0)
    await expect(sheet).toContainText('Not yet checked on this device.')
    await sheet.getByTestId('receipt-verify').click()
    await expect(sheet.getByTestId('receipt-stamp')).toContainText('Verified on this device', { timeout: 20_000 })
    await expect(sheet.getByTestId('receipt-proof-link')).toBeVisible()
  })

  test('keyboard only: Enter on a row button opens the sheet, Escape closes it', async ({ page }) => {
    await rows(page).first().getByRole('button').focus()
    await page.keyboard.press('Enter')
    await expect(page.getByTestId('receipt-sheet')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.getByTestId('receipt-sheet')).toBeHidden()
  })

  test('Load more pages further back in the log', async ({ page }) => {
    const before = await rows(page).count()
    await page.getByRole('button', { name: 'Load more' }).click()
    await expect.poll(async () => rows(page).count()).toBeGreaterThan(before)
  })
})

test.describe('verify page', () => {
  test.beforeEach(async ({ page }) => {
    await unlockAs(page, 'jonas')
    await goto(page, 'Log')
    await expect(page.getByTestId('evidence-list')).toBeVisible()
  })

  test('verify a receipt id from the log: steps appear, result verified', async ({ page }) => {
    const id = await firstReceiptId(page)
    await goto(page, 'Verify')
    await expect(page.getByText('What this proves')).toBeVisible()
    await page.getByTestId('verify-input').fill(id)
    await page.getByTestId('verify-submit').click()
    const steps = page.getByTestId('verify-steps')
    await expect(steps).toBeVisible()
    await expect(steps).toContainText(/Receipt hashed as log entry #\d+/)
    await expect(steps).toContainText('Computed root matches the signed checkpoint')
    const result = page.getByTestId('verify-result')
    await expect(result).toContainText('Verified on this device', { timeout: 20_000 })
    await expect(result).toHaveAttribute('data-ok', 'true')
    await expect(page.getByTestId('receipt-stamp')).toBeVisible()
  })

  test('keyboard only: the field, Tab, Enter', async ({ page }) => {
    const id = await firstReceiptId(page)
    await goto(page, 'Verify')
    await page.getByTestId('verify-input').focus()
    await page.keyboard.type(id)
    await page.keyboard.press('Enter')
    await expect(page.getByTestId('verify-result')).toContainText('Verified on this device', { timeout: 20_000 })
  })

  test('an unknown receipt id shows an error with a Try again button', async ({ page }) => {
    await goto(page, 'Verify')
    await page.getByTestId('verify-input').fill('rcp_nope')
    await page.getByTestId('verify-submit').click()
    await expect(page.getByTestId('error-notice')).toContainText('Not found')
    await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible()
  })

  test('a tampered bundle shows the failing entry number', async ({ page, context }, testInfo) => {
    // Export a real bundle as the operator, in her own page.
    const operator = await context.newPage()
    await seedTour(operator)
    await unlockAs(operator, 'priya')
    await goto(operator, 'Incidents')
    await operator.locator('[data-testid^="incident-row-"]').first().getByRole('link').click()
    const download = operator.waitForEvent('download')
    await operator.getByTestId('incident-export').click()
    const file = await (await download).path()
    const bundle = JSON.parse(await readFile(file, 'utf8')) as { receipts: Record<string, unknown>[] }
    expect(bundle.receipts.length).toBeGreaterThan(2)
    const good = testInfo.outputPath('good-bundle.json')
    await writeFile(good, JSON.stringify(bundle))
    bundle.receipts[2]!.tampered = true
    const bad = testInfo.outputPath('tampered-bundle.json')
    await writeFile(bad, JSON.stringify(bundle))

    // Verify both as the auditor, on the auditor's page.
    await goto(page, 'Verify')
    await page.getByRole('group', { name: 'What to verify' }).getByRole('button', { name: 'A proof bundle' }).click()
    await page.getByTestId('verify-file-input').setInputFiles(good)
    await expect(page.getByTestId('verify-result')).toHaveAttribute('data-ok', 'true', { timeout: 20_000 })
    await expect(page.getByTestId('verify-result')).toContainText('Verified on this device')

    await page.getByTestId('verify-file-input').setInputFiles(bad)
    const result = page.getByTestId('verify-result')
    await expect(result).toHaveAttribute('data-ok', 'false', { timeout: 20_000 })
    await expect(result).toContainText('Verification failed')
    await expect(page.getByTestId('verify-failed-index')).toHaveText('#2')
    await expect(page.getByTestId('verify-steps')).toContainText('does not match the signed checkpoint')
  })

  test('a file that is not JSON is refused with a clear message', async ({ page }, testInfo) => {
    const junk = testInfo.outputPath('junk.json')
    await writeFile(junk, 'this is not json')
    await goto(page, 'Verify')
    await page.getByRole('group', { name: 'What to verify' }).getByRole('button', { name: 'A proof bundle' }).click()
    await page.getByTestId('verify-file-input').setInputFiles(junk)
    await expect(page.getByTestId('verify-result')).toContainText('This file is not a proof bundle')
  })

  test('offline: a single receipt needs the network, and the page says so', async ({ page, context }) => {
    await goto(page, 'Verify')
    await expect(page.getByRole('heading', { name: 'Verify', level: 1 })).toBeVisible()
    await context.setOffline(true)
    await expect(page.getByText('You are offline. One receipt needs the network to fetch its proof')).toBeVisible()
    await page.getByTestId('verify-input').fill('rcp_x')
    await expect(page.getByTestId('verify-submit')).toBeDisabled()
  })

  test('the unlock passphrase still works after verifying (sanity for the shared page)', async ({ page }) => {
    await page.getByTestId('lock-now').click()
    await page.getByTestId('lock-overlay').getByTestId('unlock-passphrase').fill(PASSPHRASE)
    await page.keyboard.press('Enter')
    await expect(page.getByTestId('lock-overlay')).toBeHidden()
  })
})

test.describe('evidence on a narrow screen', () => {
  test.use({ viewport: MOBILE })
  test('log, sheet and verify page fit without sideways scrolling', async ({ page }) => {
    await unlockAs(page, 'jonas')
    await goto(page, 'Log')
    await expect(page.getByTestId('evidence-list')).toBeVisible()
    await expectNoHorizontalScroll(page)
    await rows(page).first().getByRole('button').click()
    await expect(page.getByTestId('receipt-sheet')).toBeVisible()
    await expectNoHorizontalScroll(page)
    await page.keyboard.press('Escape')
    await goto(page, 'Verify')
    await expectNoHorizontalScroll(page)
  })
})
