import { expect, test, PASSPHRASE, goto, mock, sampleFile, unlockAs } from './helpers'

test.use({ reducedMotion: 'reduce' })

test.describe('reduced motion keeps the text equivalents', () => {
  test('enrolment completes and shows the step list', async ({ page }) => {
    await page.goto('/app/enrol?persona=none')
    expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true)
    await page.getByTestId('enrol-code').fill('KESTREL-AIKO')
    await page.getByTestId('enrol-next').click()
    await page.getByTestId('enrol-next').click()
    await page.getByTestId('enrol-passphrase').fill(PASSPHRASE)
    await page.getByTestId('enrol-passphrase-confirm').fill(PASSPHRASE)
    await page.getByTestId('enrol-create').click()
    const list = page.getByTestId('enrol-progress')
    await expect(list).toBeVisible()
    await expect(page.getByTestId('enrol-done')).toBeVisible()
    await expect(list.locator('li[data-state="done"]')).toHaveCount(5)
    for (const text of ['Keys created on this device', 'Possession of both private keys proved', 'Certificate issued and directory updated', 'Private keys locked under your passphrase', 'Session started']) {
      await expect(list).toContainText(text)
    }
    await expect(page.getByRole('img', { name: /./ }).first()).toBeVisible()
    await page.getByTestId('enrol-done').click()
    await expect(page.getByRole('heading', { name: 'Files', level: 1 })).toBeVisible()
  })

  test('protect shows a progress bar and a per-device checklist, then the receipt', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await mock(page).setLatency(600)
    await page.getByTestId('files-protect').click()
    await page.getByTestId('protect-file-input').setInputFiles(sampleFile('calm.txt'))
    await page.getByLabel('Mira Okafor').check()
    await page.getByTestId('protect-submit').click()
    const progress = page.getByTestId('protect-progress')
    await expect(progress.getByRole('progressbar', { name: 'Encrypting' })).toBeVisible()
    await expect(progress.getByTestId('wrap-beams')).toBeVisible()
    await expect(progress.getByRole('status')).toContainText(/Encrypting|Sending|Wrapping|Signing/)
    await expect(progress.getByTestId('wrap-beams').getByText('key wrapped').first()).toBeAttached({ timeout: 20_000 })
    await expect(page.getByTestId('protect-receipt')).toBeVisible({ timeout: 20_000 })
    await expect(page.getByTestId('receipt-slip')).toBeVisible()
  })

  test('verify lists the steps top to bottom and reaches a verified result', async ({ page }) => {
    await unlockAs(page, 'jonas')
    await goto(page, 'Log')
    await expect(page.getByTestId('evidence-list')).toBeVisible()
    await page.locator('[data-testid^="receipt-row-"]').first().getByRole('button').click()
    const id = await page.getByTestId('receipt-sheet').getByTestId('receipt-slip').getAttribute('data-receipt-id')
    await page.keyboard.press('Escape')
    await expect(page.getByTestId('receipt-sheet')).toBeHidden()
    await goto(page, 'Verify')
    await page.getByTestId('verify-input').fill(id!)
    await page.getByTestId('verify-submit').click()
    const steps = page.getByTestId('verify-steps')
    await expect(steps).toContainText('Steps checked on this device')
    await expect(steps.locator('ol')).toHaveCSS('flex-direction', 'column')
    await expect(steps).toContainText(/Receipt hashed as log entry #\d+/)
    await expect(page.getByTestId('verify-result')).toContainText('Verified on this device', { timeout: 20_000 })
    await expect(steps).toContainText('Computed root matches the signed checkpoint')
  })

  test('the report-lost result still shows its figures', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await goto(page, 'Devices')
    await page.locator('[data-testid^="device-row-"]').filter({ hasText: 'Lab bench tablet' }).getByRole('button', { name: 'Report lost' }).click()
    await page.getByTestId('report-confirm').click()
    await expect(page.getByTestId('report-enforce-ms')).toHaveText(/^\d+\s*ms$/)
  })
})
