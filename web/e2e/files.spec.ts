import { expect, test, MOBILE, expectNoHorizontalScroll, mock, sampleFile, unlockAs } from './helpers'
import type { Page } from '@playwright/test'

const ASSAY = 'Assay-results-batch-41.xlsx'
const rows = (page: Page) => page.locator('[data-testid^="file-row-"]')
const rowOf = (page: Page, name: string) => rows(page).filter({ hasText: name })

async function openProtect(page: Page) {
  await page.getByTestId('files-protect').click()
  await expect(page.getByTestId('protect-dialog')).toBeVisible()
}

test.describe('files', () => {
  test.beforeEach(async ({ page }) => {
    await unlockAs(page, 'aiko')
    await expect(page.getByTestId('files-list')).toBeVisible()
  })

  test('the list renders with names, sensitivity and who can open', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Files', level: 1 })).toBeVisible()
    await expect(rowOf(page, ASSAY)).toBeVisible()
    await expect(rowOf(page, ASSAY)).toContainText('Confidential')
    await expect(rowOf(page, ASSAY)).toContainText('You and 2 others')
    const n = await rows(page).count()
    expect(n).toBeGreaterThan(3)
    await expect(page.getByText(`${n} of ${n}`)).toBeVisible()
  })

  test('search narrows the list and reports when nothing matches', async ({ page }) => {
    const search = page.getByRole('textbox', { name: 'Find a file' })
    await search.fill('assay')
    await expect(rows(page)).toHaveCount(1)
    await expect(rowOf(page, ASSAY)).toBeVisible()
    await expect(page.getByText(/^1 of \d+$/)).toBeVisible()
    await search.fill('no such file anywhere')
    await expect(page.getByText('No file matches')).toBeVisible()
    await search.fill('')
    await expect(rows(page).first()).toBeVisible()
  })

  test('the sensitivity filter keeps only that sensitivity', async ({ page }) => {
    const filter = page.getByRole('group', { name: 'Filter by sensitivity' })
    const total = await rows(page).count()
    await filter.getByRole('button', { name: 'Restricted' }).click()
    await expect(filter.getByRole('button', { name: 'Restricted' })).toHaveAttribute('aria-pressed', 'true')
    await expect(rowOf(page, 'Compound-K-synthesis-protocol.pdf')).toBeVisible()
    await expect(rowOf(page, ASSAY)).toHaveCount(0)
    expect(await rows(page).count()).toBeLessThan(total)
    for (const row of await rows(page).all()) await expect(row).toContainText('Restricted')
    await filter.getByRole('button', { name: 'All' }).click()
    await expect(rows(page)).toHaveCount(total)
  })

  test('protect a file: recipients, progress, receipt slip, and it is first in the list', async ({ page }) => {
    await mock(page).setLatency(500)
    await openProtect(page)
    await expect(page.getByTestId('protect-submit')).toBeDisabled()
    await page.getByTestId('protect-file-input').setInputFiles(sampleFile())
    await expect(page.getByTestId('protect-drop')).toContainText('e2e-notes.txt')
    await page.getByTestId('protect-level-restricted').check({ force: true })
    await page.getByLabel('Mira Okafor').check()
    await expect(page.getByText('You on', { exact: false })).toBeVisible()
    await page.getByTestId('protect-submit').click()
    const progress = page.getByTestId('protect-progress')
    await expect(progress).toBeVisible()
    await expect(progress).toContainText('Protecting e2e-notes.txt')
    await expect(progress.getByRole('status')).toContainText(/Encrypting|Sending|Wrapping|Signing/)
    const slip = page.getByTestId('protect-receipt')
    await expect(slip).toBeVisible({ timeout: 20_000 })
    await expect(slip.getByRole('heading', { name: 'Protected' })).toBeVisible()
    await expect(slip.getByTestId('receipt-slip')).toBeVisible()
    await page.getByTestId('protect-done').click()
    await expect(page.getByTestId('protect-dialog')).toBeHidden()
    await expect(rows(page).first()).toContainText('e2e-notes.txt')
    await expect(rows(page).first()).toContainText('Restricted')
  })

  test('cancel during protect leaves no new row', async ({ page }) => {
    const before = await rows(page).count()
    await mock(page).setLatency(2000)
    await openProtect(page)
    await page.getByTestId('protect-file-input').setInputFiles(sampleFile('never-saved.txt'))
    await page.getByTestId('protect-submit').click()
    await expect(page.getByTestId('protect-progress')).toBeVisible()
    await page.getByTestId('protect-cancel').click()
    await expect(page.getByTestId('protect-dialog')).toBeHidden()
    await mock(page).setLatency(0)
    await expect(rows(page)).toHaveCount(before)
    await expect(rowOf(page, 'never-saved.txt')).toHaveCount(0)
  })

  test('keyboard only: the dialog takes focus, radios use arrows, Escape closes', async ({ page }) => {
    await page.getByTestId('files-protect').focus()
    await page.keyboard.press('Enter')
    await expect(page.getByRole('button', { name: 'Choose a file' })).toBeFocused()
    await page.getByTestId('protect-file-input').setInputFiles(sampleFile('kbd.txt'))
    await page.getByRole('button', { name: 'Choose another' }).focus()
    await page.keyboard.press('Tab')
    await expect(page.getByTestId('protect-level-confidential')).toBeFocused()
    await page.keyboard.press('ArrowRight')
    await expect(page.getByTestId('protect-level-restricted')).toBeChecked()
    await page.getByTestId('protect-submit').focus()
    await page.keyboard.press('Enter')
    await expect(page.getByTestId('protect-receipt')).toBeVisible({ timeout: 20_000 })
    await page.keyboard.press('Escape')
    await expect(page.getByTestId('protect-dialog')).toBeHidden()
    await page.getByTestId('files-protect').focus()
    await page.keyboard.press('Enter')
    await page.keyboard.press('Escape')
    await expect(page.getByTestId('protect-dialog')).toBeHidden()
  })

  test('open a file: download, checked mark and a receipt link', async ({ page }) => {
    const row = rowOf(page, ASSAY)
    const download = page.waitForEvent('download')
    await row.getByRole('button', { name: `Open ${ASSAY}` }).click()
    expect((await download).suggestedFilename()).toBe(ASSAY)
    await expect(row.getByTestId('file-verified')).toContainText('Checked on this device')
    const link = row.getByTestId('file-receipt-link')
    await expect(link).toHaveAttribute('href', /\/app\/evidence\/verify\?receipt=rcp_/)
    await link.click()
    await expect(page.getByRole('heading', { name: 'Verify', level: 1 })).toBeVisible()
    await expect(page.getByTestId('verify-result')).toContainText('Verified on this device')
  })

  test('a policy denial on open shows the access message with a receipt', async ({ page }) => {
    const row = rowOf(page, ASSAY)
    await mock(page).failNext('QG_DENY_POLICY', 'no_slot')
    await row.getByRole('button', { name: `Open ${ASSAY}` }).click()
    const err = row.getByTestId('file-open-error')
    await expect(err).toContainText('You do not have access to this')
    await expect(err).toContainText('ask the file owner or an admin')
    await expect(row.getByRole('button', { name: `Open ${ASSAY}` })).toContainText('Open again')
    // Trying again works.
    const download = page.waitForEvent('download')
    await row.getByRole('button', { name: `Open ${ASSAY}` }).click()
    await download
    await expect(row.getByTestId('file-verified')).toBeVisible()
  })

  test('the file sheet: share with a person, then back out of removing one, then remove', async ({ page }) => {
    await rowOf(page, ASSAY).getByRole('button', { name: new RegExp(ASSAY) }).first().click()
    const sheet = page.getByTestId('file-sheet')
    await expect(sheet).toBeVisible()
    await expect(page).toHaveURL(/\/app\/files\/fil_/)
    await expect(sheet.getByRole('heading', { name: ASSAY })).toBeVisible()
    await expect(sheet).toContainText('Who can open this')

    const who = sheet.locator('section').filter({ has: page.getByRole('heading', { name: 'Who can open this' }) })

    // Share with Tomas.
    await page.getByTestId('file-share-open').click()
    await sheet.getByLabel('Tomas Lindqvist').check()
    await page.getByTestId('share-submit').click()
    await expect(who.getByRole('listitem').filter({ hasText: 'Tomas Lindqvist' })).toBeVisible()
    await expect(page.getByText('Shared', { exact: true })).toBeVisible()

    // Backing out of a removal changes nothing.
    const priya = who.getByRole('listitem').filter({ hasText: 'Priya Raman' })
    await priya.getByRole('button', { name: 'Remove' }).click()
    await expect(priya).toContainText('Remove access for Priya Raman.')
    await expect(priya).toContainText('the file gets a new key')
    await priya.getByRole('button', { name: 'Cancel' }).click()
    await expect(page.getByTestId('unshare-confirm')).toHaveCount(0)
    await expect(priya).toBeVisible()

    // Confirm it.
    await priya.getByRole('button', { name: 'Remove' }).click()
    await page.getByTestId('unshare-confirm').click()
    await expect(sheet.getByText('New key pending')).toBeVisible()
    await expect(who.getByRole('listitem').filter({ hasText: 'Priya Raman' })).toHaveCount(0)
    // The re-key banner picks it up and finishes.
    await expect(page.getByTestId('rekey-banner').or(page.getByTestId('rekey-done'))).toBeVisible()
    await expect(page.getByTestId('rekey-done')).toBeVisible({ timeout: 20_000 })
  })

  test('the sheet closes with Escape and returns to the list', async ({ page }) => {
    await rowOf(page, ASSAY).getByRole('button', { name: new RegExp(ASSAY) }).first().click()
    await expect(page.getByTestId('file-sheet')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.getByTestId('file-sheet')).toBeHidden()
    await expect(page).toHaveURL(/\/app\/files$/)
  })

  test('opening from the sheet works too', async ({ page }) => {
    await rowOf(page, ASSAY).getByRole('button', { name: new RegExp(ASSAY) }).first().click()
    const download = page.waitForEvent('download')
    await page.getByTestId('file-sheet').getByRole('button', { name: 'Open', exact: true }).click()
    await download
    await expect(page.getByTestId('file-sheet')).toContainText('Opened and checked on this device.')
    await expect(page.getByTestId('file-sheet').getByRole('link', { name: 'View receipt' })).toBeVisible()
  })

  test('the owner can delete a file after confirming', async ({ page }) => {
    await rowOf(page, ASSAY).getByRole('button', { name: new RegExp(ASSAY) }).first().click()
    await page.getByTestId('file-delete').click()
    await page.getByTestId('file-delete-confirm').click()
    await expect(page.getByTestId('file-sheet')).toBeHidden()
    await expect(rowOf(page, ASSAY)).toHaveCount(0)
  })

  test('offline disables Protect and Open and says so', async ({ page, context }) => {
    await context.setOffline(true)
    await expect(page.getByTestId('offline-banner')).toContainText('You are offline. Nothing is sent until the connection returns.')
    await expect(page.getByTestId('files-protect')).toBeDisabled()
    for (const open of await page.getByRole('button', { name: /^Open / }).all()) await expect(open).toBeDisabled()
    await context.setOffline(false)
    await expect(page.getByTestId('files-protect')).toBeEnabled()
    await expect(page.getByTestId('offline-banner')).toBeHidden()
  })

  test('offline inside the dialog disables Protect', async ({ page, context }) => {
    await openProtect(page)
    await page.getByTestId('protect-file-input').setInputFiles(sampleFile())
    await expect(page.getByTestId('protect-submit')).toBeEnabled()
    await context.setOffline(true)
    await expect(page.getByTestId('protect-submit')).toBeDisabled()
    await expect(page.getByText('You are offline. Protecting needs a connection.')).toBeVisible()
  })
})

test.describe('files on a narrow screen', () => {
  test.use({ viewport: MOBILE })
  test('list, dialog and sheet fit without sideways scrolling', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await expect(page.getByTestId('files-list')).toBeVisible()
    await expectNoHorizontalScroll(page)
    await page.getByTestId('files-protect').click()
    await page.getByTestId('protect-file-input').setInputFiles(sampleFile('a-rather-long-file-name-to-test-wrapping-on-phones.txt'))
    await expectNoHorizontalScroll(page)
    await page.keyboard.press('Escape')
    await rowOf(page, ASSAY).getByRole('button', { name: new RegExp(ASSAY) }).first().click()
    await expect(page.getByTestId('file-sheet')).toBeVisible()
    await expectNoHorizontalScroll(page)
  })
})
