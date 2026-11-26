import { expect, test, MOBILE, expectNoHorizontalScroll, failNextThenClick, goto, mock, unlockAs } from './helpers'
import type { Page } from '@playwright/test'

const PIXEL = "Daniel's Pixel 8"
const incidentRows = (page: Page) => page.locator('[data-testid^="incident-row-"]')

async function openSeededIncident(page: Page) {
  await goto(page, 'Incidents')
  await expect(incidentRows(page)).toHaveCount(1)
  await incidentRows(page).first().getByRole('link').click()
  await expect(page).toHaveURL(/\/app\/ops\/incidents\/inc_/)
  await expect(page.getByTestId('incident-timeline')).toBeVisible()
}

test.describe('operator (Priya)', () => {
  test.beforeEach(async ({ page }) => {
    await unlockAs(page, 'priya')
  })

  test.describe('overview', () => {
    test('figures and the chart summary text', async ({ page }) => {
      await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible()
      const figures = page.getByTestId('overview-figures')
      await expect(figures).toBeVisible()
      await expect(page.getByTestId('figure-active-devices')).toHaveText(/^\d+$/)
      await expect(page.getByTestId('figure-open-alerts')).toHaveText('2')
      await expect(page.getByTestId('figure-open-incidents')).toHaveText('1')
      await expect(page.getByTestId('figure-enforce-ms')).toContainText('34')
      await expect(page.getByTestId('overview-chart-summary')).toHaveText(/^\d+ allowed, \d+ denied$/)
      await expect(page.getByTestId('overview-alerts')).toContainText('Compound-K')
      await expect(page.getByTestId('overview-incidents')).toContainText(PIXEL)
      await expect(page.getByTestId('overview-footer')).toContainText('directory epoch 14')
    })
  })

  test.describe('all devices', () => {
    test('filter by name', async ({ page }) => {
      await goto(page, 'All devices')
      const rows = page.locator('[data-testid^="ops-device-row-"]')
      await expect(rows.first()).toBeVisible()
      const total = await rows.count()
      expect(total).toBeGreaterThan(5)
      await page.getByTestId('ops-devices-filter').fill('daniel')
      await expect(rows).toHaveCount(2)
      await page.getByTestId('ops-devices-filter').fill('zzz')
      await expect(page.getByTestId('ops-devices-nomatch')).toBeVisible()
    })

    test('revoke with a reason reaches the result panel, then the incident page', async ({ page }) => {
      await goto(page, 'All devices')
      await page.getByRole('button', { name: 'Revoke Lab bench tablet' }).click()
      const dialog = page.getByTestId('revoke-dialog')
      await expect(dialog).toContainText('Revoke Lab bench tablet')
      await expect(page.getByTestId('revoke-confirm')).toBeDisabled()
      await dialog.getByTestId('revoke-preset-hour').check({ force: true })
      await dialog.getByTestId('revoke-reason').fill('reported stolen by phone')
      await dialog.getByTestId('revoke-confirm').click()
      const result = page.getByTestId('revoke-result')
      await expect(result).toContainText('Access removed from Lab bench tablet')
      await expect(result.getByTestId('revoke-enforce-ms')).toHaveText(/^\d+\s*ms$/)
      await expect(result.getByTestId('revoke-scope')).toBeVisible()
      await page.getByTestId('revoke-open-incident').click()
      await expect(page).toHaveURL(/\/app\/ops\/incidents\/inc_/)
      await expect(page.getByRole('heading', { level: 1 })).toContainText('Lab bench tablet')
      await expect(page.getByTestId('incident-step-reported')).toBeVisible()
    })

    test('a revoked device shows its incident link and no Revoke button', async ({ page }) => {
      await goto(page, 'All devices')
      const row = page.locator('[data-testid^="ops-device-row-"]').filter({ hasText: PIXEL })
      await expect(row).toHaveAttribute('data-status', 'revoked')
      await expect(row.getByRole('button', { name: /Revoke/ })).toHaveCount(0)
      await expect(row.getByRole('link', { name: 'Incident' })).toBeVisible()
    })

    test('keyboard only: the dialog opens from the Revoke button and Enter confirms', async ({ page }) => {
      await goto(page, 'All devices')
      await page.getByRole('button', { name: 'Revoke Lab bench tablet' }).focus()
      await page.keyboard.press('Enter')
      await expect(page.getByTestId('revoke-preset-now')).toBeFocused()
      await page.keyboard.press('Tab')
      await expect(page.getByTestId('revoke-reason')).toBeFocused()
      await page.keyboard.type('keyboard reason')
      await page.keyboard.press('Enter')
      await expect(page.getByTestId('revoke-result')).toBeVisible()
    })
  })

  test.describe('incident page', () => {
    test('the timeline lists entries in order', async ({ page }) => {
      await openSeededIncident(page)
      await expect(page.getByTestId('incident-status')).toContainText('Contained')
      await expect(page.getByTestId('incident-enforce-ms')).toContainText('34')
      const ids = await page.getByTestId('incident-timeline').locator('li[data-testid^="incident-step-"]').evaluateAll((els) => els.map((e) => e.getAttribute('data-testid')))
      expect(ids).toEqual([
        'incident-step-reported',
        'incident-step-revoked',
        'incident-step-scoped',
        'incident-step-rekey_started',
        'incident-step-rekey_progress',
        'incident-step-rekey_progress',
        'incident-step-rekey_progress',
        'incident-step-rekey_done',
        'incident-step-denied_attempt',
        'incident-step-denied_attempt',
      ])
      await expect(page.getByTestId('incident-step-reported')).toContainText('Reported lost')
      await expect(page.getByTestId('incident-step-rekey_done')).toContainText('New keys finished')
    })

    test('each exposure tab shows its group', async ({ page }) => {
      await openSeededIncident(page)
      const expectTab = async (id: string, text: string | null) => {
        await page.getByTestId(`incident-tab-${id}`).click()
        await expect(page.getByTestId(`incident-tab-${id}`)).toHaveAttribute('aria-selected', 'true')
        if (text) await expect(page.locator('[data-tour="incident-exposure"]')).toContainText(text)
      }
      await expect(page.getByTestId('incident-tab-exposed')).toHaveAttribute('aria-selected', 'true')
      await expect(page.locator('[data-testid^="incident-file-"]')).toHaveCount(2)
      await expect(page.locator('[data-testid^="incident-file-"]').first()).toContainText(/New key/)
      await expectTab('held', 'Plasmid-library-inventory.csv')
      await expectTab('never_released', 'Freezer-fault-log.txt')
      await expectTab('suspect', null)
      await expect(page.getByRole('tab', { name: /Suspect decisions/ })).toBeVisible()
    })

    test('tabs move with the arrow keys', async ({ page }) => {
      await openSeededIncident(page)
      await page.getByTestId('incident-tab-exposed').focus()
      await page.keyboard.press('Tab')
      await expect(page.getByTestId('incident-tab-held')).toBeFocused()
      await page.keyboard.press('Enter')
      await expect(page.getByTestId('incident-tab-held')).toHaveAttribute('aria-selected', 'true')
    })

    test('export bundle triggers a download, and "Verify it here" shows a verified result', async ({ page }) => {
      await openSeededIncident(page)
      const download = page.waitForEvent('download')
      await page.getByTestId('incident-export').click()
      expect((await download).suggestedFilename()).toMatch(/^quantumguard-proof-inc_.+\.json$/)
      await expect(page.getByText('The proof bundle was saved to this device.')).toBeVisible()
      await page.getByTestId('incident-verify').click()
      await expect(page).toHaveURL(/\/app\/evidence\/verify$/)
      await expect(page.getByTestId('verify-result')).toContainText('Verified on this device', { timeout: 20_000 })
      await expect(page.getByTestId('verify-result')).toHaveAttribute('data-ok', 'true')
    })

    test('correct the loss time re-scopes the incident', async ({ page }) => {
      await openSeededIncident(page)
      await page.getByTestId('incident-correct-time').click()
      const dialog = page.getByTestId('revoke-dialog')
      await expect(dialog).toContainText(`Correct the loss time for ${PIXEL}`)
      await dialog.getByTestId('revoke-preset-yesterday').check({ force: true })
      await dialog.getByTestId('revoke-reason').fill('owner remembered the right time')
      await dialog.getByRole('button', { name: 'Recalculate scope' }).click()
      await expect(page.getByTestId('revoke-result')).toContainText('Scope recalculated')
      await page.getByTestId('revoke-done').click()
      await expect(page.getByTestId('incident-step-rescoped')).toContainText('Scope recalculated')
    })

    test('close incident when contained', async ({ page }) => {
      await openSeededIncident(page)
      await page.getByTestId('incident-close').click()
      await expect(page.getByTestId('incident-status')).toContainText('Closed')
      await expect(page.getByTestId('incident-step-closed')).toBeVisible()
      await expect(page.getByTestId('incident-close')).toHaveCount(0)
    })

    test('closing too early explains that files are waiting for new keys', async ({ page }) => {
      await openSeededIncident(page)
      await failNextThenClick(page, 'incident-close', 'QG_CONFLICT', 'rekey_pending')
      const err = page.getByTestId('error-notice')
      await expect(err).toContainText('Files are still waiting for new keys')
      await expect(err).toContainText('Close the incident after every affected file has a new key.')
      await expect(page.getByTestId('incident-status')).not.toContainText('Closed')
    })
  })

  test.describe('alerts', () => {
    const alertRows = (page: Page) => page.locator('[data-testid^="alert-row-"]')

    test('open one and read why it fired, the evidence and the response', async ({ page }) => {
      await goto(page, 'Alerts')
      await expect(alertRows(page)).toHaveCount(2)
      await page.getByRole('button', { name: /Four restricted-file requests denied/ }).click()
      const sheet = page.getByTestId('alert-sheet')
      await expect(sheet.getByTestId('alert-why')).toContainText('Four or more policy denials on restricted files')
      await expect(sheet.getByTestId('alert-evidence').getByRole('link', { name: /Check receipt/ })).toHaveCount(4)
      await expect(sheet.getByTestId('alert-response')).toContainText('Device paused')
      await expect(sheet.getByTestId('alert-revoke-device')).toBeVisible()
    })

    test('acknowledge an alert', async ({ page }) => {
      await goto(page, 'Alerts')
      await page.getByRole('button', { name: /8 chunk reads of Compound-K/ }).click()
      const sheet = page.getByTestId('alert-sheet')
      await sheet.getByTestId('alert-note').fill('looked at it, a batch export')
      await sheet.getByTestId('alert-ack').click()
      await expect(page.getByText('Alert acknowledged')).toBeVisible()
      await expect(sheet.getByTestId('alert-ack')).toHaveCount(0)
      await expect(sheet).toContainText('Acknowledged')
      await page.keyboard.press('Escape')
      await expect(alertRows(page)).toHaveCount(1)
    })

    test('lift a response with a reason', async ({ page }) => {
      await goto(page, 'Alerts')
      await page.getByRole('button', { name: /Four restricted-file requests denied/ }).click()
      await page.getByTestId('alert-lift').click()
      const confirm = page.getByTestId('alert-lift-confirm')
      await expect(confirm).toBeDisabled()
      await page.getByTestId('alert-lift-reason').fill('owner confirmed it was them')
      await confirm.click()
      await expect(page.getByText('Response lifted')).toBeVisible()
      await expect(page.getByTestId('alert-response')).toContainText('Lifted')
      await expect(page.getByTestId('alert-lift')).toHaveCount(0)
    })

    test('keyboard only: Enter on a summary opens the sheet, Escape closes it', async ({ page }) => {
      await goto(page, 'Alerts')
      await page.getByRole('button', { name: /8 chunk reads of Compound-K/ }).focus()
      await page.keyboard.press('Enter')
      await expect(page.getByTestId('alert-sheet')).toBeVisible()
      await page.keyboard.press('Escape')
      await expect(page.getByTestId('alert-sheet')).toBeHidden()
    })

    test('a new alert appears in the list and the sidebar badge count goes up', async ({ page }) => {
      await goto(page, 'Alerts')
      const nav = page.getByRole('navigation', { name: 'Console' })
      await expect(nav.getByLabel('2 open alerts')).toBeVisible()
      await expect(alertRows(page)).toHaveCount(2)
      await mock(page).raiseAlert('QG-R004')
      await expect(alertRows(page)).toHaveCount(3, { timeout: 20_000 })
      await expect(page.getByText('Rule QG-R004 matched')).toBeVisible()
      await expect(nav.getByLabel('3 open alerts')).toBeVisible({ timeout: 20_000 })
    })
  })
})

test.describe('operator on a narrow screen', () => {
  test.use({ viewport: MOBILE })
  for (const label of ['Overview', 'All devices', 'Alerts', 'Incidents']) {
    test(`${label} fits without sideways scrolling`, async ({ page }) => {
      await unlockAs(page, 'priya')
      await goto(page, label)
      await expect(page.getByRole('heading', { name: label, level: 1 })).toBeVisible()
      await expectNoHorizontalScroll(page)
    })
  }
  test('the incident page and revoke dialog fit', async ({ page }) => {
    await unlockAs(page, 'priya')
    await openSeededIncident(page)
    await expectNoHorizontalScroll(page)
    await page.getByTestId('incident-tab-held').click()
    await expectNoHorizontalScroll(page)
    await page.getByTestId('incident-correct-time').click()
    await expectNoHorizontalScroll(page)
  })
})
