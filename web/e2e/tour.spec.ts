import { expect, test, unlockAs } from './helpers'
import type { Page } from '@playwright/test'
import { goto, PASSPHRASE } from './helpers'

// Titles and anchors come from src/tour/steps.ts, written out here so a change there shows up as a failing test.
const EMPLOYEE = [
  ['device-chip', 'This device'],
  ['nav-files', 'Files'],
  ['files-protect', 'Protect a file'],
  ['nav-devices', 'Devices and Report lost'],
  ['nav-activity', 'Activity and receipts'],
  ['nav-help', 'Help'],
] as const
const ADMIN = [
  ['overview-figures', 'Overview'],
  ['nav-people', 'People and roles'],
  ['nav-changes', 'Change requests'],
  ['nav-ops-devices', 'All devices'],
  ['nav-verify', 'Evidence and Verify'],
  ['nav-policy', 'Policy and settings'],
] as const
const OPERATOR = [
  ['overview-figures', 'Overview'],
  ['nav-changes', 'Change requests'],
  ['nav-ops-devices', 'All devices'],
  ['nav-alerts', 'Alerts'],
  ['nav-incidents', 'Incidents and the exposure report'],
  ['nav-verify', 'Evidence and Verify'],
  ['nav-policy', 'Policy and settings'],
] as const

const popover = (page: Page) => page.locator('.driver-popover')
const progress = (page: Page) => page.locator('.driver-popover-progress-text')
const next = (page: Page) => popover(page).getByRole('button', { name: /^(Next|Done)$/ })

async function walk(page: Page, steps: readonly (readonly [string, string])[]) {
  for (const [i, [anchor, title]] of steps.entries()) {
    await expect(popover(page).locator('.driver-popover-title')).toHaveText(title)
    await expect(progress(page)).toHaveText(`${i + 1} of ${steps.length}`)
    await expect(page.locator(`.driver-active-element[data-tour="${anchor}"]`), `anchor ${anchor} on its page`).toHaveCount(1)
    await next(page).click()
  }
  await expect(popover(page)).toHaveCount(0)
}

test.describe('guided tour (not pre-seeded)', () => {
  test.use({ seedTour: false })

  test('starts once for an employee, with progress "1 of 6"', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await expect(popover(page)).toBeVisible()
    await expect(progress(page)).toHaveText('1 of 6')
    await expect(popover(page).locator('.driver-popover-title')).toHaveText('This device')
    await expect(popover(page).getByRole('button', { name: 'Back' })).toHaveCount(0)
    await expect(popover(page).getByRole('button', { name: 'Skip tour' })).toBeVisible()
  })

  test('Next and Back move between steps', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await expect(progress(page)).toHaveText('1 of 6')
    await next(page).click()
    await expect(progress(page)).toHaveText('2 of 6')
    await expect(popover(page).locator('.driver-popover-title')).toHaveText('Files')
    await popover(page).getByRole('button', { name: 'Back' }).click()
    await expect(progress(page)).toHaveText('1 of 6')
  })

  test('Skip tour closes it', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await expect(popover(page)).toBeVisible()
    await popover(page).getByRole('button', { name: 'Skip tour' }).click()
    await expect(popover(page)).toHaveCount(0)
  })

  test('Esc closes it', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await expect(popover(page)).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(popover(page)).toHaveCount(0)
  })

  test('it does not start again after a reload and unlock', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await expect(popover(page)).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(popover(page)).toHaveCount(0)
    expect(await page.evaluate(() => window.localStorage.getItem('qg-tour-seen'))).toContain('employee')
    await page.reload()
    await page.getByTestId('unlock-passphrase').fill(PASSPHRASE)
    await page.keyboard.press('Enter')
    await expect(page.getByRole('heading', { name: 'Files', level: 1 })).toBeVisible()
    // The tour starts 700 ms after unlock; give it time to (wrongly) appear.
    await page.waitForTimeout(1500)
    await expect(popover(page)).toHaveCount(0)
  })

  test('the Help page button replays it', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await page.keyboard.press('Escape')
    await expect(popover(page)).toHaveCount(0)
    await goto(page, 'Help and tour')
    await page.getByTestId('help-replay-tour').click()
    await expect(progress(page)).toHaveText('1 of 6')
  })

  test('employee tour: every step has its anchor on its page', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await walk(page, EMPLOYEE)
  })

  test('admin tour: every step has its anchor on its page', async ({ page }) => {
    await unlockAs(page, 'mira')
    await walk(page, ADMIN)
  })

  test('operator tour: every step has its anchor on its page', async ({ page }) => {
    await unlockAs(page, 'priya')
    await walk(page, OPERATOR)
  })
})

test.describe('guided demo (operator)', () => {
  test('starts from Help and its first step points at the all-devices table', async ({ page }) => {
    await unlockAs(page, 'priya')
    await goto(page, 'Help and tour')
    await page.getByTestId('help-guided-demo').click()
    await expect(popover(page).locator('.driver-popover-title')).toHaveText('1. Revoke the lost device')
    await expect(page).toHaveURL(/\/app\/ops\/devices$/)
    await expect(page.locator('.driver-active-element[data-tour="ops-devices"]')).toHaveCount(1)
    await expect(progress(page)).toHaveText('1 of 7')
  })

  test('the demo button is for operators only', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await goto(page, 'Help and tour')
    await expect(page.getByTestId('help-replay-tour')).toBeVisible()
    await expect(page.getByTestId('help-guided-demo')).toHaveCount(0)
  })
})
