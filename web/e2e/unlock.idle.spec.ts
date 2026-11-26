// Runs only in the `mock-idle` project, whose dev server sets VITE_QG_IDLE_MS=4000.
import { expect, test, unlockAs, unlockOverlay } from './helpers'

test.describe('auto-lock after idle', () => {
  test('the overlay appears after the idle time and unlocking returns to the same page', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await expect(page.getByTestId('lock-overlay')).toBeHidden()
    await expect(page.getByTestId('lock-overlay')).toBeVisible({ timeout: 15_000 })
    await expect(page.getByTestId('lock-overlay')).toContainText('This device is locked')
    await unlockOverlay(page)
    await expect(page).toHaveURL(/\/app\/files$/)
  })

  test('input resets the idle clock', async ({ page }) => {
    await unlockAs(page, 'aiko')
    // Keep pressing keys for longer than the idle time; the device must stay unlocked.
    for (let i = 0; i < 10; i++) {
      await page.keyboard.press('Shift')
      await page.waitForTimeout(700)
    }
    await expect(page.getByTestId('lock-overlay')).toBeHidden()
    await expect(page.getByTestId('lock-overlay')).toBeVisible({ timeout: 15_000 })
  })
})
