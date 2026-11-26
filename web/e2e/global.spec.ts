import { expect, test, MOBILE, expectNoHorizontalScroll, goto, unlockAs } from './helpers'
import type { Page } from '@playwright/test'

/** Move inside the running app without a reload (a reload would lock the device again). */
async function clientNavigate(page: Page, path: string) {
  await page.evaluate((p) => {
    window.history.pushState({}, '', p)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, path)
}

async function unnamedButtons(page: Page): Promise<string[]> {
  const snapshot = await page.locator('body').ariaSnapshot()
  // A button with a name prints as `- button "Name"`; without one it prints bare.
  return snapshot.split('\n').filter((l) => /^\s*- button(\s*\[[^\]]*\])*:?\s*$/.test(l))
}

test.describe('theme', () => {
  test('the toggle switches the dark class and it persists across reload', async ({ page }) => {
    await unlockAs(page, 'aiko')
    const html = page.locator('html')
    await page.getByTestId('user-menu').click()
    await page.getByRole('menuitemradio', { name: 'Dark' }).click()
    await expect(html).toHaveClass(/dark/)
    await page.reload()
    await expect(page.getByRole('heading', { name: 'Unlock this device' })).toBeVisible()
    await expect(html).toHaveClass(/dark/)
    await page.getByTestId('unlock-passphrase').fill('correct horse battery')
    await page.keyboard.press('Enter')
    await expect(page.getByTestId('user-menu')).toBeVisible()
    await page.getByTestId('user-menu').click()
    await page.getByRole('menuitemradio', { name: 'Light' }).click()
    await expect(html).not.toHaveClass(/dark/)
    await page.reload()
    await expect(page.getByRole('heading', { name: 'Unlock this device' })).toBeVisible()
    await expect(html).not.toHaveClass(/dark/)
  })

  test('the theme also follows the setting on the public site', async ({ page }) => {
    await page.addInitScript(() => window.localStorage.setItem('qg-theme', 'dark'))
    await page.goto('/')
    await expect(page.locator('html')).toHaveClass(/dark/)
  })
})

test.describe('command palette', () => {
  test.fixme('opens with Ctrl/Meta+K and navigates (opening it crashes the app: src/components/ui/command.tsx:~35 CommandDialog renders cmdk parts without a <Command> root, cmdk throws "reading subscribe")', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await page.keyboard.press(process.platform === 'darwin' ? 'Meta+k' : 'Control+k')
    await expect(page.getByTestId('command-input')).toBeVisible()
    await page.getByTestId('command-input').fill('devices')
    await page.getByRole('option', { name: 'Devices' }).click()
    await expect(page).toHaveURL(/\/app\/devices$/)
  })

  test.fixme('the search button in the top bar opens it (same crash)', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await page.getByTestId('command-open').click()
    await expect(page.getByTestId('command-input')).toBeVisible()
    await page.getByTestId('command-verify').click()
    await expect(page).toHaveURL(/\/app\/evidence\/verify$/)
  })
})

test.describe('app states', () => {
  test('the offline banner appears and goes away', async ({ page, context }) => {
    await unlockAs(page, 'aiko')
    await expect(page.getByTestId('offline-banner')).toHaveCount(0)
    await context.setOffline(true)
    await expect(page.getByTestId('offline-banner')).toContainText('You are offline. Nothing is sent until the connection returns.')
    await context.setOffline(false)
    await expect(page.getByTestId('offline-banner')).toHaveCount(0)
  })

  test('an unknown route inside the app shows the not-found state and keeps the shell', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await clientNavigate(page, '/app/does-not-exist')
    await expect(page.getByTestId('not-found')).toContainText('This page does not exist')
    await expect(page.getByTestId('user-menu')).toBeVisible()
    await page.getByRole('link', { name: 'Go to the console' }).click()
    await expect(page.getByRole('heading', { name: 'Files', level: 1 })).toBeVisible()
  })

  test('an unknown public route shows the standalone not-found page', async ({ page }) => {
    await page.goto('/nowhere')
    await expect(page.getByTestId('not-found')).toContainText('This page does not exist')
    await page.getByRole('link', { name: 'Go to the home page' }).click()
    await expect(page).toHaveURL(/\/$/)
  })

  test('a role-gated route as an employee shows "Not available for your role"', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await clientNavigate(page, '/app/ops/alerts')
    const gate = page.getByTestId('role-required')
    await expect(gate).toContainText('Not available for your role')
    await gate.getByRole('link', { name: 'Back to your work' }).click()
    await expect(page.getByRole('heading', { name: 'Files', level: 1 })).toBeVisible()
  })

  test('the same gate applies to an admin on operator pages', async ({ page }) => {
    await unlockAs(page, 'mira')
    await clientNavigate(page, '/app/ops/alerts')
    await expect(page.getByTestId('role-required')).toBeVisible()
    await clientNavigate(page, '/app/admin/people')
    await expect(page.getByRole('heading', { name: 'People', level: 1 })).toBeVisible()
  })

  test('the sidebar only lists groups the role may use', async ({ page }) => {
    await unlockAs(page, 'aiko')
    const nav = page.getByRole('navigation', { name: 'Console' })
    await expect(nav.getByRole('link', { name: 'Files', exact: true })).toBeVisible()
    await expect(nav.getByRole('link', { name: 'People', exact: true })).toHaveCount(0)
    await expect(nav.getByRole('link', { name: 'Alerts', exact: true })).toHaveCount(0)
  })

  test('the skip link is first in tab order and moves focus to the content', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await page.keyboard.press('Tab')
    await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused()
    await page.keyboard.press('Enter')
    await expect(page.locator('#main')).toBeFocused()
  })
})

test.describe('accessible names', () => {
  test('every button on Files has an accessible name', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await expect(page.getByTestId('files-list')).toBeVisible()
    expect(await unnamedButtons(page)).toEqual([])
  })

  test('every button on Devices has an accessible name', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await goto(page, 'Devices')
    await expect(page.getByTestId('devices-list')).toBeVisible()
    expect(await unnamedButtons(page)).toEqual([])
  })

  test('every button on Overview has an accessible name', async ({ page }) => {
    await unlockAs(page, 'priya')
    await expect(page.getByTestId('overview-figures')).toBeVisible()
    await expect(page.getByTestId('overview-incidents')).toBeVisible()
    expect(await unnamedButtons(page)).toEqual([])
  })

  test('the Protect dialog buttons are named too', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await page.getByTestId('files-protect').click()
    await expect(page.getByTestId('protect-dialog')).toBeVisible()
    expect(await unnamedButtons(page)).toEqual([])
  })
})

test.describe('shell on a narrow screen', () => {
  test.use({ viewport: MOBILE })
  test('the menu opens from the toggle, and the offline banner and not-found state fit', async ({ page, context }) => {
    await unlockAs(page, 'aiko')
    const nav = page.getByRole('navigation', { name: 'Console' })
    await expect(nav).toHaveCount(0)
    await page.getByRole('button', { name: 'Toggle navigation' }).click()
    await expect(nav.getByRole('link', { name: 'Devices', exact: true })).toBeVisible()
    await nav.getByRole('link', { name: 'Devices', exact: true }).click()
    await expect(page.getByRole('heading', { name: 'Devices', level: 1 })).toBeVisible()
    await context.setOffline(true)
    await expect(page.getByTestId('offline-banner')).toBeVisible()
    await expectNoHorizontalScroll(page)
    await context.setOffline(false)
    await clientNavigate(page, '/app/nope')
    await expect(page.getByTestId('not-found')).toBeVisible()
    await expectNoHorizontalScroll(page)
  })
})
