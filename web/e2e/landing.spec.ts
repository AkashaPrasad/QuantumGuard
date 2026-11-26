import { expect, test, MOBILE, expectNoHorizontalScroll } from './helpers'
import type { Page } from '@playwright/test'

const SECTIONS = [
  { link: 'How it works', path: '/how-it-works', id: 'how-it-works' },
  { link: 'Product', path: '/product', id: 'product' },
  { link: 'Architecture', path: '/architecture', id: 'architecture' },
  { link: 'Security', path: '/security', id: 'security' },
] as const

const site = (page: Page) => page.getByRole('navigation', { name: 'Site', exact: true })

test.describe('public site', () => {
  test('the home page names the product and has a console button', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('Lose the laptop')
    await expect(page.getByTestId('launch-console')).toBeVisible()
  })

  for (const s of SECTIONS) {
    test(`the "${s.link}" link opens its section`, async ({ page }) => {
      await page.goto('/')
      await site(page).getByRole('link', { name: s.link }).click()
      await expect(page).toHaveURL(new RegExp(`${s.path}$`))
      await expect(page.locator(`#${s.id}`)).toBeInViewport()
      await expect(page.locator(`#${s.id} h2`)).toBeVisible()
    })

    test(`${s.path} opens straight on its section`, async ({ page }) => {
      await page.goto(s.path)
      await expect(page.locator(`#${s.id}`)).toBeInViewport()
    })
  }

  test('the Docs link opens the API reference', async ({ page }) => {
    await page.goto('/')
    await site(page).getByRole('link', { name: 'Docs' }).click()
    await expect(page).toHaveURL(/\/docs$/)
    await expect(page.getByRole('heading', { name: 'API reference', level: 1 })).toBeVisible()
  })

  test('the footer reaches Status', async ({ page }) => {
    await page.goto('/')
    await page.getByRole('contentinfo').getByRole('link', { name: /status/i }).first().click()
    await expect(page).toHaveURL(/\/status$/)
    await expect(page.getByRole('heading', { name: 'What this server says about itself', level: 1 })).toBeVisible()
  })

  test('"Launch console" goes to /app, which sends a browser with no device to enrol', async ({ page }) => {
    await page.goto('/')
    await page.getByTestId('launch-console').click()
    await expect(page).toHaveURL(/\/app\/enrol$/)
    await expect(page.getByRole('heading', { name: 'Enrol this device' })).toBeVisible()
  })

  test('the hero button does the same', async ({ page }) => {
    await page.goto('/')
    await page.getByTestId('hero-launch').click()
    await expect(page).toHaveURL(/\/app\/enrol$/)
  })

  test('the public pages only talk to the test server', async ({ page, baseURL }) => {
    const origin = new URL(baseURL!).origin
    const foreign: string[] = []
    page.on('request', (r) => {
      const u = r.url()
      if (u.startsWith('data:') || u.startsWith('blob:')) return
      if (new URL(u).origin !== origin) foreign.push(u)
    })
    for (const path of ['/', '/how-it-works', '/architecture', '/security', '/status', '/docs']) {
      await page.goto(path)
      await page.waitForLoadState('networkidle')
    }
    expect(foreign).toEqual([])
  })

  test('the architecture buttons change the description', async ({ page }) => {
    await page.goto('/architecture')
    const section = page.locator('#architecture')
    const live = section.locator('[aria-live="polite"]')
    const before = await live.innerText()
    const label = (await section.locator('button[aria-pressed="false"]').first().innerText()).trim()
    const other = section.getByRole('button', { name: label, exact: true })
    await other.click()
    await expect(other).toHaveAttribute('aria-pressed', 'true')
    await expect(live).toContainText(label)
    expect(await live.innerText()).not.toBe(before)
  })

  test('the FAQ opens and moves with the keyboard', async ({ page }) => {
    await page.goto('/security')
    const triggers = page.locator('#questions button[aria-expanded]')
    await triggers.first().focus()
    await expect(triggers.first()).toHaveAttribute('aria-expanded', 'false')
    await page.keyboard.press('Enter')
    await expect(triggers.first()).toHaveAttribute('aria-expanded', 'true')
    await page.keyboard.press('ArrowDown')
    await expect(triggers.nth(1)).toBeFocused()
    await page.keyboard.press('Space')
    await expect(triggers.nth(1)).toHaveAttribute('aria-expanded', 'true')
    await expect(triggers.first()).toHaveAttribute('aria-expanded', 'false')
  })

  test('the skip link is the first thing Tab reaches', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    await page.keyboard.press('Tab')
    await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused()
  })

  test.describe('narrow screen', () => {
    test.use({ viewport: MOBILE })
    for (const path of ['/', '/how-it-works', '/architecture', '/security', '/status', '/docs']) {
      test(`${path} fits without sideways scrolling`, async ({ page }) => {
        await page.goto(path)
        await page.waitForLoadState('networkidle')
        await expectNoHorizontalScroll(page)
      })
    }
    test('the section links are in the second nav row', async ({ page }) => {
      await page.goto('/')
      await page.getByRole('navigation', { name: 'Site sections' }).getByRole('link', { name: 'Product' }).click()
      await expect(page.locator('#product')).toBeInViewport()
    })
  })
})
