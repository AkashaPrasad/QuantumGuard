import AxeBuilder from '@axe-core/playwright'
import { expect, test, goto, unlockAs } from './helpers'
import type { Persona } from './helpers'
import type { Page } from '@playwright/test'

type Theme = 'light' | 'dark'
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']
const THEMES: Theme[] = ['light', 'dark']

interface Route {
  persona: Persona
  name: string
  /** Sidebar link to click, when the page is a menu item. */
  link?: string
  /** Custom way in, for pages that are not in the menu. */
  open?: (page: Page) => Promise<void>
  heading: string
  /** A real violation found by axe: the test is skipped and the reason is the finding. */
  fixme?: string
}

// From src/app/routes.tsx and src/app/nav.ts, one entry per distinct page and the first role that sees it,
// plus the pages whose content differs by role (Overview for an operator).
const ROUTES: Route[] = [
  { persona: 'aiko', name: 'files', link: 'Files', heading: 'Files' },
  { persona: 'aiko', name: 'files sheet', heading: 'Files', open: async (p) => {
      await p.locator('[data-testid^="file-row-"]').first().getByRole('button').first().click()
      await p.getByTestId('file-sheet').getByText('Who can open this').waitFor()
    } },
  { persona: 'aiko', name: 'files protect dialog', heading: 'Files', open: async (p) => {
      await p.getByTestId('files-protect').click()
      await p.getByTestId('protect-dialog').waitFor()
      await p.getByLabel('Mira Okafor').waitFor()
    } },
  { persona: 'aiko', name: 'devices', link: 'Devices', heading: 'Devices' },
  { persona: 'aiko', name: 'activity', link: 'Activity', heading: 'Activity' },
  { persona: 'aiko', name: 'messages', link: 'Messages', heading: 'Messages' },
  { persona: 'aiko', name: 'policy', link: 'Policy', heading: 'Policy' },
  { persona: 'aiko', name: 'verify', link: 'Verify', heading: 'Verify' },
  { persona: 'aiko', name: 'help', link: 'Help and tour', heading: 'Help and tour' },
  { persona: 'aiko', name: 'role gate', heading: 'Files', open: async (p) => {
      await p.evaluate(() => {
        window.history.pushState({}, '', '/app/ops/alerts')
        window.dispatchEvent(new PopStateEvent('popstate'))
      })
      await p.getByTestId('role-required').waitFor()
    } },
  { persona: 'aiko', name: 'not found', heading: 'Files', open: async (p) => {
      await p.evaluate(() => {
        window.history.pushState({}, '', '/app/nope')
        window.dispatchEvent(new PopStateEvent('popstate'))
      })
      await p.getByTestId('not-found').waitFor()
    } },
  { persona: 'mira', name: 'overview (admin)', link: 'Overview', heading: 'Overview' },
  { persona: 'mira', name: 'people', link: 'People', heading: 'People' },
  { persona: 'mira', name: 'invite dialog', heading: 'People', open: async (p) => {
      await goto(p, 'People')
      await p.getByTestId('people-invite').click()
      await p.getByTestId('invite-name').waitFor()
    } },
  { persona: 'mira', name: 'change requests', link: 'Change requests', heading: 'Change requests' },
  { persona: 'mira', name: 'change sheet', heading: 'Change requests', open: async (p) => {
      await goto(p, 'Change requests')
      await p.locator('[data-testid^="change-row-"]').first().getByRole('button').click()
      await p.getByTestId('change-sheet').getByRole('heading', { name: 'Approvals' }).waitFor()
    } },
  { persona: 'mira', name: 'services', link: 'Services', heading: 'Services' },
  { persona: 'mira', name: 'settings', link: 'Settings', heading: 'Settings' },
  { persona: 'mira', name: 'all devices (admin)', link: 'All devices', heading: 'All devices' },
  { persona: 'priya', name: 'overview (operator)', link: 'Overview', heading: 'Overview' },
  { persona: 'priya', name: 'alerts', link: 'Alerts', heading: 'Alerts' },
  { persona: 'priya', name: 'alert sheet', heading: 'Alerts', open: async (p) => {
      await goto(p, 'Alerts')
      await p.locator('[data-testid^="alert-row-"]').first().getByRole('button').click()
      await p.getByTestId('alert-why').waitFor()
    } },
  { persona: 'priya', name: 'incidents', link: 'Incidents', heading: 'Incidents' },
  { persona: 'priya', name: 'incident detail', heading: 'Incidents', open: async (p) => {
      await goto(p, 'Incidents')
      await p.locator('[data-testid^="incident-row-"]').first().getByRole('link').click()
      await p.getByTestId('incident-timeline').waitFor()
      await p.locator('[data-tour="incident-exposure"] .animate-pulse').first().waitFor({ state: 'detached' }).catch(() => undefined)
    } },
  { persona: 'priya', name: 'revoke dialog', heading: 'All devices', open: async (p) => {
      await goto(p, 'All devices')
      await p.getByRole('button', { name: 'Revoke Lab bench tablet' }).click()
      await p.getByTestId('revoke-dialog').waitFor()
    } },
  { persona: 'priya', name: 'evidence log (operator)', link: 'Log', heading: 'Evidence log' },
  { persona: 'jonas', name: 'overview (auditor)', link: 'Overview', heading: 'Overview' },
  { persona: 'jonas', name: 'evidence log', link: 'Log', heading: 'Evidence log' },
  { persona: 'jonas', name: 'receipt sheet', heading: 'Evidence log', open: async (p) => {
      await goto(p, 'Log')
      await p.locator('[data-testid^="receipt-row-"]').first().getByRole('button').click()
      await p.getByTestId('receipt-sheet').getByTestId('receipt-slip').waitFor()
    } },
  { persona: 'jonas', name: 'verify result', heading: 'Verify', open: async (p) => {
      await goto(p, 'Log')
      await p.getByTestId('evidence-list').waitFor()
      await p.locator('[data-testid^="receipt-row-"]').first().getByRole('button').click()
      await p.getByTestId('receipt-sheet').getByTestId('receipt-slip').waitFor()
      const id = await p.getByTestId('receipt-sheet').getByTestId('receipt-slip').getAttribute('data-receipt-id')
      await p.keyboard.press('Escape')
      await p.getByTestId('receipt-sheet').waitFor({ state: 'hidden' })
      await goto(p, 'Verify')
      await p.getByTestId('verify-input').fill(id!)
      await p.getByTestId('verify-submit').click()
      await p.getByTestId('verify-result').waitFor()
    } },
]

const PUBLIC = ['/', '/how-it-works', '/architecture', '/security', '/status', '/docs']

async function setTheme(page: Page, theme: Theme) {
  await page.addInitScript((t) => window.localStorage.setItem('qg-theme', t), theme)
}

async function settle(page: Page, heading: string) {
  await expect(page.locator('main h1').filter({ hasText: heading }).first()).toBeVisible()
  await expect(page.locator('main .animate-pulse')).toHaveCount(0)
}

async function audit(page: Page, label: string) {
  // Colours are only meaningful once fades and slides have finished.
  await page.waitForFunction(() => document.getAnimations().every((x) => x.playState !== 'running' || x.effect?.getTiming().iterations === Infinity))
  const builder = new AxeBuilder({ page }).withTags(TAGS)
  // With a modal open the page behind it is inert and dimmed; audit what the person can reach.
  if ((await page.locator('[role="dialog"]').count()) > 0) builder.include('[role="dialog"]')
  const results = await builder.analyze()
  const bad = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')
  if (bad.length > 0) {
    const table = bad.map((v) => ({ route: label, rule: v.id, impact: v.impact, count: v.nodes.length, first: v.nodes[0]?.target.join(' ').slice(0, 90) }))
    console.table(table)
  }
  expect(bad.map((v) => `${v.id} (${v.impact}) x${v.nodes.length}: ${v.nodes[0]?.target.join(' ')}`), `axe violations on ${label}`).toEqual([])
}

test.describe('@a11y console pages', () => {
  for (const theme of THEMES) {
    for (const r of ROUTES) {
      const run = r.fixme ? test.fixme : test
      run(`${r.persona}: ${r.name} (${theme}) ${r.fixme ? `[${r.fixme}]` : ''}`.trim(), async ({ page }) => {
        await setTheme(page, theme)
        await unlockAs(page, r.persona)
        if (r.link) {
          const home = r.persona === 'aiko' ? 'Files' : 'Overview'
          if (r.link !== home) await goto(page, r.link)
        } else if (r.open) await r.open(page)
        // Pages opened through `open` wait for their own marker; menu pages wait for the heading and no skeletons.
        if (!r.open) await settle(page, r.heading)
        await expect(page.locator('html')).toHaveClass(theme === 'dark' ? /dark/ : /^(?!.*dark).*$/)
        await audit(page, `${r.name} [${theme}]`)
      })
    }
  }
})

test.describe('@a11y public pages', () => {
  for (const theme of THEMES) {
    for (const path of PUBLIC) {
      test(`${path} (${theme})`, async ({ page }) => {
        await setTheme(page, theme)
        await page.goto(path)
        await page.waitForLoadState('networkidle')
        await expect(page.locator('h1').first()).toBeVisible()
        await audit(page, `${path} [${theme}]`)
      })
    }
  }
})

test.describe('@a11y loading state', () => {
  test('skeleton rows are announced without an invalid attribute', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await page.evaluate(() => window.__qgMock!.setLatency(4000))
    await page.getByRole('navigation', { name: 'Console' }).getByRole('link', { name: 'Activity', exact: true }).click()
    await expect(page.getByLabel('Loading').first()).toBeVisible()
    await audit(page, 'loading skeleton')
  })
})

test.describe('@a11y enrolment and unlock', () => {
  for (const theme of THEMES) {
    test(`enrol steps (${theme})`, async ({ page }) => {
      await setTheme(page, theme)
      await page.goto('/app/enrol?persona=none')
      await expect(page.getByTestId('enrol-code')).toBeVisible()
      await audit(page, `enrol step 1 [${theme}]`)
      await page.getByTestId('enrol-code').fill('KESTREL-AIKO')
      await page.getByTestId('enrol-next').click()
      await expect(page.getByTestId('enrol-device-name')).toBeVisible()
      await audit(page, `enrol step 2 [${theme}]`)
      await page.getByTestId('enrol-next').click()
      await expect(page.getByTestId('enrol-passphrase')).toBeVisible()
      await audit(page, `enrol step 3 [${theme}]`)
    })
    test(`unlock page and lock overlay (${theme})`, async ({ page }) => {
      await setTheme(page, theme)
      await page.goto('/app/unlock?persona=aiko')
      await expect(page.getByTestId('unlock-passphrase')).toBeVisible()
      await audit(page, `unlock [${theme}]`)
      await page.getByTestId('unlock-passphrase').fill('correct horse battery')
      await page.keyboard.press('Enter')
      await expect(page.getByTestId('user-menu')).toBeVisible()
      await page.getByTestId('lock-now').click()
      await expect(page.getByTestId('lock-overlay')).toBeVisible()
      await audit(page, `lock overlay [${theme}]`)
    })
  }
})
