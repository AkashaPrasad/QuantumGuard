import { expect, test as base } from '@playwright/test'
import type { Locator, Page } from '@playwright/test'

/** Every role key the tour remembers (src/tour/Tour.tsx, localStorage `qg-tour-seen`). */
export const TOUR_SEEN_KEY = 'qg-tour-seen'
export const TOUR_ROLE_KEYS = ['employee', 'admin', 'operator', 'auditor']

/**
 * The test object every spec uses. By default the guided tour is marked as already seen for every role so it
 * never covers the page; tour.spec.ts turns that off with `test.use({ seedTour: false })`.
 */
export const test = base.extend<{ seedTour: boolean }>({
  seedTour: [true, { option: true }],
  page: async ({ page, seedTour }, use) => {
    if (seedTour) {
      await page.addInitScript(
        ([key, roles]) => {
          try {
            window.localStorage.setItem(key!, JSON.stringify(roles))
          } catch {
            /* storage unavailable */
          }
        },
        [TOUR_SEEN_KEY, TOUR_ROLE_KEYS] as const,
      )
    }
    await use(page)
  },
})
export { expect }

export type Persona = 'aiko' | 'mira' | 'priya' | 'jonas'
export const PASSPHRASE = 'correct horse battery'
export const MOBILE = { width: 390, height: 844 } as const

interface MockControl {
  setOffline(on: boolean): void
  expireSession(): void
  revokeCurrentDevice(): void
  failNext(code: string, reason?: string): void
  raiseAlert(ruleId: string): void
  setLatency(ms: number): void
  reset(): void
}

declare global {
  interface Window {
    __qgMock?: MockControl
  }
}

/** Thin wrappers over `window.__qgMock`, which only exists on the mock dev server. */
export function mock(page: Page) {
  return {
    setOffline: (on: boolean) => page.evaluate((v) => window.__qgMock!.setOffline(v), on),
    expireSession: () => page.evaluate(() => window.__qgMock!.expireSession()),
    revokeCurrentDevice: () => page.evaluate(() => window.__qgMock!.revokeCurrentDevice()),
    failNext: (code: string, reason?: string) => page.evaluate(([c, r]) => window.__qgMock!.failNext(c!, r), [code, reason] as const),
    raiseAlert: (ruleId: string) => page.evaluate((id) => window.__qgMock!.raiseAlert(id), ruleId),
    setLatency: (ms: number) => page.evaluate((v) => window.__qgMock!.setLatency(v), ms),
    reset: () => page.evaluate(() => window.__qgMock!.reset()),
  }
}

/** Load the unlock page as a persona, type the seeded passphrase and wait for the console. */
export async function unlockAs(page: Page, persona: Persona): Promise<void> {
  await page.goto(`/app/unlock?persona=${persona}`)
  await page.getByTestId('unlock-passphrase').fill(PASSPHRASE)
  await page.getByTestId('unlock-submit').click()
  await expect(page.getByTestId('user-menu')).toBeVisible()
  await expect(page.locator('main h1').first()).toBeVisible()
}

/** Enrol a browser with no device, end to end, and land in the console. */
export async function enrolFresh(page: Page, code: string, opts: { deviceName?: string; passphrase?: string } = {}): Promise<void> {
  const passphrase = opts.passphrase ?? PASSPHRASE
  await page.goto('/app/enrol?persona=none')
  await page.getByTestId('enrol-code').fill(code)
  await page.getByTestId('enrol-next').click()
  if (opts.deviceName) await page.getByTestId('enrol-device-name').fill(opts.deviceName)
  await page.getByTestId('enrol-next').click()
  await page.getByTestId('enrol-passphrase').fill(passphrase)
  await page.getByTestId('enrol-passphrase-confirm').fill(passphrase)
  await page.getByTestId('enrol-create').click()
  await page.getByTestId('enrol-done').click()
  await expect(page.getByTestId('user-menu')).toBeVisible()
}

/** Click a sidebar link by its name, opening the menu first on a narrow screen. */
export async function goto(page: Page, label: string): Promise<void> {
  const link = page.getByRole('navigation', { name: 'Console' }).getByRole('link', { name: label, exact: true })
  if (!(await link.isVisible())) await page.getByRole('button', { name: 'Toggle navigation' }).click()
  await link.click()
}

/** The page itself must never scroll sideways (tables may scroll inside their own box). */
export async function expectNoHorizontalScroll(page: Page): Promise<void> {
  const over = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  expect(over, 'horizontal overflow in px').toBeLessThanOrEqual(1)
}

/** Open the lock overlay's passphrase field and unlock again. */
export async function unlockOverlay(page: Page, passphrase = PASSPHRASE): Promise<void> {
  const overlay = page.getByTestId('lock-overlay')
  await overlay.getByTestId('unlock-passphrase').fill(passphrase)
  await overlay.getByTestId('unlock-submit').click()
  await expect(overlay).toBeHidden()
}

/** Row locator by test id prefix, first match. */
export function firstByTestIdPrefix(page: Page, prefix: string): Locator {
  return page.locator(`[data-testid^="${prefix}"]`).first()
}

/** A small in-memory file for the protect dialog. */
export function sampleFile(name = 'e2e-notes.txt', text = 'hello from the browser test') {
  return { name, mimeType: 'text/plain', buffer: Buffer.from(text) }
}
