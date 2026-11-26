import { execFileSync } from 'node:child_process'
import { join, resolve } from 'node:path'
import { expect, test as base } from '@playwright/test'
import type { Browser, BrowserContext, Page, Response } from '@playwright/test'

// Shared by every live spec. The server and the web dev server are started by playwright.live.config.ts
// with a data directory under QG_LIVE_DIR; the admin command below runs against the same directory.

export const ROOT = resolve(import.meta.dirname, '..', '..')
export const PASSPHRASE = 'correct horse battery staple'

function liveDir(): string {
  const dir = process.env.QG_LIVE_DIR
  if (!dir) throw new Error('QG_LIVE_DIR is not set: run through playwright.live.config.ts')
  return dir
}

/** Runs `python -m qg.admin ...` against the live server's data and keys directories. */
export function admin(args: string[]): string {
  const dir = liveDir()
  return execFileSync('uv', ['run', '--quiet', '--project', join(ROOT, 'backend'), 'python', '-m', 'qg.admin', ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    env: {
      ...process.env,
      QG_DATA_DIR: join(dir, 'data'),
      QG_KEYS_DIR: join(dir, 'keys'),
      PYTHONPATH: `${join(ROOT, 'backend')}:${join(ROOT, 'cli')}`,
    },
  })
}

export interface IssuedCode {
  user_id: string
  name: string
  roles: string[]
  code: string
  expires_at: string
}

/**
 * Fresh single-use enrolment codes from the local admin command (spec/API.md 10), by person name.
 * Issuing cancels that person's earlier pending bootstrap code.
 */
export function issueCodes(userIds?: string[]): Record<string, IssuedCode> {
  const args = ['invite', '--json']
  if (userIds?.length) for (const u of userIds) args.push('--user-id', u)
  else args.push('--all')
  const out = JSON.parse(admin(args)) as { invites: IssuedCode[] }
  return Object.fromEntries(out.invites.map((i) => [i.name, i]))
}

let seeded: Record<string, string> | null = null

/** Seeded people's user ids by name (read once with --all, before any code is in use). */
export function userIdOf(name: string): string {
  seeded ??= Object.fromEntries(Object.values(issueCodes()).map((p) => [p.name, p.user_id]))
  const id = seeded[name]
  if (!id) throw new Error(`no seeded person called ${name}`)
  return id
}

/** A fresh code for one seeded person, by name; other people's pending codes stay valid. */
export function codeFor(name: string): string {
  return issueCodes([userIdOf(name)])[name]!.code
}

/** Every role combination the tour remembers (src/tour/Tour.tsx: roles sorted, joined with '+'). */
function tourKeys(): string[] {
  const roles = ['admin', 'auditor', 'employee', 'operator']
  const out: string[] = []
  for (let mask = 1; mask < 1 << roles.length; mask++) out.push(roles.filter((_, i) => mask & (1 << i)).join('+'))
  return out
}

// ---- refusals ---------------------------------------------------------------------------------

export interface Refusal {
  method: string
  path: string
  status: number
  code: string | null
  reason: string | null
}

export interface RefusalMatcher {
  code: string
  reason?: string
  path?: RegExp
}

/** Every API response with status >= 400, across all devices of a test. */
export class Refusals {
  private readonly pending: Promise<Refusal>[] = []
  private readonly allowed: RefusalMatcher[] = []

  record(res: Response): void {
    const url = new URL(res.url())
    if (!url.pathname.startsWith('/api/') || res.status() < 400) return
    const method = res.request().method()
    this.pending.push(
      res
        .json()
        .catch(() => null)
        .then((body: unknown) => {
          const e = (body as { error?: { code?: string; reason?: string } } | null)?.error
          return { method, path: url.pathname, status: res.status(), code: e?.code ?? null, reason: e?.reason ?? null }
        }),
    )
  }

  /** Declares a refusal this test expects (any number of times); anything else fails the test at the end. */
  expect(...m: RefusalMatcher[]): void {
    this.allowed.push(...m)
  }

  async all(): Promise<Refusal[]> {
    return Promise.all(this.pending)
  }

  /** Refusals with this code (and reason), in order. */
  async with(code: string, reason?: string): Promise<Refusal[]> {
    return (await this.all()).filter((r) => r.code === code && (reason === undefined || r.reason === reason))
  }

  async unexpected(): Promise<Refusal[]> {
    const ok = (r: Refusal) => this.allowed.some((m) => m.code === r.code && (m.reason === undefined || m.reason === r.reason) && (!m.path || m.path.test(r.path)))
    return (await this.all()).filter((r) => !ok(r))
  }
}

// ---- devices ----------------------------------------------------------------------------------

export interface LiveDevice {
  context: BrowserContext
  page: Page
}

export interface Live {
  /** A new browser context: its own IndexedDB, so its own enrolled device. */
  newDevice(): Promise<LiveDevice>
  refusals: Refusals
}

/**
 * The live test object. `live.newDevice()` opens isolated contexts; any uncaught page error fails the
 * test, and any API refusal the test did not declare with `live.refusals.expect(...)` fails it too.
 */
export const test = base.extend<{ live: Live }>({
  live: async ({ browser, baseURL }, provide) => {
    const contexts: BrowserContext[] = []
    const pageErrors: string[] = []
    const refusals = new Refusals()
    const newDevice = async (): Promise<LiveDevice> => {
      const context = await (browser as Browser).newContext({ baseURL, acceptDownloads: true })
      await context.addInitScript(
        ([key, value]) => {
          try {
            window.localStorage.setItem(key!, value!)
          } catch {
            /* storage unavailable */
          }
        },
        ['qg-tour-seen', JSON.stringify(tourKeys())] as const,
      )
      context.on('page', (p) => watch(p))
      const page = await context.newPage()
      contexts.push(context)
      return { context, page }
    }
    const watch = (p: Page) => {
      p.on('pageerror', (e) => pageErrors.push(`${p.url()}: ${e.message}`))
      p.on('response', (r) => refusals.record(r))
    }
    await provide({ newDevice, refusals })
    const unexpected = await refusals.unexpected()
    for (const c of contexts) await c.close().catch(() => undefined)
    expect(pageErrors, 'uncaught page errors').toEqual([])
    expect(unexpected, 'API refusals the test did not expect').toEqual([])
  },
})
export { expect }

// ---- flows --------------------------------------------------------------------------------------

/** Enrols this context's browser with a code and lands in the console. */
export async function enrol(page: Page, code: string, deviceName: string, passphrase = PASSPHRASE): Promise<void> {
  await startEnrol(page, code, deviceName, passphrase)
  await expect(page.getByTestId('enrol-done')).toBeVisible({ timeout: 30_000 })
  await page.getByTestId('enrol-done').click()
  await expect(page.getByTestId('user-menu')).toBeVisible()
}

/** Fills the enrolment steps and submits, without waiting for the result. */
export async function startEnrol(page: Page, code: string, deviceName: string, passphrase = PASSPHRASE): Promise<void> {
  await page.goto('/app/enrol')
  await expect(page.getByTestId('enrol-code')).toBeFocused()
  await page.getByTestId('enrol-code').fill(code)
  await page.getByTestId('enrol-next').click()
  await page.getByTestId('enrol-device-name').fill(deviceName)
  await page.getByTestId('enrol-next').click()
  await page.getByTestId('enrol-passphrase').fill(passphrase)
  await page.getByTestId('enrol-passphrase-confirm').fill(passphrase)
  await page.getByTestId('enrol-create').click()
}

/** A new device enrolled for a seeded person. */
export async function device(live: Live, person: string, deviceName: string): Promise<LiveDevice> {
  const d = await live.newDevice()
  await enrol(d.page, codeFor(person), deviceName)
  return d
}

/** In-app navigation (a reload would lock the device: its keys live only in memory). */
export async function visit(page: Page, path: string): Promise<void> {
  await page.evaluate((p) => {
    window.history.pushState({}, '', p)
    window.dispatchEvent(new PopStateEvent('popstate'))
  }, path)
}

/** Click a sidebar link by its name. */
export async function goto(page: Page, label: string): Promise<void> {
  await page.getByRole('navigation', { name: 'Console' }).getByRole('link', { name: label, exact: true }).click()
}

/** Invites a new person from People (admin page) and returns the one-time code, or null when sent for approval. */
export async function invitePerson(adminPage: Page, name: string, role = 'Employee'): Promise<string | null> {
  await goto(adminPage, 'People')
  await adminPage.getByTestId('people-invite').click()
  await adminPage.getByTestId('invite-name').fill(name)
  await adminPage.getByTestId('invite-role').selectOption({ label: role })
  await adminPage.getByTestId('invite-submit').click()
  const dialog = adminPage.getByRole('dialog')
  await expect(dialog.getByTestId('invite-code').or(dialog.getByTestId('invite-pending-approval'))).toBeVisible()
  const code = (await dialog.getByTestId('invite-code').count()) ? (await dialog.getByTestId('invite-code').textContent())!.trim() : null
  await dialog.getByRole('button', { name: 'Close' }).first().click()
  await expect(dialog).toBeHidden()
  return code
}

/** Protects a small text file from the Files page, shared with the named people. */
export async function protect(page: Page, name: string, text: string, opts: { with?: string[]; level?: 'internal' | 'confidential' | 'restricted' } = {}): Promise<void> {
  await goto(page, 'Files')
  await page.getByTestId('files-protect').click()
  await expect(page.getByTestId('protect-dialog')).toBeVisible()
  await page.getByTestId('protect-file-input').setInputFiles({ name, mimeType: 'text/plain', buffer: Buffer.from(text) })
  if (opts.level) await page.getByTestId(`protect-level-${opts.level}`).check({ force: true })
  for (const person of opts.with ?? []) await page.getByTestId('protect-dialog').getByLabel(person).check()
  await page.getByTestId('protect-submit').click()
  await expect(page.getByTestId('protect-receipt')).toBeVisible({ timeout: 30_000 })
  await page.getByTestId('protect-done').click()
  await expect(page.getByTestId('protect-dialog')).toBeHidden()
}

export const fileRow = (page: Page, name: string) => page.locator('[data-testid^="file-row-"]').filter({ hasText: name })

/** Opens a file from its row and returns the downloaded text. */
export async function openFileText(page: Page, name: string): Promise<string> {
  await goto(page, 'Files')
  const row = fileRow(page, name)
  await expect(row).toBeVisible()
  const download = page.waitForEvent('download')
  await row.getByRole('button', { name: `Open ${name}` }).click()
  const d = await download
  await expect(row.getByTestId('file-verified')).toContainText('Checked on this device')
  const path = await d.path()
  const { readFile } = await import('node:fs/promises')
  return readFile(path, 'utf8')
}

/** datetime-local value for a Date in the browser's zone. */
export function localInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}
