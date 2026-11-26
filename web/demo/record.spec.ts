import { execFileSync, spawn } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { expect, test } from '@playwright/test'
import type { Browser, BrowserContext, Page } from '@playwright/test'

// The timed demo for screen recording. Run it with `bash scripts/demo-video.sh`; the narration for every cue is
// in brief/video-script.md and is printed in the terminal as each segment starts. Captions on screen can be turned
// off with QG_DEMO_CAPTIONS=0. Everything happens in ONE browser window with three tabs: Aiko's laptop, Aiko's
// phone and Priya (operator). Each tab uses its own *.localhost address (laptop.localhost, phone.localhost,
// ops.localhost), which browsers treat as a secure context with its own storage, so each tab is its own device.

const ROOT = resolve(import.meta.dirname, '..', '..')
const PASSPHRASE = 'correct horse battery staple'
const FILE = 'trial-protocol-kb-17.pdf'
const CAPTIONS = process.env.QG_DEMO_CAPTIONS !== '0'
const [W, H] = (process.env.QG_DEMO_SIZE ?? '1440x900').split('x').map(Number)
const LEAD_IN = Number(process.env.QG_DEMO_LEAD_IN ?? '8')

// ---- server-side admin command (local trust, as in the README) ----------------------------------------------

function admin(args: string[]): string {
  return execFileSync('bash', ['scripts/compose.sh', '-p', 'qgdemo', '-f', 'docker-compose.yml', '-f', 'scripts/demo-video.compose.yml',
    'exec', '-T', 'quantumguard', 'python', '-m', 'qg.admin', ...args], { cwd: ROOT, encoding: 'utf8' })
}
let ids: Record<string, string> | null = null
function codeFor(name: string): string {
  ids ??= Object.fromEntries((JSON.parse(admin(['invite', '--all', '--json'])).invites as { name: string; user_id: string }[]).map((i) => [i.name, i.user_id]))
  const out = JSON.parse(admin(['invite', '--json', '--user-id', ids[name]!])) as { invites: { code: string }[] }
  return out.invites[0]!.code
}

// ---- windows, timeline, captions --------------------------------------------------------------------------

function tourKeys(): string[] {
  const roles = ['admin', 'auditor', 'employee', 'operator']
  const out: string[] = []
  for (let mask = 1; mask < 1 << roles.length; mask++) out.push(roles.filter((_, i) => mask & (1 << i)).join('+'))
  return out
}

const PORT = new URL(process.env.QG_DEMO_URL ?? 'http://localhost:18080').port || '80'
const ORIGIN = new Map<Page, string>()

/** One window for the whole take; every device is a tab in it. */
async function openWindow(browser: Browser): Promise<BrowserContext> {
  const context = await browser.newContext({ viewport: null, acceptDownloads: true })
  await context.addInitScript(([k, v]) => { try { localStorage.setItem(k!, v!) } catch { /* storage unavailable */ } },
    ['qg-tour-seen', JSON.stringify(tourKeys())] as const)
  return context
}

/** A tab for one device, on its own origin (`<host>.localhost`), so it has its own storage and keys. */
async function tab(context: BrowserContext, host: string): Promise<Page> {
  const page = await context.newPage()
  ORIGIN.set(page, `http://${host}.localhost:${PORT}`)
  if (context.pages().length === 1) {
    const cdp = await context.newCDPSession(page)
    const { windowId } = await cdp.send('Browser.getWindowForTarget')
    await cdp.send('Browser.setWindowBounds', { windowId, bounds: { left: 0, top: 0, width: W, height: H, windowState: 'normal' } })
  }
  return page
}

async function go(page: Page, path: string): Promise<void> {
  await page.goto(`${ORIGIN.get(page)}${path}`)
}

let t0 = 0
const clock = (s: number) => `${Math.floor(s / 60)}:${String(Math.floor(s % 60)).padStart(2, '0')}`
const now = () => (Date.now() - t0) / 1000
const pause = (s: number) => new Promise((r) => setTimeout(r, s * 1000))

/** Waits until `at` seconds into the take, then prints the cue and shows its caption on the page in front. */
async function cue(page: Page, at: number, caption: string): Promise<void> {
  const wait = at - now()
  if (wait > 0) await pause(wait)
  const late = now() - at
  console.log(`[${clock(now())}]${late > 1 ? ` (+${late.toFixed(0)} s)` : ''} ${caption}`)
  await page.bringToFront()
  if (!CAPTIONS) return
  await page.evaluate((text) => {
    let el = document.getElementById('qg-demo-caption')
    if (!el) {
      el = document.createElement('div')
      el.id = 'qg-demo-caption'
      // CSSOM, not a style attribute: the console's Content-Security-Policy forbids inline style attributes.
      Object.assign(el.style, {
        position: 'fixed', left: '50%', bottom: '18px', transform: 'translateX(-50%)', zIndex: '2147483647',
        maxWidth: '80%', padding: '8px 16px', borderRadius: '8px', background: 'rgba(16,19,42,0.88)', color: '#eef0ff',
        font: '500 15px/1.4 Inter, system-ui, sans-serif', pointerEvents: 'none', textAlign: 'center',
      })
      document.body.appendChild(el)
    }
    el.textContent = text
  }, caption)
}

async function scrollTo(page: Page, id: string): Promise<void> {
  await page.evaluate((target) => document.getElementById(target)?.scrollIntoView({ behavior: 'smooth', block: 'start' }), id)
}

async function nav(page: Page, label: string): Promise<void> {
  await page.getByRole('navigation', { name: 'Console' }).getByRole('link', { name: label, exact: true }).click()
}

async function enrol(page: Page, code: string, deviceName: string, typed: boolean): Promise<void> {
  const fill = async (id: string, text: string) => {
    const field = page.getByTestId(id)
    if (typed) await field.pressSequentially(text, { delay: 45 })
    else await field.fill(text)
  }
  if (!page.url().includes('/app/enrol')) await go(page, '/app/enrol')
  await expect(page.getByTestId('enrol-code')).toBeVisible()
  await fill('enrol-code', code)
  await page.getByTestId('enrol-next').click()
  await fill('enrol-device-name', deviceName)
  await page.getByTestId('enrol-next').click()
  await fill('enrol-passphrase', PASSPHRASE)
  await page.getByTestId('enrol-passphrase-confirm').fill(PASSPHRASE)
  await page.getByTestId('enrol-create').click()
  await expect(page.getByTestId('enrol-done')).toBeVisible({ timeout: 60_000 })
  if (typed) await pause(2)
  await page.getByTestId('enrol-done').click()
  await expect(page.getByTestId('user-menu')).toBeVisible()
}

/** Selects a radio input, retrying while its dialog is still animating in. */
async function choose(page: Page, testId: string, scope = page.locator('body')): Promise<void> {
  const radio = scope.getByTestId(testId)
  await expect(async () => {
    await radio.check({ force: true, timeout: 2_000 })
    await expect(radio).toBeChecked({ timeout: 1_000 })
  }).toPass({ timeout: 15_000 })
}

/** Runs a Compose command against the demo stack. */
function compose(args: string[]): void {
  execFileSync('bash', ['scripts/compose.sh', '-p', 'qgdemo', '-f', 'docker-compose.yml', '-f', 'scripts/demo-video.compose.yml', ...args],
    { cwd: ROOT, stdio: 'ignore' })
}

/** Off camera: scripts/demo-attacks.py inside the container (enumeration, replay, decoy) as Daniel's new device. */
function attack(): Promise<string> {
  const code = codeFor('Daniel Mensah')
  const decoy = (JSON.parse(admin(['decoys', '--json'])) as { files: string[] }).files[0]!
  return new Promise((done, fail) => {
    const child = spawn('bash', ['scripts/compose.sh', '-p', 'qgdemo', '-f', 'docker-compose.yml', '-f', 'scripts/demo-video.compose.yml',
      'exec', '-T', 'quantumguard', 'python', '-', code, decoy], { cwd: ROOT })
    let out = ''
    child.stdout.on('data', (b: Buffer) => { out += b.toString() })
    child.on('close', (status) => (status === 0 ? done(out.trim()) : fail(new Error(`attacker exited ${status}: ${out}`))))
    child.stdin.end(readFileSync(join(ROOT, 'scripts', 'demo-attacks.py')))
  })
}

async function waitHealthy(): Promise<void> {
  const url = `http://localhost:${PORT}/healthz`
  for (let i = 0; i < 120; i++) {
    try {
      if ((await fetch(url)).ok) return
    } catch { /* still starting */ }
    await pause(0.5)
  }
  throw new Error('the demo server did not come back')
}

/** A restart ends every session and the console locks; reload and unlock with the passphrase. */
async function unlockAgain(page: Page): Promise<void> {
  await page.reload()
  const field = page.getByTestId('unlock-passphrase')
  await expect(field.or(page.getByTestId('user-menu'))).toBeVisible()
  if (await field.isVisible()) {
    await field.pressSequentially(PASSPHRASE, { delay: 25 })
    await page.getByTestId('unlock-submit').click()
  }
  await expect(page.getByTestId('user-menu')).toBeVisible()
}

const fileRow = (page: Page) => page.locator('[data-testid^="file-row-"]').filter({ hasText: FILE })
const deviceRow = (page: Page, name: string) => page.locator('[data-testid^="device-row-"]').filter({ hasText: name })

async function openFile(page: Page): Promise<void> {
  await nav(page, 'Files')
  await expect(fileRow(page)).toBeVisible()
  const download = page.waitForEvent('download')
  await fileRow(page).getByRole('button', { name: `Open ${FILE}` }).click()
  await download
  await expect(fileRow(page).getByTestId('file-verified')).toContainText('Checked on this device')
}

// ---- the take -----------------------------------------------------------------------------------------------

test('QuantumGuard demo (timed, for screen recording)', async ({ browser }) => {
  test.setTimeout(10 * 60_000)
  const pdf = Buffer.concat([Buffer.from('%PDF-1.7\n% synthetic trial protocol for the demo\n'), Buffer.alloc(180_000, 7)])

  // Off camera: three windows at one position. Aiko's phone and the operator enrol before the take, so the file
  // protected on camera is wrapped for both of Aiko's devices from the start.
  const win = await openWindow(browser)
  const laptop = await tab(win, 'laptop')
  const phone = await tab(win, 'phone')
  const priya = await tab(win, 'ops')
  console.log('Preparing: enrolling Aiko\'s phone and the operator (tabs 2 and 3) before the take ...')
  await enrol(phone, codeFor('Aiko Tanaka'), "Aiko's phone", false)
  await enrol(priya, codeFor('Priya Raman'), "Priya's desk", false)
  await laptop.bringToFront()
  await go(laptop, '/')
  await expect(laptop.getByTestId('hero-launch')).toBeVisible()
  const laptopCode = codeFor('Aiko Tanaka')
  console.log(`\nStart the screen recording now. The take begins in ${LEAD_IN} s.\n`)
  await pause(LEAD_IN)
  t0 = Date.now()

  // 0:00 the claim
  await cue(laptop, 0, 'QuantumGuard: post-quantum file protection that proves what a lost device could read')
  await pause(5)
  await scrollTo(laptop, 'how-it-works')
  await pause(4)
  await laptop.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }))

  // 0:12 enrol the laptop: two key pairs created in the browser
  await cue(laptop, 12, 'Enrol a device: ML-DSA-65 and X-Wing (X25519 + ML-KEM-768) keys are created in the browser')
  await laptop.getByTestId('hero-launch').click()
  await enrol(laptop, laptopCode, "Aiko's laptop", true)

  // 0:40 protect a confidential file
  await cue(laptop, 40, 'Protect a file: encrypted here in 1 MiB AES-256-GCM chunks; the key is wrapped per device, then sealed by the server')
  await nav(laptop, 'Files')
  await laptop.getByTestId('files-protect').click()
  await expect(laptop.getByTestId('protect-dialog')).toBeVisible()
  await laptop.getByTestId('protect-file-input').setInputFiles({ name: FILE, mimeType: 'application/pdf', buffer: pdf })
  await choose(laptop, 'protect-level-confidential')
  await pause(1.5)
  await laptop.getByTestId('protect-submit').click()
  await expect(laptop.getByTestId('protect-receipt')).toBeVisible({ timeout: 30_000 })
  await pause(4)
  await laptop.getByTestId('protect-done').click()

  // 1:00 open it: a policy decision now, a 60 s lease, a receipt
  await cue(laptop, 60, 'Opening asks the policy engine at that moment; every allow or deny becomes a signed, logged receipt')
  await openFile(laptop)
  await pause(3)

  // 1:15 the phone (enrolled off camera) opens the same file, then sits on the public Status page. That page makes
  // no signed requests, so the phone does not learn it is revoked until it next signs in (after the restart).
  await cue(phone, 75, "Aiko's phone opens the same file: it has its own wrapped key")
  await openFile(phone)
  await pause(2)
  await go(phone, '/status')

  // 1:28 the phone is lost: report it from the laptop
  await cue(laptop, 88, 'The phone is lost. From the laptop: report it lost, last safe an hour ago')
  await nav(laptop, 'Devices')
  await deviceRow(laptop, "Aiko's phone").getByRole('button', { name: 'Report lost' }).click()
  const dialog = laptop.getByTestId('revoke-dialog')
  await expect(dialog).toBeVisible()
  await choose(laptop, 'report-preset-hour', dialog)
  await dialog.getByTestId('report-note').pressSequentially('left on the train', { delay: 40 })
  await pause(1)
  await dialog.getByTestId('report-confirm').click()
  const result = laptop.getByTestId('report-result')
  await expect(result).toContainText("Access removed from Aiko's phone")
  await expect(result.getByTestId('report-enforce-ms')).toHaveText(/^\d+\s*ms$/)
  await cue(laptop, now(), `One transaction: revoked, slots deleted, sessions ended, enforced in ${(await result.getByTestId('report-enforce-ms').textContent())?.trim()}`)
  await pause(6)

  // 1:50 crash the server (SIGKILL): the Status page's heartbeat breaks, then reconnects and checks the durable state
  await cue(phone, 110, 'Crash the server: the container is killed with SIGKILL, no clean shutdown')
  const heartbeat = phone.getByTestId('server-pulse')
  await heartbeat.scrollIntoViewIfNeeded()
  await expect(heartbeat).toHaveAttribute('data-phase', 'up')
  await pause(2)
  compose(['kill', 'quantumguard'])
  await expect(heartbeat).toHaveAttribute('data-phase', 'down', { timeout: 15_000 })
  await pause(4)
  await cue(phone, now(), 'Restart it: the revocation was committed to disk before the report returned')
  compose(['start', 'quantumguard'])
  await waitHealthy()
  await expect(heartbeat).toHaveAttribute('data-phase', 'back', { timeout: 30_000 })
  await expect(phone.getByTestId('pulse-verdict')).toContainText('state intact after restart', { timeout: 15_000 })
  await pause(5)

  // 2:10 the lost phone signs in to the restarted server for the first time since the report: refused by the server
  await cue(phone, 130, 'The lost phone signs in to the restarted server: the server refuses it, records it and alerts')
  await go(phone, '/app/files')
  await phone.getByTestId('unlock-passphrase').pressSequentially(PASSPHRASE, { delay: 25 })
  await phone.getByTestId('unlock-submit').click()
  await expect(phone.getByTestId('revoked-page')).toContainText('Access removed from this device')
  await pause(3)

  // 2:22 the laptop unlocks again after the restart (every session ended); the exposed file has its new key
  await cue(laptop, 142, "After the restart the laptop signs in again; the exposed file has a new key; the incident is contained")
  const attacker = attack() // off camera, meanwhile: an attacker with Daniel's new device probes the server
  await unlockAgain(laptop)
  await nav(laptop, 'Files')
  await expect(fileRow(laptop)).toBeVisible()
  await expect(fileRow(laptop)).not.toContainText('New key pending', { timeout: 60_000 })
  await pause(3)
  await nav(laptop, 'Devices')
  await deviceRow(laptop, "Aiko's phone").getByRole('link').first().click()
  await expect(laptop).toHaveURL(/\/app\/ops\/incidents\/inc_/)
  const incidentPath = new URL(laptop.url()).pathname
  await expect(laptop.getByTestId('incident-status')).toContainText('Contained', { timeout: 30_000 })
  await pause(3)

  // 2:15 the operator sees the alert: who, where, what
  console.log(`         attacker: ${await attacker}`)
  await cue(priya, 160, 'Meanwhile an attacker probed: enumeration, replay, a decoy file. Every attempt refused, alerted, contained')
  await unlockAgain(priya)
  await nav(priya, 'Alerts')
  for (const rule of ['QG-R001', 'QG-R002', 'QG-R004', 'QG-R009']) {
    await expect(priya.locator('[data-testid^="alert-row-"]').filter({ hasText: rule }).first()).toBeVisible({ timeout: 30_000 })
  }
  await pause(5)
  await cue(priya, now(), 'Each alert names the identity, the service and the event, with its receipts and its scoped response')
  const row = priya.locator('[data-testid^="alert-row-"]').filter({ hasText: 'QG-R001' }).first()
  await pause(1)
  await row.click()
  const sheet = priya.getByTestId('alert-sheet')
  await expect(sheet.getByTestId('alert-names')).toBeVisible()
  await pause(4)
  await sheet.getByTestId('alert-evidence').scrollIntoViewIfNeeded()
  await pause(3)
  await priya.keyboard.press('Escape')

  // 2:35 the incident and its proof bundle, verified offline in the browser
  await cue(priya, 184, 'Export the proof bundle: receipts, Merkle proofs, checkpoints signed with Ed25519 and ML-DSA-65')
  await priya.evaluate((p) => { window.history.pushState({}, '', p); window.dispatchEvent(new PopStateEvent('popstate')) }, incidentPath)
  await expect(priya.getByTestId('incident-status')).toContainText('Contained')
  await pause(4)
  const download = priya.waitForEvent('download')
  await priya.getByTestId('incident-export').click()
  const saved = await (await download).path()
  await priya.getByTestId('incident-verify').click()
  await expect(priya.getByTestId('verify-result')).toHaveAttribute('data-ok', 'true', { timeout: 30_000 })
  await cue(priya, now(), 'Verified on this device, with public keys only and no network request')
  await pause(5)

  // 3:00 change one receipt: verification fails at its index
  await cue(priya, 207, 'Change one receipt in the bundle: verification fails and names the entry')
  const bundle = JSON.parse(await readFile(saved!, 'utf8')) as { entries: { receipt: { decision: string } }[] }
  const target = bundle.entries[1]!
  target.receipt.decision = target.receipt.decision === 'allow' ? 'deny' : 'allow'
  const tampered = join(tmpdir(), `qg-demo-tampered-${Date.now()}.json`)
  await writeFile(tampered, JSON.stringify(bundle))
  await nav(priya, 'Verify')
  await priya.getByRole('group', { name: 'What to verify' }).getByRole('button', { name: 'A proof bundle' }).click()
  await priya.getByTestId('verify-file-input').setInputFiles(tampered)
  await expect(priya.getByTestId('verify-result')).toHaveAttribute('data-ok', 'false', { timeout: 30_000 })
  await expect(priya.getByTestId('verify-failed-index')).toBeVisible()
  await pause(5)

  // 3:15 limits and measured numbers
  await cue(priya, 220, 'What we do not protect, stated plainly, and the numbers measured on this build')
  await go(priya, '/')
  await scrollTo(priya, 'limits')
  await pause(6)
  await scrollTo(priya, 'performance')
  await pause(6)

  // 3:30 close
  await cue(priya, 233, 'github.com/AkashaPrasad/QuantumGuard: README, threat model, every claim with its test')
  await priya.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }))
  await pause(4)
  console.log(`\nTake finished at ${clock(now())}. Stop the recording.\n`)
})
