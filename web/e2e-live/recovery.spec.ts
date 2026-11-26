import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { admin, device, expect, goto, openFileText, protect, test } from './helpers'

// spec/API.md 6 and 10: before a recovery kit exists files carry no recovery wrap; once the operator issues
// the kit, the directory publishes recovery_pk and every commit must carry one.
test('files carry a recovery wrap only once a recovery kit has been issued', async ({ live, request }) => {
  const tomas = await device(live, 'Tomas Lindqvist', 'Tomas desk (recovery)')
  const commits: Record<string, unknown>[] = []
  tomas.page.on('request', (r) => {
    if (r.method() === 'POST' && /\/api\/v1\/files\/[^/]+\/versions\/\d+\/commit$/.test(new URL(r.url()).pathname)) commits.push(r.postDataJSON() as Record<string, unknown>)
  })

  const directory = async () => (await (await request.get('/api/v1/directory')).json()) as { recovery_pk: string | null }
  if ((await directory()).recovery_pk === null) {
    await protect(tomas.page, 'before-the-kit.txt', 'no recovery slot yet')
    expect(commits.at(-1)).not.toHaveProperty('recovery_wrap')
    // Issue the kit (its private half goes to a file outside the data and keys directories).
    const kitDir = join(process.env.QG_LIVE_DIR!, 'recovery-kit')
    mkdirSync(kitDir, { recursive: true })
    admin(['recovery-kit', 'init', '--out', join(kitDir, 'recovery-kit.json')])
  }
  await expect.poll(async () => (await directory()).recovery_pk).not.toBeNull()

  await protect(tomas.page, 'after-the-kit.txt', 'recoverable by the kit holder')
  expect(commits.at(-1)).toHaveProperty('recovery_wrap')
  expect(await openFileText(tomas.page, 'after-the-kit.txt')).toBe('recoverable by the kit holder')
  await goto(tomas.page, 'Settings')
  await expect(tomas.page.getByTestId('settings-server-keys')).toContainText('Recovery public key')
})
