import type { Page } from '@playwright/test'
import { device, enrol, expect, goto, invitePerson, test } from './helpers'

const deviceRow = (page: Page, name: string) => page.locator('[data-testid^="device-row-"]').filter({ hasText: name })
const idOf = async (page: Page, name: string) => (await deviceRow(page, name).getAttribute('data-testid'))!.replace('device-row-', '')

test('send a message: the recipient reads it with the signature checked; a revoked device is not addressed', async ({ live }) => {
  test.setTimeout(120_000)
  // A person of their own, so their devices are exactly the ones this test enrols.
  const mira = await device(live, 'Mira Okafor', 'Mira desk (messages)')
  const code = await invitePerson(mira.page, 'Lena Park')
  const laptop = await live.newDevice()
  await enrol(laptop.page, code!, 'Lena laptop')

  // Lena adds a second device with her own one-time code, then reports it lost.
  await goto(laptop.page, 'Devices')
  await laptop.page.getByTestId('devices-add').click()
  const add = laptop.page.getByRole('dialog', { name: 'Add a device' })
  const second = (await add.getByTestId('invite-code').locator('span').first().textContent())!.trim()
  await add.getByRole('button', { name: 'Close' }).first().click()
  const tablet = await live.newDevice()
  await enrol(tablet.page, second, 'Lena tablet')
  await goto(laptop.page, 'Devices')
  const laptopId = await idOf(laptop.page, 'Lena laptop')
  const tabletId = await idOf(laptop.page, 'Lena tablet')
  await tablet.page.goto('about:blank')
  await deviceRow(laptop.page, 'Lena tablet').getByRole('button', { name: 'Report lost' }).click()
  await laptop.page.getByTestId('report-confirm').click()
  await expect(laptop.page.getByTestId('report-result')).toBeVisible()
  await laptop.page.getByTestId('revoke-done').click()

  // Mira writes to Lena: one envelope, for the laptop only.
  await goto(mira.page, 'Messages')
  await mira.page.getByTestId('message-to').selectOption({ label: 'Lena Park' })
  await mira.page.getByTestId('message-text').fill('The cold room is back at 4 °C.')
  const sent = mira.page.waitForRequest((r) => r.method() === 'POST' && new URL(r.url()).pathname === '/api/v1/messages')
  await mira.page.getByTestId('message-send').click()
  const body = (await sent).postDataJSON() as { to_user_id: string; envelopes: { device_id: string }[] }
  expect(body.envelopes.map((e) => e.device_id)).toEqual([laptopId])
  expect(body.envelopes.map((e) => e.device_id)).not.toContain(tabletId)
  await expect(mira.page.getByText('Message sent')).toBeVisible()

  await goto(laptop.page, 'Messages')
  const msg = laptop.page.locator('[data-testid^="message-msg_"]').first()
  await expect(msg).toContainText('Mira Okafor')
  await expect(msg).toContainText('The cold room is back at 4 °C.')
  await expect(msg).toContainText('Signature checked on this device')
})

// spec/API.md 9: GET /messages returns only this device's envelope, but the sender signs the statement over
// every envelope (spec/SUITE.md 11), so a recipient with two or more active devices cannot check it.
test.fixme('a recipient with two active devices sees the signature-checked mark', async () => {})
