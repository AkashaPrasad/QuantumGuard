import type { Page } from '@playwright/test'
import { device, enrol, expect, goto, invitePerson, test } from './helpers'
import type { LiveDevice } from './helpers'

const deviceRow = (page: Page, name: string) => page.locator('[data-testid^="device-row-"]').filter({ hasText: name })
const idOf = async (page: Page, name: string) => (await deviceRow(page, name).getAttribute('data-testid'))!.replace('device-row-', '')

/** A one-time code from Devices > Add a device on one of the person's own devices. */
async function ownCode(page: Page): Promise<string> {
  await goto(page, 'Devices')
  await page.getByTestId('devices-add').click()
  const add = page.getByRole('dialog', { name: 'Add a device' })
  const code = (await add.getByTestId('invite-code').locator('span').first().textContent())!.trim()
  await add.getByRole('button', { name: 'Close' }).first().click()
  await expect(add).toBeHidden()
  return code
}

async function expectMessage(d: LiveDevice, text: string) {
  await goto(d.page, 'Messages')
  const msg = d.page.locator('[data-testid^="message-msg_"]').filter({ hasText: text })
  await expect(msg).toContainText('Mira Okafor')
  await expect(msg).toContainText('Signature checked on this device')
}

test('a message reaches both devices of the recipient, each checks the signature; a revoked device is not addressed', async ({ live }) => {
  test.setTimeout(150_000)
  // A person of their own, so their devices are exactly the ones this test enrols.
  const mira = await device(live, 'Mira Okafor', 'Mira desk (messages)')
  const laptop = await live.newDevice()
  await enrol(laptop.page, (await invitePerson(mira.page, 'Lena Park'))!, 'Lena laptop')
  const tablet = await live.newDevice()
  await enrol(tablet.page, await ownCode(laptop.page), 'Lena tablet')
  const phone = await live.newDevice()
  await enrol(phone.page, await ownCode(laptop.page), 'Lena old phone')

  // The old phone is reported lost from the laptop.
  await goto(laptop.page, 'Devices')
  const ids = [await idOf(laptop.page, 'Lena laptop'), await idOf(laptop.page, 'Lena tablet')].sort()
  const phoneId = await idOf(laptop.page, 'Lena old phone')
  await phone.page.goto('about:blank')
  await deviceRow(laptop.page, 'Lena old phone').getByRole('button', { name: 'Report lost' }).click()
  await laptop.page.getByTestId('report-confirm').click()
  await expect(laptop.page.getByTestId('report-result')).toBeVisible()
  await laptop.page.getByTestId('revoke-done').click()

  // Mira writes to Lena: one envelope per active device, none for the phone.
  const text = 'The cold room is back at 4 °C.'
  await goto(mira.page, 'Messages')
  await mira.page.getByTestId('message-to').selectOption({ label: 'Lena Park' })
  await mira.page.getByTestId('message-text').fill(text)
  const sent = mira.page.waitForRequest((r) => r.method() === 'POST' && new URL(r.url()).pathname === '/api/v1/messages')
  await mira.page.getByTestId('message-send').click()
  const body = (await sent).postDataJSON() as { to_user_id: string; envelopes: { device_id: string }[] }
  expect(body.envelopes.map((e) => e.device_id)).toEqual(ids)
  expect(body.envelopes.map((e) => e.device_id)).not.toContain(phoneId)
  await expect(mira.page.getByText('Message sent')).toBeVisible()

  // Each device holds only its own envelope plus the signed digests, and checks the signature itself.
  await expectMessage(laptop, text)
  await expectMessage(tablet, text)
})
