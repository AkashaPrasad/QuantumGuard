import { device, expect, goto, test } from './helpers'

test('add a service, rotate its key: active and retiring keys, a new key set epoch', async ({ live }) => {
  const mira = await device(live, 'Mira Okafor', 'Mira desk (services)')
  await goto(mira.page, 'Services')
  const epochText = mira.page.getByText(/Key set epoch \d+\./)
  await expect(epochText).toBeVisible()
  const epoch = async () => Number(/Key set epoch (\d+)/.exec((await epochText.textContent()) ?? '')![1])
  const before = await epoch()

  const name = `freezer-telemetry-${Date.now().toString(36)}`
  await mira.page.getByTestId('service-add').first().click()
  await mira.page.getByTestId('service-name').fill(name)
  await mira.page.getByTestId('service-add-submit').click()
  const svc = mira.page.locator('[data-testid^="service-row-"]').filter({ hasText: name })
  await expect(svc).toBeVisible()
  const keys = svc.locator('[data-testid^="service-key-"]')
  await expect(keys).toHaveCount(1)
  await expect(keys.filter({ hasText: 'Active' })).toHaveCount(1)
  await expect.poll(epoch).toBeGreaterThan(before)
  const afterCreate = await epoch()

  await svc.getByRole('button', { name: 'Rotate key' }).click()
  const dialog = mira.page.getByRole('dialog', { name: `Rotate the key for ${name}` })
  await expect(dialog.getByTestId('rotate-emergency')).toHaveCount(0)
  await dialog.getByTestId('rotate-reason').fill('scheduled quarterly rotation')
  await dialog.getByTestId('rotate-submit').click()
  await expect(keys).toHaveCount(2)
  await expect(keys.filter({ hasText: 'Active' })).toHaveCount(1)
  await expect(keys.filter({ hasText: /Retiring|Retired/ })).toHaveCount(1)
  await expect.poll(epoch).toBeGreaterThan(afterCreate)
})
