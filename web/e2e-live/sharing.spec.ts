import type { Page } from '@playwright/test'
import { device, expect, fileRow, goto, openFileText, protect, test, visit } from './helpers'

const FILE = 'plate-map-17.txt'
const TEXT = 'plate 17: columns 3 and 9 are controls'

async function openSheet(page: Page, name: string) {
  await goto(page, 'Files')
  await fileRow(page, name).getByRole('button', { name: new RegExp(name) }).first().click()
  const sheet = page.getByTestId('file-sheet')
  await expect(sheet.getByRole('heading', { name })).toBeVisible()
  return sheet
}

test('share from the file sheet, unshare with confirm (re-keyed, the person is cut off), delete', async ({ live }) => {
  test.setTimeout(120_000)
  const owner = await device(live, 'Tomas Lindqvist', 'Tomas laptop')
  const other = await device(live, 'Daniel Mensah', 'Daniel sharing desk')

  await protect(owner.page, FILE, TEXT)
  const fileId = (await fileRow(owner.page, FILE).getAttribute('data-testid'))!.replace('file-row-', '')
  await goto(other.page, 'Files')
  await expect(fileRow(other.page, FILE)).toHaveCount(0)

  // Share with Daniel from the sheet.
  const sheet = await openSheet(owner.page, FILE)
  const who = sheet.locator('section').filter({ has: owner.page.getByRole('heading', { name: 'Who can open this' }) })
  await owner.page.getByTestId('file-share-open').click()
  await sheet.getByLabel('Daniel Mensah').check()
  await owner.page.getByTestId('share-submit').click()
  await expect(who.getByRole('listitem').filter({ hasText: 'Daniel Mensah' })).toBeVisible()
  expect(await openFileText(other.page, FILE)).toBe(TEXT)

  // Remove Daniel: confirm, the file gets a new key, Daniel can no longer open it.
  const daniel = who.getByRole('listitem').filter({ hasText: 'Daniel Mensah' })
  await daniel.getByRole('button', { name: 'Remove' }).click()
  await expect(daniel).toContainText('Remove access for Daniel Mensah.')
  await owner.page.getByTestId('unshare-confirm').click()
  await expect(who.getByRole('listitem').filter({ hasText: 'Daniel Mensah' })).toHaveCount(0)
  await expect(owner.page.getByTestId('rekey-done')).toContainText('All affected files have new keys', { timeout: 60_000 })
  await expect(sheet.getByText('New key pending')).toHaveCount(0)

  live.refusals.expect({ code: 'QG_NOT_FOUND', path: new RegExp(`/files/${fileId}`) })
  await goto(other.page, 'Files')
  await expect(other.page.getByTestId('files-list').or(other.page.getByTestId('files-empty')).first()).toBeVisible()
  await expect(fileRow(other.page, FILE)).toHaveCount(0)
  await visit(other.page, `/app/files/${fileId}`)
  await expect(other.page.getByTestId('file-sheet').getByTestId('error-notice')).toContainText('Not found')

  // The owner still opens the re-keyed version.
  await owner.page.keyboard.press('Escape')
  expect(await openFileText(owner.page, FILE)).toBe(TEXT)
  const again = await openSheet(owner.page, FILE)
  await expect(again).toContainText(/[Vv]ersion 2|v2/)

  // Delete it.
  await owner.page.getByTestId('file-delete').click()
  await owner.page.getByTestId('file-delete-confirm').click()
  await expect(owner.page.getByTestId('file-sheet')).toBeHidden()
  await expect(fileRow(owner.page, FILE)).toHaveCount(0)
})
