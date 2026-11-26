import type { Page } from '@playwright/test'
import { expect, test, MOBILE, PASSPHRASE, expectNoHorizontalScroll, mock } from './helpers'

async function toStep(page: Page, step: 1 | 2, code = 'KESTREL-AIKO') {
  await page.goto('/app/enrol?persona=none')
  await expect(page.getByTestId('enrol-code')).toBeFocused() // the app has mounted
  await page.getByTestId('enrol-code').fill(code)
  await page.getByTestId('enrol-next').click()
  if (step === 2) {
    await expect(page.getByTestId('enrol-device-name')).toBeVisible()
    await page.getByTestId('enrol-next').click()
  }
}

async function createWith(page: Page, pass = PASSPHRASE) {
  await page.getByTestId('enrol-passphrase').fill(pass)
  await page.getByTestId('enrol-passphrase-confirm').fill(pass)
  await page.getByTestId('enrol-create').click()
}

test.describe('enrol a device', () => {
  test('a valid code goes end to end and lands in the console', async ({ page }) => {
    await toStep(page, 2)
    await createWith(page)
    const progress = page.getByTestId('enrol-progress')
    await expect(progress).toBeVisible()
    await expect(page.getByTestId('enrol-done')).toBeVisible()
    await expect(progress.locator('li[data-state="done"]')).toHaveCount(5)
    await expect(page.getByRole('heading', { name: 'This device is enrolled' })).toBeVisible()
    await page.getByTestId('enrol-done').click()
    // An employee lands on Files.
    await expect(page.getByRole('heading', { name: 'Files', level: 1 })).toBeVisible()
    await expect(page.getByTestId('user-menu')).toBeVisible()
  })

  test('a code for a person with a role lands on Overview', async ({ page }) => {
    await toStep(page, 2, 'KESTREL-MIRA')
    await createWith(page)
    await page.getByTestId('enrol-done').click()
    await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible()
  })

  test('the device name is prefilled and can be changed', async ({ page }) => {
    await toStep(page, 1)
    await expect(page.getByTestId('enrol-device-name')).not.toHaveValue('')
    await page.getByTestId('enrol-device-name').fill('Bench laptop')
    await page.getByTestId('enrol-next').click()
    await createWith(page)
    await expect(page.getByText('Bench laptop can now protect and open files for Aiko Tanaka.')).toBeVisible()
  })

  for (const code of ['WRONG-CODE', 'EXPIRED-CODE']) {
    test(`${code} returns to step 1 with the code kept and the message shown`, async ({ page }) => {
      await toStep(page, 2, code)
      await createWith(page)
      const err = page.getByTestId('enrol-error')
      await expect(err).toBeVisible()
      await expect(err).toContainText('That code did not work')
      await expect(err).toContainText('It may be mistyped, already used, or older than 15 minutes. Ask your admin for a new one.')
      await expect(page.getByTestId('enrol-code')).toHaveValue(code)
      await expect(page.getByTestId('enrol-code')).toBeFocused()
      // Still enrollable: the next valid code works from here.
      await page.getByTestId('enrol-code').fill('KESTREL-AIKO')
      await page.getByTestId('enrol-next').click()
      await page.getByTestId('enrol-next').click()
      await createWith(page)
      await expect(page.getByTestId('enrol-done')).toBeVisible()
    })
  }

  test('a held enrolment explains the hold', async ({ page }) => {
    await toStep(page, 2)
    await mock(page).failNext('QG_QUARANTINED', 'enrolment_held')
    await createWith(page)
    const err = page.getByTestId('enrol-error')
    await expect(err).toContainText('Enrolment is on hold')
    await expect(err).toContainText('A device of yours was reported lost, so new devices wait for an operator.')
  })

  test('a bad signature offers "Start again"', async ({ page }) => {
    await toStep(page, 2)
    await mock(page).failNext('QG_BAD_SIGNATURE')
    await createWith(page)
    await expect(page.getByTestId('enrol-error')).toContainText('This device could not prove its keys')
    await expect(page.getByRole('button', { name: 'Start again' })).toBeVisible()
  })

  test('a passphrase under 10 characters keeps Create disabled and says how many more', async ({ page }) => {
    await toStep(page, 2)
    const create = page.getByTestId('enrol-create')
    await expect(create).toBeDisabled()
    await page.getByTestId('enrol-passphrase').fill('123456789')
    await page.getByTestId('enrol-passphrase-confirm').fill('123456789')
    await expect(page.getByTestId('enrol-strength')).toContainText('1 more character needed')
    await expect(create).toBeDisabled()
    await page.getByTestId('enrol-passphrase').fill('1234567890')
    await page.getByTestId('enrol-passphrase-confirm').fill('1234567890')
    await expect(create).toBeEnabled()
  })

  test('the strength line updates as the passphrase grows', async ({ page }) => {
    await toStep(page, 2)
    const strength = page.getByTestId('enrol-strength')
    await page.getByTestId('enrol-passphrase').fill('abcdefghij')
    await expect(strength).toHaveAttribute('data-score', '1')
    await page.getByTestId('enrol-passphrase').fill(PASSPHRASE)
    await expect(strength).not.toHaveAttribute('data-score', '0')
    await expect(strength).toContainText(/Strong|Good/)
  })

  test('a mismatch shows the message and blocks Create', async ({ page }) => {
    await toStep(page, 2)
    await page.getByTestId('enrol-passphrase').fill(PASSPHRASE)
    await page.getByTestId('enrol-passphrase-confirm').fill('correct horse batterx')
    await page.getByTestId('enrol-passphrase-confirm').blur()
    await expect(page.getByTestId('enrol-mismatch')).toHaveText('The two passphrases are different.')
    await expect(page.getByTestId('enrol-create')).toBeDisabled()
    await page.getByTestId('enrol-passphrase-confirm').fill(PASSPHRASE)
    await expect(page.getByTestId('enrol-mismatch')).toBeHidden()
    await expect(page.getByTestId('enrol-create')).toBeEnabled()
  })

  test('show and hide switches the passphrase fields between dots and text', async ({ page }) => {
    await toStep(page, 2)
    await expect(page.getByTestId('enrol-passphrase')).toHaveAttribute('type', 'password')
    await page.getByRole('button', { name: 'Show passphrase' }).click()
    await expect(page.getByTestId('enrol-passphrase')).toHaveAttribute('type', 'text')
    await expect(page.getByTestId('enrol-passphrase-confirm')).toHaveAttribute('type', 'text')
    await page.getByRole('button', { name: 'Hide passphrase' }).click()
    await expect(page.getByTestId('enrol-passphrase')).toHaveAttribute('type', 'password')
  })

  test('Back and Continue keep what was typed', async ({ page }) => {
    await toStep(page, 1)
    await page.getByTestId('enrol-device-name').fill('Kept name')
    await page.getByTestId('enrol-next').click()
    await page.getByTestId('enrol-passphrase').fill(PASSPHRASE)
    await page.getByTestId('enrol-passphrase-confirm').fill(PASSPHRASE)
    await page.getByTestId('enrol-back').click()
    await expect(page.getByTestId('enrol-device-name')).toHaveValue('Kept name')
    await page.getByTestId('enrol-back').click()
    await expect(page.getByTestId('enrol-code')).toHaveValue('KESTREL-AIKO')
    await page.getByTestId('enrol-next').click()
    await page.getByTestId('enrol-next').click()
    await expect(page.getByTestId('enrol-passphrase')).toHaveValue(PASSPHRASE)
    await expect(page.getByTestId('enrol-passphrase-confirm')).toHaveValue(PASSPHRASE)
    await expect(page.getByTestId('enrol-create')).toBeEnabled()
  })

  test('a code that is too short is explained in place instead of sent', async ({ page }) => {
    await page.goto('/app/enrol?persona=none')
    await expect(page.getByTestId('enrol-code')).toBeFocused() // the app has mounted
    await expect(page.getByTestId('enrol-next')).toBeDisabled()
    await page.getByTestId('enrol-code').fill('abc')
    await expect(page.getByTestId('enrol-next')).toBeEnabled()
    await page.getByTestId('enrol-next').click()
    await expect(page.getByTestId('enrol-code-problem')).toContainText('does not look like an enrolment code')
    await expect(page.getByTestId('enrol-code')).toBeFocused()
    await expect(page.getByTestId('enrol-device-name')).toHaveCount(0)
    await page.getByTestId('enrol-code').fill('kestrel-aiko')
    await expect(page.getByTestId('enrol-code-problem')).toHaveCount(0)
    await page.getByTestId('enrol-next').click()
    await expect(page.getByTestId('enrol-device-name')).toBeVisible()
  })

  test('capitals do not matter: a lower-case code enrols', async ({ page }) => {
    await toStep(page, 2, 'kestrel-aiko')
    await createWith(page)
    await expect(page.getByTestId('enrol-done')).toBeVisible()
  })

  test('a refresh in the middle of the form restarts at step 1 with nothing kept', async ({ page }) => {
    await toStep(page, 2)
    await page.getByTestId('enrol-passphrase').fill(PASSPHRASE)
    await page.reload()
    await expect(page.getByTestId('enrol-code')).toBeVisible()
    await expect(page.getByTestId('enrol-code')).toHaveValue('')
    await expect(page.getByRole('listitem').filter({ hasText: 'Step 1' })).toHaveAttribute('aria-current', 'step')
  })

  test('offline disables Create and says why', async ({ page, context }) => {
    await toStep(page, 2)
    await createWithoutSubmit(page)
    await context.setOffline(true)
    await expect(page.getByTestId('enrol-create')).toBeDisabled()
    await expect(page.getByText('You are offline. Enrolment needs a connection.')).toBeVisible()
    await context.setOffline(false)
    await expect(page.getByTestId('enrol-create')).toBeEnabled()
  })

  test('browser Back steps back inside the flow', async ({ page }) => {
    await toStep(page, 1)
    await expect(page.getByTestId('enrol-device-name')).toBeVisible()
    await page.goBack()
    await expect(page.getByTestId('enrol-code')).toBeVisible()
  })

  test('keyboard only: Enter advances, focus lands on the first field of each step', async ({ page }) => {
    await page.goto('/app/enrol?persona=none')
    await expect(page.getByTestId('enrol-code')).toBeFocused()
    await page.keyboard.type('kestrel-aiko')
    await page.keyboard.press('Enter')
    await expect(page.getByTestId('enrol-device-name')).toBeFocused()
    await page.keyboard.press('Enter')
    await expect(page.getByTestId('enrol-passphrase')).toBeFocused()
    await page.keyboard.type(PASSPHRASE)
    await page.keyboard.press('Tab') // show / hide button
    await page.keyboard.press('Tab') // repeat field
    await expect(page.getByTestId('enrol-passphrase-confirm')).toBeFocused()
    await page.keyboard.type(PASSPHRASE)
    await page.keyboard.press('Enter')
    await expect(page.getByTestId('enrol-done')).toBeFocused()
    await page.keyboard.press('Enter')
    await expect(page.getByRole('heading', { name: 'Files', level: 1 })).toBeVisible()
  })

  test('Back is a button reachable by keyboard', async ({ page }) => {
    await toStep(page, 1)
    await page.getByTestId('enrol-back').focus()
    await page.keyboard.press('Enter')
    await expect(page.getByTestId('enrol-code')).toBeFocused()
  })

  test.describe('narrow screen', () => {
    test.use({ viewport: MOBILE })
    test('every step fits without sideways scrolling', async ({ page }) => {
      await page.goto('/app/enrol?persona=none')
      await expectNoHorizontalScroll(page)
      await page.getByTestId('enrol-code').fill('KESTREL-AIKO')
      await page.getByTestId('enrol-next').click()
      await expectNoHorizontalScroll(page)
      await page.getByTestId('enrol-next').click()
      await expectNoHorizontalScroll(page)
      await createWith(page)
      await expect(page.getByTestId('enrol-done')).toBeVisible()
      await expectNoHorizontalScroll(page)
    })

    test('the error state fits too', async ({ page }) => {
      await toStep(page, 2, 'EXPIRED-CODE')
      await createWith(page)
      await expect(page.getByTestId('enrol-error')).toBeVisible()
      await expectNoHorizontalScroll(page)
    })
  })
})

async function createWithoutSubmit(page: Page) {
  await page.getByTestId('enrol-passphrase').fill(PASSPHRASE)
  await page.getByTestId('enrol-passphrase-confirm').fill(PASSPHRASE)
  await expect(page.getByTestId('enrol-create')).toBeEnabled()
}
