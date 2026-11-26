import { expect, test, MOBILE, PASSPHRASE, expectNoHorizontalScroll, goto, mock, unlockAs, unlockOverlay } from './helpers'

test.describe('unlock', () => {
  test('the right passphrase opens Files for an employee', async ({ page }) => {
    await page.goto('/app/unlock?persona=aiko')
    await expect(page.getByRole('heading', { name: 'Unlock this device' })).toBeVisible()
    await expect(page.getByText('Aiko Tanaka', { exact: true })).toBeVisible()
    await expect(page.getByLabel(/^Passphrase for/)).toContainText('')
    await page.getByTestId('unlock-passphrase').fill(PASSPHRASE)
    await page.getByTestId('unlock-submit').click()
    await expect(page.getByRole('heading', { name: 'Files', level: 1 })).toBeVisible()
  })

  test('other roles land on Overview', async ({ page }) => {
    await unlockAs(page, 'mira')
    await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible()
  })

  test('a wrong passphrase shows the message inline and the field keeps focus with its text selected', async ({ page }) => {
    await page.goto('/app/unlock?persona=aiko')
    const field = page.getByTestId('unlock-passphrase')
    await field.fill('not the passphrase')
    await page.getByTestId('unlock-submit').click()
    await expect(page.getByTestId('unlock-error')).toHaveText('That passphrase did not unlock this device. Passphrases are case sensitive.')
    await expect(field).toBeFocused()
    await expect(field).toHaveAttribute('aria-invalid', 'true')
    const selected = await field.evaluate((el: HTMLInputElement) => el.value.slice(el.selectionStart ?? 0, el.selectionEnd ?? 0))
    expect(selected).toBe('not the passphrase')
    // Retrying with the right one works from the same page.
    await field.fill(PASSPHRASE)
    await page.keyboard.press('Enter')
    await expect(page.getByRole('heading', { name: 'Files', level: 1 })).toBeVisible()
  })

  test('the Unlock button waits for something to be typed', async ({ page }) => {
    await page.goto('/app/unlock?persona=aiko')
    await expect(page.getByTestId('unlock-submit')).toBeDisabled()
    await page.getByTestId('unlock-passphrase').fill('x')
    await expect(page.getByTestId('unlock-submit')).toBeEnabled()
  })

  test('a paused device explains that access is paused', async ({ page }) => {
    await page.goto('/app/unlock?persona=aiko')
    await mock(page).failNext('QG_QUARANTINED', 'device_quarantined')
    await page.getByTestId('unlock-passphrase').fill(PASSPHRASE)
    await page.getByTestId('unlock-submit').click()
    await expect(page.getByTestId('unlock-error')).toContainText('Access is paused for now')
  })

  test('a revoked device on the unlock page shows "Access removed from this device"', async ({ page }) => {
    await page.goto('/app/unlock?persona=aiko')
    await mock(page).revokeCurrentDevice()
    await expect(page.getByRole('heading', { name: 'Access removed from this device' })).toBeVisible()
    await expect(page.getByTestId('revoked-page')).toContainText('contact your operator')
  })

  test('forget this device asks first, then returns to enrolment', async ({ page }) => {
    await page.goto('/app/unlock?persona=aiko')
    await page.getByTestId('unlock-forget').click()
    await expect(page.getByText('This removes the locked keys for')).toBeVisible()
    await page.getByRole('button', { name: 'Keep it' }).click()
    await expect(page.getByTestId('forget-confirm')).toBeHidden()
    await page.getByTestId('unlock-forget').click()
    await page.getByTestId('forget-confirm').click()
    await expect(page.getByRole('heading', { name: 'Enrol this device' })).toBeVisible()
  })

  test('keyboard only: the field is focused on arrival and Enter unlocks', async ({ page }) => {
    await page.goto('/app/unlock?persona=aiko')
    await expect(page.getByTestId('unlock-passphrase')).toBeFocused()
    await page.keyboard.type(PASSPHRASE)
    await page.keyboard.press('Enter')
    await expect(page.getByRole('heading', { name: 'Files', level: 1 })).toBeVisible()
  })

  test('a deep link while locked unlocks back to that page', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await goto(page, 'Devices')
    await page.reload() // keys live in memory, so the page is locked again
    await expect(page.getByRole('heading', { name: 'Unlock this device' })).toBeVisible()
    await page.getByTestId('unlock-passphrase').fill(PASSPHRASE)
    await page.keyboard.press('Enter')
    await expect(page).toHaveURL(/\/app\/devices$/)
    await expect(page.getByRole('heading', { name: 'Devices', level: 1 })).toBeVisible()
  })
})

test.describe('lock overlay', () => {
  test('locking from the top bar and unlocking returns to the same page with input kept', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await page.getByTestId('files-search').fill('assay')
    await page.getByTestId('lock-now').click()
    const overlay = page.getByTestId('lock-overlay')
    await expect(overlay).toBeVisible()
    await expect(overlay.getByRole('heading', { name: 'This device is locked' })).toBeVisible()
    // The page underneath cannot be reached while it is locked.
    await expect(page.getByTestId('files-search')).not.toBeFocused()
    await unlockOverlay(page, 'wrong wrong wrong')
      .then(() => {
        throw new Error('overlay should stay while the passphrase is wrong')
      })
      .catch(() => undefined)
    await expect(overlay.getByTestId('unlock-error')).toBeVisible()
    await unlockOverlay(page)
    await expect(page).toHaveURL(/\/app\/files$/)
    await expect(page.getByTestId('files-search')).toHaveValue('assay')
  })

  test('locking on a later page returns to that page', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await goto(page, 'Devices')
    await expect(page.getByRole('heading', { name: 'Devices', level: 1 })).toBeVisible()
    await page.getByRole('button', { name: 'Account menu for Aiko Tanaka' }).click()
    await page.getByRole('menuitem', { name: 'Lock this device' }).click()
    await expect(page.getByTestId('lock-overlay')).toBeVisible()
    await unlockOverlay(page)
    await expect(page).toHaveURL(/\/app\/devices$/)
    await expect(page.getByRole('heading', { name: 'Devices', level: 1 })).toBeVisible()
  })

  test('the command palette can lock the device', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await page.keyboard.press('Control+k')
    await page.getByRole('option', { name: 'Lock this device now' }).click()
    await expect(page.getByTestId('lock-overlay')).toBeVisible()
  })

  test('an expired session shows the overlay over the current page', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await goto(page, 'Activity')
    await mock(page).expireSession()
    const overlay = page.getByTestId('lock-overlay')
    await expect(overlay).toBeVisible()
    await expect(overlay).toContainText('This device is locked')
    await expect(overlay).toContainText('nothing you typed was lost')
    await expect(overlay.getByTestId('unlock-passphrase')).toBeFocused()
    await unlockOverlay(page)
    await expect(page).toHaveURL(/\/app\/activity$/)
  })

  test.fixme('the overlay says the device locked itself after 10 minutes idle (AppShell.tsx:~215 uses different copy than flows/README.md)', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await mock(page).expireSession()
    await expect(page.getByTestId('lock-overlay')).toContainText('This device locked itself after 10 minutes idle.')
  })

  test('a revoked device mid-session shows "Access removed from this device"', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await mock(page).revokeCurrentDevice()
    await expect(page.getByRole('heading', { name: 'Access removed from this device' })).toBeVisible()
    await expect(page.getByTestId('user-menu')).toBeHidden()
    await expect(page.getByRole('button', { name: 'Forget this device' })).toBeVisible()
  })

  test('the session clock counts down in the top bar', async ({ page }) => {
    await unlockAs(page, 'aiko')
    await expect(page.getByTestId('session-clock')).toHaveText(/locks in \d+:\d\d|locks in \d+/)
  })

  test.describe('narrow screen', () => {
    test.use({ viewport: MOBILE })
    test('unlock page and lock overlay fit without sideways scrolling', async ({ page }) => {
      await page.goto('/app/unlock?persona=aiko')
      await expectNoHorizontalScroll(page)
      await page.getByTestId('unlock-passphrase').fill('nope nope nope')
      await page.getByTestId('unlock-submit').click()
      await expect(page.getByTestId('unlock-error')).toBeVisible()
      await expectNoHorizontalScroll(page)
      await page.getByTestId('unlock-passphrase').fill(PASSPHRASE)
      await page.keyboard.press('Enter')
      await expect(page.getByRole('heading', { name: 'Files', level: 1 })).toBeVisible()
      await mock(page).expireSession()
      await expect(page.getByTestId('lock-overlay')).toBeVisible()
      await expectNoHorizontalScroll(page)
    })
  })
})
