import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { defineConfig, devices } from '@playwright/test'

// The live suite: the real browser client against the real Python server, nothing mocked.
//   API  127.0.0.1:8091  fresh data and keys directory per run (QG_LIVE_DIR)
//   web  127.0.0.1:5181  Vite dev server without the mock, proxying /api to the API
// Kept off 8080, 5173, 5174, 5175 and 5180, which other people and the mock suite use.
export const API_PORT = 8091
export const WEB_PORT = 5181
const ROOT = resolve(import.meta.dirname, '..')

// The runner loads this file first and sets QG_LIVE_DIR; workers inherit it and reuse the same directory.
if (!process.env.QG_LIVE_DIR) {
  const dir = mkdtempSync(join(tmpdir(), 'qg-live-'))
  process.env.QG_LIVE_DIR = dir
  process.on('exit', () => rmSync(dir, { recursive: true, force: true }))
}
const LIVE = process.env.QG_LIVE_DIR

export default defineConfig({
  testDir: './e2e-live',
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: `http://127.0.0.1:${WEB_PORT}`,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'live', use: { ...devices['Desktop Chrome'] } }],
  webServer: [
    {
      command: 'uv run --quiet --project backend python -m qg.server',
      cwd: ROOT,
      url: `http://127.0.0.1:${API_PORT}/healthz`,
      reuseExistingServer: false,
      timeout: 120_000,
      stdout: 'ignore',
      stderr: 'pipe',
      env: {
        QG_DATA_DIR: join(LIVE, 'data'),
        QG_KEYS_DIR: join(LIVE, 'keys'),
        QG_PORT: String(API_PORT),
        QG_DEMO: '0',
        PYTHONPATH: `${join(ROOT, 'backend')}:${join(ROOT, 'cli')}`,
      },
    },
    {
      command: 'pnpm exec vite --host 127.0.0.1',
      url: `http://127.0.0.1:${WEB_PORT}/`,
      reuseExistingServer: false,
      timeout: 120_000,
      env: { QG_WEB_PORT: String(WEB_PORT), QG_API: `http://127.0.0.1:${API_PORT}` },
    },
  ],
})
