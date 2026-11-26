import { defineConfig } from '@playwright/test'

// The timed demo for screen recording (brief/video-script.md). Started by scripts/demo-video.sh against a
// fresh Docker stack; QG_DEMO_URL points at it. Windows are visible and sized by QG_DEMO_SIZE (default 1440x900).
const [W, H] = (process.env.QG_DEMO_SIZE ?? '1440x900').split('x').map(Number)

export default defineConfig({
  testDir: '.',
  testMatch: 'record.spec.ts',
  workers: 1,
  retries: 0,
  timeout: 10 * 60_000,
  expect: { timeout: 30_000 },
  reporter: [['list']],
  use: {
    baseURL: process.env.QG_DEMO_URL ?? 'http://localhost:18080',
    headless: process.env.QG_DEMO_HEADLESS === '1',
    viewport: null,
    acceptDownloads: true,
    video: 'off',
    launchOptions: { args: [`--window-size=${W},${H}`, '--window-position=0,0', '--hide-crash-restore-bubble'] },
  },
})
