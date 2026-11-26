import { defineConfig, devices } from '@playwright/test'

// Two dev servers, each with its own copy of the in-memory mock, kept off 5173 (used by other people).
//   mock       5174  default idle time
//   mock-idle  5175  VITE_QG_IDLE_MS=4000, only for the auto-lock spec
const MOCK_PORT = 5174
const IDLE_PORT = 5175

const server = (port: number, extra: Record<string, string> = {}) => ({
  command: 'pnpm exec vite',
  url: `http://localhost:${port}/`,
  reuseExistingServer: !process.env.CI,
  timeout: 120_000,
  env: { QG_WEB_PORT: String(port), VITE_QG_MOCK: '1', ...extra },
})

// To add Firefox or WebKit later, add one line per browser here, for example:
//   { name: 'mock-firefox', ...mockProject(devices['Desktop Firefox']) },
const mockProject = (device: (typeof devices)[string]) => ({
  use: { ...device, baseURL: `http://localhost:${MOCK_PORT}` },
  testIgnore: [/\.idle\.spec\.ts$/],
})

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: { trace: 'retain-on-failure', screenshot: 'only-on-failure' },
  projects: [
    { name: 'mock', ...mockProject(devices['Desktop Chrome']) },
    {
      name: 'mock-idle',
      use: { ...devices['Desktop Chrome'], baseURL: `http://localhost:${IDLE_PORT}` },
      testMatch: [/\.idle\.spec\.ts$/],
    },
  ],
  webServer: [server(MOCK_PORT), server(IDLE_PORT, { VITE_QG_IDLE_MS: '4000' })],
})
