import { defineConfig, devices } from '@playwright/test';

// P2 checks run against a real portal that serves the production bundle and real recorded replays
// (SHOWCASE_PORTAL_URL, default the local P1 stack). The browser projects are chosen with --project.
export default defineConfig({
  testDir: './e2e/portal',
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: process.env.SHOWCASE_PORTAL_URL ?? 'http://127.0.0.1:19180',
    trace: 'retain-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'chromium-360', use: { ...devices['Desktop Chrome'], viewport: { width: 360, height: 780 } } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
    { name: 'webkit-360', use: { ...devices['iPhone 13 Mini'], viewport: { width: 360, height: 780 } } },
  ],
});
