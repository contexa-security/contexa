import { defineConfig, devices } from '@playwright/test';

// P2-FE-05: the design mock compared with the P0 screenshots kept outside the repository
// (SHOWCASE_VISUAL_BASELINE, the folder of design-<viewport>-<scheme>-<language>.png). Runs on the Vite dev server.
export default defineConfig({
  testDir: './e2e/visual',
  fullyParallel: true,
  retries: 0,
  reporter: [['list']],
  snapshotPathTemplate: `${process.env.SHOWCASE_VISUAL_BASELINE ?? 'visual-baseline'}/{arg}{ext}`,
  use: {
    baseURL: 'http://127.0.0.1:5180',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'npm run dev -- --host 127.0.0.1',
    url: 'http://127.0.0.1:5180',
    reuseExistingServer: true,
    timeout: 120_000,
  },
});
