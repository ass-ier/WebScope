import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  outputDir: process.env.WEBSCOPE_TEST_HOSTED === '1' ? './test-results/hosted' : './test-results/local',
  testMatch: process.env.WEBSCOPE_TEST_HOSTED === '1' ? '**/temporary-workspace.spec.ts' : '**/workstation.spec.ts',
  fullyParallel: false,
  use: {
    baseURL: process.env.WEBSCOPE_BASE_URL || 'http://127.0.0.1:5173',
    ignoreHTTPSErrors: process.env.WEBSCOPE_TEST_HTTPS === '1',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
