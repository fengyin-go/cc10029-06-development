import { defineConfig } from '@playwright/test'
export default defineConfig({
  testDir: './tests', timeout: 300_000, expect: { timeout: 10_000 }, workers: 1,
  use: { baseURL: 'http://127.0.0.1:5173', browserName: 'chromium', headless: true, actionTimeout: 10_000,
    launchOptions: { executablePath: '/home/node/.cache/ms-playwright/chromium-1255/chrome-linux-arm64/chrome' } },
  reporter: 'line',
})
