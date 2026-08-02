import { defineConfig } from '@playwright/test';

/**
 * Accessibility gate. Tests run against the production build served by
 * `vite preview`, so what passes here is what actually ships to Pages.
 * The web server builds first on every run: `vite preview` serves whatever
 * is already in dist/, so relying on a separate earlier build meant a failed
 * build left the previous good bundle in place and the suite passed green
 * against source that no longer compiles.
 */
export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'list' : [['list'], ['html', { open: 'never' }]],
  webServer: {
    command: 'npm run build && npm run preview -- --port 4340 --strictPort',
    url: 'http://localhost:4340/crypto-lab-world-hashes/',
    reuseExistingServer: !process.env.CI,
  },
  use: {
    baseURL: 'http://localhost:4340/crypto-lab-world-hashes/',
    colorScheme: 'dark',
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],
});
