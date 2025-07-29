import { defineConfig } from '@playwright/test';

export default defineConfig({
  use: {
    baseURL: process.env.UAPI_URL || 'https://qc.uapi.sa/login',
    headless: true
  },
  testDir: 'tests',
  fullyParallel: true,
  reporter: [['list']]
});
