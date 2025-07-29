import { test, expect } from '@playwright/test';

const USERNAME = process.env.UAPI_USERNAME || 'sedr';
const PASSWORD = process.env.UAPI_PASSWORD || 'V@iolaptop123';

// The base URL is configured in playwright.config.ts

// Verify login page elements are visible

test('login page loads', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('input[name="username"]')).toBeVisible();
  await expect(page.locator('input[name="password"]')).toBeVisible();
});

// Invalid credentials should show an error

test('invalid login', async ({ page }) => {
  await page.goto('/');
  await page.fill('input[name="username"]', 'invalid');
  await page.fill('input[name="password"]', 'invalid');
  await page.click('button[type="submit"]');
  await expect(page.locator('.error')).toBeVisible();
});

// Valid login should navigate away from the login page

test('valid login', async ({ page }) => {
  await page.goto('/');
  await page.fill('input[name="username"]', USERNAME);
  await page.fill('input[name="password"]', PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForLoadState('networkidle');
  await expect(page).not.toHaveURL(/login/);
  await expect(page.locator('text=Dashboard')).toBeVisible();
});
