import { test, expect } from '@playwright/test';

const USERNAME = process.env.UAPI_USERNAME || 'sedr';
const PASSWORD = process.env.UAPI_PASSWORD || 'V@iolaptop123';

// Reusable login function
async function login(page) {
  await page.goto('/');
  await page.fill('input[name="username"]', USERNAME);
  await page.fill('input[name="password"]', PASSWORD);
  await page.click('button[type="submit"]');
  await page.waitForLoadState('networkidle');
}

test.beforeEach(async ({ page }) => {
  await login(page);
});

test.describe('feature navigation', () => {
  for (const menu of ['Dashboard', 'Users', 'Settings']) {
    test(`navigate to ${menu}`, async ({ page }) => {
      await page.click(`text=${menu}`);
      await page.waitForLoadState('networkidle');
      await expect(page.locator(`h1:has-text("${menu}")`)).toBeVisible();
    });
  }
});

test('logout', async ({ page }) => {
  await login(page);
  await page.click('text=Logout');
  await page.waitForLoadState('networkidle');
  await expect(page).toHaveURL(/login/);
});
