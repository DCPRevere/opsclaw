import { expect, Page } from '@playwright/test';

export async function login(page: Page) {
  await page.goto('/app');
  await expect(page.locator('#login-card')).toBeVisible();
  await page.locator('#login-email').fill('web@example.com');
  await page.locator('#login-password').fill('web-smoke-password');
  await page.locator('#login-form button[type=submit]').click();
  await expect(page.locator('#nav')).toBeVisible();
}
