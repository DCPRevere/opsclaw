import { test, expect } from '@playwright/test';
import { login } from './helpers';

test('operator shell loads its module graph and critical views', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await login(page);

  await page.getByRole('button', { name: 'Incidents' }).click();
  await expect(page.locator('#incidents-list')).toHaveText(/No incidents/);
  await page.getByRole('button', { name: 'Approvals' }).click();
  await expect(page.locator('#approvals-list')).toHaveText(/No pending approvals/);
  await page.getByRole('button', { name: 'Status' }).click();
  await expect(page.locator('#status-card')).toContainText(/heartbeat/i);
  await page.getByRole('button', { name: 'Settings' }).click();
  await expect(page.locator('#config-toml')).not.toHaveValue('');

  expect(errors).toEqual([]);
});

test('chat sends an idempotency key and renders the fake reply', async ({ page }) => {
  let body: Record<string, unknown> | undefined;
  page.on('request', request => {
    if (request.url().endsWith('/api/chat') && request.method() === 'POST') {
      body = request.postDataJSON();
    }
  });
  await login(page);
  await page.locator('#chat-input').fill('check the test target');
  await page.locator('#chat-form button[type=submit]').click();
  await expect(page.locator('#chat-log')).toContainText('OK (fake LLM');
  expect(body?.message).toBe('check the test target');
  expect(body?.idempotency_key).toMatch(/.+/);
});
