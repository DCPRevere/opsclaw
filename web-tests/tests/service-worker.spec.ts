import { test, expect } from '@playwright/test';
import { login } from './helpers';

test('service worker is versioned and controls the app shell', async ({ page }) => {
  const response = await page.request.get('/sw.js');
  expect(response.status()).toBe(200);
  expect(response.headers()['content-type']).toContain('javascript');
  expect(response.headers()['cache-control']).toBe('no-cache');
  const source = await response.text();
  expect(source).not.toContain('__SW_VERSION__');
  expect(source).toContain("addEventListener('push'");
  expect(source).toContain("addEventListener('notificationclick'");

  await login(page);
  await page.waitForFunction(async () => {
    const registration = await navigator.serviceWorker.ready;
    return !!registration.active && !!navigator.serviceWorker.controller;
  });
  const cached = await page.evaluate(async () => {
    const name = (await caches.keys()).find(value => value.startsWith('opsclaw-shell-'));
    if (!name) return false;
    return !!(await (await caches.open(name)).match('/app/main.js'));
  });
  expect(cached).toBe(true);
});
