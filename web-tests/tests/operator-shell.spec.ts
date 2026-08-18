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
  expect(body?.conversation).toBe('operations');
  expect(body?.idempotency_key).toMatch(/.+/);
});

test('chat switches between durable environment conversations', async ({ page }) => {
  await login(page);
  await page.route('**/api/chat/conversations', route => route.fulfill({ json: {
    conversations: [
      { id: 'operations', kind: 'operations', label: 'Operations' },
      { id: 'shop::prod', kind: 'environment', label: 'shop / prod' },
    ],
  } }));
  await page.route('**/api/chat/history?conversation=*', route => {
    const conversation = new URL(route.request().url()).searchParams.get('conversation');
    return route.fulfill({ json: { history: [{
      seq: 1, role: 'assistant', speaker: 'assistant',
      content: conversation === 'shop::prod' ? 'production handoff' : 'operations handoff',
      at: '2026-08-18T12:00:00Z',
    }], has_more: false } });
  });
  // Force a fresh catalogue/history read after installing the routes.
  await page.locator('#chat-conversation').evaluate((select: HTMLSelectElement) => {
    delete select.dataset.loaded;
  });
  await page.getByRole('button', { name: 'Incidents' }).click();
  await page.getByRole('button', { name: 'Chat' }).click();

  await page.locator('#chat-conversation').selectOption('shop::prod');
  await expect(page.locator('#chat-log')).toContainText('production handoff');
  await expect(page.locator('#chat-scope-note')).toContainText('restricted to this environment');
});

test('an operator can approve a queued command', async ({ page }) => {
  const id = '11111111-1111-4111-8111-111111111111';
  let pending = true;
  let approved = false;
  await login(page);
  await page.route('**/api/approvals**', async route => {
    const request = route.request();
    if (request.method() === 'POST' && request.url().endsWith(`/${id}/approve`)) {
      approved = true;
      pending = false;
      await route.fulfill({ json: { decision: 'approved', status: 'executed', detail: {} } });
      return;
    }
    await route.fulfill({ json: { approvals: pending ? [{
      id, target: 'shop::prod::api', tool: 'shell', command: 'systemctl restart api',
      risk: 'high', hypothesis: 'the process is wedged', expires_at: '2026-08-18T12:00:00Z',
    }] : [] } });
  });

  await page.getByRole('button', { name: 'Approvals' }).click();
  await expect(page.locator('#approvals-list')).toContainText('systemctl restart api');
  await page.getByRole('button', { name: 'Approve' }).click();
  await expect(page.locator('#approvals-list')).toHaveText(/No pending approvals/);
  expect(approved).toBe(true);
});

test('an operator can acknowledge an active incident', async ({ page }) => {
  const id = '22222222-2222-4222-8222-222222222222';
  let state = 'active';
  const incident = () => ({
    id, target: 'shop::prod::api', severity: 'critical', state,
    hypothesis: 'API error rate is elevated', signals: '5xx above 20%',
    recommended_action: 'inspect the latest deployment',
    opened_at: '2026-08-18T10:00:00Z', notify_count: 1,
  });
  await login(page);
  await page.route('**/api/incidents**', async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === 'POST' && url.pathname.endsWith(`/${id}/ack`)) {
      state = 'acknowledged';
      await route.fulfill({ json: incident() });
    } else if (url.pathname === `/api/incidents/${id}`) {
      await route.fulfill({ json: incident() });
    } else {
      await route.fulfill({ json: { incidents: [incident()] } });
    }
  });

  await page.getByRole('button', { name: 'Incidents' }).click();
  await page.locator(`#incidents-list [data-id="${id}"]`).click();
  await page.getByRole('button', { name: 'Acknowledge' }).click();
  await expect(page.locator('#incident-detail .state-acknowledged')).toBeVisible();
});

test('a failed chat send can be retried as a new idempotent request', async ({ page }) => {
  const keys: string[] = [];
  let sends = 0;
  await login(page);
  await page.route('**/api/chat', async route => {
    const body = route.request().postDataJSON();
    keys.push(body.idempotency_key);
    sends += 1;
    if (sends === 1) {
      await route.fulfill({ status: 503, json: { error: 'provider unavailable' } });
    } else {
      await route.continue();
    }
  });

  await page.locator('#chat-input').fill('check the retry path');
  await page.locator('#chat-form button[type=submit]').click();
  await expect(page.locator('#chat-log')).toContainText('provider unavailable');
  await page.locator('#chat-input').fill('check the retry path');
  await page.locator('#chat-form button[type=submit]').click();
  await expect(page.locator('#chat-log')).toContainText('OK (fake LLM');
  expect(keys).toHaveLength(2);
  expect(keys[0]).not.toBe(keys[1]);
});

test('an uncertain chat delivery reuses its idempotency key', async ({ page }) => {
  const keys: string[] = [];
  let sends = 0;
  await login(page);
  await page.route('**/api/chat', async route => {
    keys.push(route.request().postDataJSON().idempotency_key);
    sends += 1;
    if (sends === 1) {
      await route.abort('connectionrefused');
    } else {
      await route.continue();
    }
  });

  await page.locator('#chat-input').fill('safe transport retry');
  await page.locator('#chat-form button[type=submit]').click();
  await expect(page.locator('#chat-log')).toContainText('Delivery is uncertain');
  await expect(page.locator('#chat-input')).toHaveValue('safe transport retry');
  await page.locator('#chat-form button[type=submit]').click();
  await expect(page.locator('#chat-log')).toContainText('OK (fake LLM');
  expect(keys).toHaveLength(2);
  expect(keys[0]).toBe(keys[1]);
});
