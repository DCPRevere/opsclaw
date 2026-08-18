import { defineConfig, devices } from '@playwright/test';
import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

const port = Number(process.env.OPSCLAW_WEB_TEST_PORT || 8499);
const baseURL = `http://127.0.0.1:${port}`;

function targetDir(): string {
  try {
    return JSON.parse(execSync('cargo metadata --format-version 1 --no-deps', {
      cwd: resolve(__dirname, '..'), encoding: 'utf8',
    })).target_directory;
  } catch {
    return resolve(__dirname, '..', 'target');
  }
}

function binary(name: string): string {
  const root = targetDir();
  const profiles = process.env.CI ? ['release', 'debug'] : ['debug', 'release'];
  for (const profile of profiles) {
    const candidate = resolve(root, profile, name);
    if (existsSync(candidate)) return candidate;
  }
  return resolve(root, 'release', name);
}

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  timeout: 45_000,
  expect: { timeout: 10_000 },
  use: { baseURL, trace: 'retain-on-failure' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `${resolve(__dirname, 'start-server.sh')} ${binary('opsclaw-cli')} ${binary('opsclaw')} ${port}`,
    url: `${baseURL}/ready`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
