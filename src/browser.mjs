import { existsSync } from 'node:fs';
import { chromium } from 'playwright-core';

export function browserPath() {
  const candidates = [process.env.CHROME_PATH, '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome'];
  const found = candidates.find(p => p && existsSync(p));
  if (!found) throw new Error('Chrome not found. Set CHROME_PATH to your Chrome or Chromium executable.');
  return found;
}
export async function createBrowser(options = {}) {
  return chromium.launch({ executablePath: browserPath(), headless: true, ...options });
}
