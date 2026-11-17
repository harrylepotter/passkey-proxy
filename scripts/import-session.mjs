import { readFileSync } from 'node:fs';
import { createBrowser } from '../src/browser.mjs';
import { validateSessionBundle } from '../src/session-handoff.mjs';
const file = process.argv[2];
if (!file) { console.error('Usage: npm run import-session -- /path/to/site-session.json'); process.exit(1); }
const bundle = validateSessionBundle(JSON.parse(readFileSync(file, 'utf8')));
const browser = await createBrowser({ headless: false });
const context = await browser.newContext({ storageState: bundle.storageState, viewport: { width: 1250, height: 900 } });
const page = await context.newPage(); await page.goto(bundle.site);
console.log('Opened a fresh agent browser with the imported session. No extension or passkey was supplied.');
browser.on('disconnected', () => process.exit());
process.on('SIGINT', () => browser.close());
