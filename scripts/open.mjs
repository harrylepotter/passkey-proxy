import { readFileSync, readdirSync, mkdirSync, cpSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import { chromium } from 'playwright-core';
import { browserPath } from '../src/browser.mjs';

async function open() {
const ownerURL = readFileSync(resolve('.data/owner-url.txt'), 'utf8').trim();
const debugBrowser = process.argv.includes('--debug-browser');
if (!(await fetch('http://127.0.0.1:4780/health').catch(() => null))?.ok) {
  throw new Error('The gateway is not running. Start it with npm start first.');
}
if (debugBrowser && (await fetch('http://127.0.0.1:9223/json/version').catch(() => null))?.ok) {
  const browser = await chromium.connectOverCDP('http://127.0.0.1:9223');
  const context = browser.contexts()[0];
  const page = await context.newPage();
  await page.goto(ownerURL);
  console.log('Opened the owner dashboard in the running local debugging browser.');
  return;
}
const context = await chromium.launchPersistentContext(resolve('.data/owner-browser'), {
  executablePath: browserPath(), headless: false, viewport: null,
  ignoreDefaultArgs: ['--disable-extensions'], args: ['--enable-unsafe-extension-debugging', '--restore-last-session', '--window-size=1440,1050',
    ...(debugBrowser ? ['--remote-debugging-port=9223'] : [])],
});
const page = context.pages()[0] || await context.newPage();
const cdp = await context.browser().newBrowserCDPSession();
// Chrome can retain a debug-loaded worker after the extension is unloaded.
// Give each immutable build its own path/extension ID so code and permissions
// cannot accidentally come from a cached earlier build in this profile.
const source = resolve('extension'), hash = createHash('sha256');
for (const file of readdirSync(source).sort()) { hash.update(file); hash.update(readFileSync(join(source, file))); }
const build = resolve('.data/extension-builds', hash.digest('hex').slice(0, 20));
if (!existsSync(build)) { mkdirSync(build, { recursive: true }); cpSync(source, build, { recursive: true }); }
const manifest = JSON.parse(readFileSync(resolve('extension/manifest.json'), 'utf8'));
const { extensions } = await cdp.send('Extensions.getExtensions');
for (const installed of extensions.filter(item => item.name === manifest.name && (resolve(item.path) !== build || !item.enabled))) {
  await cdp.send('Extensions.uninstall', { id: installed.id });
}
if (!extensions.some(item => resolve(item.path) === build && item.enabled)) await cdp.send('Extensions.loadUnpacked', { path: build });
const loaded = (await cdp.send('Extensions.getExtensions')).extensions.find(item => resolve(item.path) === build);
if (loaded?.version !== manifest.version) throw new Error('The updated passkey extension did not load.');
await page.goto(ownerURL);
console.log(`Opened the owner dashboard in a separate Chrome profile with Passkey Proxy ${loaded.version} loaded.`);
if (debugBrowser) console.log('Local debugging endpoint: http://127.0.0.1:9223');
process.on('SIGINT', () => context.close());
}

await open();
