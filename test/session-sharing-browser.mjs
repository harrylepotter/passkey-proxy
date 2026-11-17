import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, writeFileSync, readdirSync, cpSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { chromium } from 'playwright-core';
import { browserPath } from '../src/browser.mjs';
import { validateSessionBundle } from '../src/session-handoff.mjs';

const pause = ms => new Promise(r => setTimeout(r, ms));
async function freePort() {
  const server = http.createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const { port } = server.address(); await new Promise(r => server.close(r)); return port;
}
const dir = mkdtempSync(join(tmpdir(), 'cookie-extension-check-'));
const [ownerPort, demoPort, agentPort] = await Promise.all([freePort(), freePort(), freePort()]);
const ownerBase = `http://127.0.0.1:${ownerPort}`, agentBase = `http://127.0.0.1:${agentPort}`;
const site = 'https://app.example.test', publicGateway = 'https://gateway.session.test';
let server, ownerContext, agentContext;
try {
  server = spawn(process.execPath, ['src/server.mjs'], { env: { ...process.env, DATA_DIR: join(dir, 'data'), GATEWAY_PORT: String(ownerPort), DEMO_PORT: String(demoPort), AGENT_PORT: String(agentPort) }, stdio: 'ignore' });
  for (let i = 0; i < 80; i++) { try { if ((await fetch(`${ownerBase}/health`)).ok) break; } catch {} await pause(50); }
  const owner = readFileSync(join(dir, 'data', 'owner-token'), 'utf8').trim();
  const api = (path, data) => fetch(`${ownerBase}${path}`, { method: data === undefined ? 'GET' : 'POST', headers: { Authorization: `Bearer ${owner}`, ...(data === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
  await api('/api/owner/agent-origin', { origin: publicGateway });
  const extension = join(dir, 'extension'); cpSync(resolve('extension'), extension, { recursive: true });
  for (const name of readdirSync(extension)) if (/\.(html|js)$/.test(name)) {
    const path = join(extension, name); writeFileSync(path, readFileSync(path, 'utf8').replaceAll(':4780', `:${ownerPort}`));
  }
  // Pregrant only this synthetic site in the disposable test installation.
  // Production requests the optional cookies + exact host permissions on click.
  const manifestPath = join(extension, 'manifest.json'), manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  manifest.permissions.push('cookies'); manifest.optional_permissions = [];
  manifest.host_permissions.push(`${site}/*`, 'https://example.test/*'); writeFileSync(manifestPath, JSON.stringify(manifest));
  ownerContext = await chromium.launchPersistentContext(join(dir, 'browser'), { executablePath: browserPath(), headless: true,
    ignoreDefaultArgs: ['--disable-extensions'], args: ['--enable-unsafe-extension-debugging'], viewport: { width: 1000, height: 1000 } });
  const cdp = await ownerContext.browser().newBrowserCDPSession();
  const loaded = await cdp.send('Extensions.loadUnpacked', { path: extension });
  const worker = ownerContext.serviceWorkers()[0] || await ownerContext.waitForEvent('serviceworker');
  await worker.evaluate(ownerToken => chrome.storage.local.set({ ownerToken, proxyEnabled: false }), owner);
  const errors = [];
  ownerContext.on('page', page => page.on('pageerror', e => errors.push(e.message)));
  const fixture = async route => {
    const authenticated = (route.request().headers().cookie || '').includes('fixture_session=owner-session-fixture');
    await route.fulfill({ contentType: 'text/html', body: `<h1>${authenticated ? 'Signed in as fixture owner' : 'Sign in required'}</h1>` });
  };
  await ownerContext.route(`${site}/**`, fixture);
  await ownerContext.addCookies([
    { name: 'fixture_session', value: 'owner-session-fixture', domain: 'app.example.test', path: '/', secure: true, httpOnly: true, sameSite: 'Lax' },
    { name: 'parent', value: 'parent-fixture', domain: '.example.test', path: '/', secure: true, httpOnly: true, sameSite: 'Strict', expires: Math.floor(Date.now() / 1000) + 3600 },
    { name: 'path', value: 'path-fixture', domain: 'app.example.test', path: '/dashboard', secure: true, httpOnly: false, sameSite: 'None' },
    { name: 'unrelated', value: 'exclude-unrelated', domain: 'unrelated.test', path: '/', secure: true },
    { name: 'sibling', value: 'exclude-sibling', domain: 'sibling.example.test', path: '/', secure: true },
    { name: 'other_path', value: 'exclude-path', domain: 'app.example.test', path: '/other', secure: true },
    { name: 'partitioned', value: 'exclude-partition', domain: 'app.example.test', path: '/', secure: true, sameSite: 'None', partitionKey: 'https://example.test' },
  ]);
  const website = await ownerContext.newPage(); await website.goto(`${site}/dashboard?private=not-shared#fragment`);
  const popup = await ownerContext.newPage(); await popup.goto(`chrome-extension://${loaded.id}/popup.html`);
  await website.bringToFront();
  await popup.evaluate(() => refreshSharing());
  assert.equal(await popup.locator('#share-site').textContent(), site);
  assert.equal(await popup.locator('#share-session').isEnabled(), true);
  assert.equal((await (await api('/api/owner/state')).json()).sessionInvites.length, 0, 'Opening popup must not capture cookies');
  await popup.evaluate(() => document.querySelector('#share-session').click());
  await popup.locator('#session-result').waitFor({ state: 'visible', timeout: 10000 });
  const instructions = await popup.locator('#session-instructions').inputValue();
  const inviteURL = /Open: (\S+)/.exec(instructions)[1];
  assert.ok(!instructions.includes('owner-session-fixture')); assert.ok(!instructions.includes('private=not-shared'));
  await popup.screenshot({ path: join(dir, 'popup.png'), fullPage: true });
  const token = new URLSearchParams(new URL(inviteURL).hash.slice(1)).get('session');
  const state = await (await api('/api/owner/state')).json();
  assert.equal(state.vault.unlocked, false); assert.equal(state.vault.initialized, false); assert.equal(state.sessionInvites.length, 1);
  assert.ok(!JSON.stringify(state).includes('owner-session-fixture'));
  assert.ok(!JSON.stringify(await worker.evaluate(() => chrome.storage.session.get(null))).includes('owner-session-fixture'));
  await popup.reload(); await website.bringToFront(); await popup.evaluate(() => refreshSharing());
  assert.equal(await popup.locator('#session-instructions').inputValue(), instructions, 'Popup reopening must retain the uncollected invite');

  agentContext = await ownerContext.browser().newContext();
  await agentContext.route(`${publicGateway}/**`, async route => {
    const url = new URL(route.request().url());
    const response = await route.fetch({ url: `${agentBase}${url.pathname}${url.search}` });
    await route.fulfill({ response });
  });
  await agentContext.route(`${site}/**`, fixture);
  const agent = await agentContext.newPage(); await agent.goto(site);
  await agent.getByRole('heading', { name: 'Sign in required' }).waitFor();
  await agent.goto(inviteURL); await agent.locator('#collect-form').waitFor({ state: 'visible' });
  assert.equal(new URL(agent.url()).hash, '');
  assert.match(await agent.locator('#import-requirements').textContent(), /2 HttpOnly cookies/);
  await agent.getByLabel('Agent name', { exact: true }).fill('Cookie fixture agent');
  await agent.getByLabel('What will you use this session for?').fill('Read the fixture page');
  await agent.getByRole('button', { name: 'Collect shared session once' }).click();
  await agent.locator('#handoff').waitFor({ state: 'visible' });
  const bundle = validateSessionBundle(JSON.parse(await agent.locator('#bundle').inputValue()));
  assert.deepEqual(bundle.storageState.cookies.map(c => c.name).sort(), ['fixture_session', 'parent', 'path']);
  await agentContext.addCookies(bundle.storageState.cookies);
  const imported = await agentContext.cookies(`${site}/dashboard`);
  assert.equal(imported.find(c => c.name === 'fixture_session').httpOnly, true);
  assert.equal(imported.find(c => c.name === 'fixture_session').secure, true);
  assert.equal(imported.find(c => c.name === 'fixture_session').domain, 'app.example.test');
  assert.equal(imported.find(c => c.name === 'parent').domain, '.example.test');
  assert.equal(imported.find(c => c.name === 'parent').sameSite, 'Strict');
  assert.equal(imported.find(c => c.name === 'path').path, '/dashboard');
  await agent.goto(`${site}/dashboard`); await agent.getByRole('heading', { name: 'Signed in as fixture owner' }).waitFor();
  const replay = await fetch(`${agentBase}/api/agent/session/redeem`, { method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ agent: 'Replay', purpose: 'Must fail' }) });
  assert.equal(replay.status, 400);
  await website.bringToFront(); await popup.evaluate(() => refreshSharing());
  assert.equal(await popup.locator('#session-result').isVisible(), false);
  assert.deepEqual(errors, []);
  console.log('PASS real extension cookie capture, popup invite/reopening, recipient collection, preserved attributes, isolated agent login and replay rejection.');
  console.log('No vault or passkey was created; unrelated, sibling-only, other-path and partitioned cookies were excluded.');
} finally {
  await agentContext?.close(); await ownerContext?.close();
  if (server && server.exitCode === null) { const done = once(server, 'exit'); server.kill('SIGTERM'); await Promise.race([done, pause(1500)]); }
  rmSync(dir, { recursive: true, force: true });
}
