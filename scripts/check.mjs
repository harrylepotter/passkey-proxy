import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, mkdirSync, rmSync, cpSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { chromium } from 'playwright-core';
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import { createBrowser, browserPath } from '../src/browser.mjs';
import { checkProviderSwitch } from '../test/provider-browser.mjs';
import { verifyRegistration, verifyAuthentication } from '../src/webauthn.mjs';
import { checkPersistentLinks } from '../test/persistent-link-browser.mjs';
import { checkOwnerAccess } from '../test/owner-access-browser.mjs';
const dir = mkdtempSync(join(tmpdir(), 'passkey-proxy-check-'));
const gateway = 'http://127.0.0.1:4870', site = 'http://localhost:4871', agentGateway = 'http://127.0.0.1:4872';
const testExtension = join(dir, 'extension'); cpSync(resolve('extension'), testExtension, { recursive: true });
for (const file of readdirSync(testExtension)) if (/\.(js|html)$/.test(file)) {
  const path = join(testExtension, file); writeFileSync(path, readFileSync(path, 'utf8').replaceAll(':4780', ':4870').replaceAll(':4781', ':4871'));
}
let server, serverOutput = '', ownerContext, agentBrowser, importedContext;
const pause = ms => new Promise(r => setTimeout(r, ms));
const errors = [];
const observe = page => page.on('pageerror', error => errors.push(error.message));
try {
  ownerContext = await chromium.launchPersistentContext(join(dir, 'browser'), { executablePath: browserPath(), headless: true, viewport: { width: 1450, height: 1100 }, ignoreDefaultArgs: ['--disable-extensions'], args: ['--enable-unsafe-extension-debugging', '--remote-debugging-port=0'] });
  const debugPort = readFileSync(join(dir, 'browser', 'DevToolsActivePort'), 'utf8').split('\n')[0];
  server = spawn(process.execPath, ['src/server.mjs'], { env: { ...process.env, DATA_DIR: dir, GATEWAY_PORT: '4870', DEMO_PORT: '4871', AGENT_PORT: '4872', OWNER_BROWSER_ENDPOINT: `http://127.0.0.1:${debugPort}` }, stdio: ['ignore', 'pipe', 'pipe'] });
  server.stdout.on('data', data => { serverOutput += data; }); server.stderr.on('data', data => { serverOutput += data; });
  for (let i = 0; i < 50; i++) {
    if (server.exitCode !== null) throw new Error(`Test server stopped: ${serverOutput}`);
    try { if ((await fetch(`${gateway}/health`)).ok) break; } catch {}
    await pause(100);
  }
  const ownerToken = readFileSync(join(dir, 'owner-token'), 'utf8').trim();
  const api = async (path, secret, data, extra = {}) => fetch(`${gateway}${path}`, { method: data === undefined ? 'GET' : 'POST', headers: { Authorization: `Bearer ${secret}`, ...(data === undefined ? {} : { 'Content-Type': 'application/json' }), ...extra }, ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
  assert.equal((await api('/api/owner/state', 'invalid')).status, 401);
  assert.equal((await api('/api/owner/vault/lock', ownerToken, {}, { Origin: 'https://evil.test' })).status, 403);
  assert.equal((await fetch(`${site}/api/register/options`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 401);
  console.log('PASS owner/agent separation, enrollment authorization and cross-origin rejection');
  await checkOwnerAccess({ ownerContext, gateway, ownerToken });
  if (!process.argv.includes('--owner-access-only')) {
  const owner = ownerContext.pages()[0]; observe(owner);
  const cdp = await ownerContext.browser().newBrowserCDPSession();
  await cdp.send('Extensions.loadUnpacked', { path: testExtension });
  await owner.goto(`${gateway}/#owner=${ownerToken}`);
  await owner.getByLabel('Vault passphrase', { exact: true }).fill('a-demo-only-passphrase-2026');
  await owner.getByRole('button', { name: 'Create encrypted vault' }).click();
  await owner.getByRole('heading', { name: 'Your vault is ready.' }).waitFor();
  await owner.getByRole('button', { name: 'Connect extension', exact: true }).click();
  await owner.getByText('Extension connected', { exact: true }).waitFor();
  const sitePromise = ownerContext.waitForEvent('page');
  await owner.getByRole('button', { name: 'Register a passkey' }).click();
  const demo = await sitePromise; observe(demo);
  await demo.waitForLoadState();
  const approvalPromise = ownerContext.waitForEvent('page');
  await demo.getByRole('button', { name: 'Create passkey in vault' }).click();
  const approval = await approvalPromise; observe(approval);
  await approval.getByRole('button', { name: 'Approve', exact: true }).click();
  await demo.getByRole('heading', { name: 'Welcome back, Demo User.' }).waitFor();
  console.log('PASS real extension registration, explicit approval and WebAuthn verification');
  await checkProviderSwitch({ ownerContext, owner, api, ownerToken, observe });
  if (!process.argv.includes('--provider-only')) {
  // Chrome trusts *.localhost as secure contexts without any TLS/security bypass.
  // All fixture content is local; no requests reach real accounts.
  const fixture = await ownerContext.newPage(); observe(fixture);
  await fixture.route('**/*', route => new URL(route.request().url()).pathname.startsWith('/.well-known/')
    ? route.abort() : route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>WebAuthn provider check</title><h1>Isolated WebAuthn fixture</h1>' }));
  const challenge = () => randomBytes(32).toString('base64url');
  const hash = value => createHash('sha256').update(value).digest();
  const ceremony = async (operation, options, wrongPassword = false) => {
    await fixture.bringToFront();
    const popupPromise = ownerContext.waitForEvent('page');
    await fixture.evaluate(({ operation, options }) => {
      window.ceremonyResult = null;
      const publicKey = operation === 'create' ? PublicKeyCredential.parseCreationOptionsFromJSON(options) : PublicKeyCredential.parseRequestOptionsFromJSON(options);
      navigator.credentials[operation]({ publicKey }).then(credential => {
        window.ceremonyResult = { native: credential instanceof PublicKeyCredential, credential: credential.toJSON() };
      }, error => { window.ceremonyResult = { error: error.message, name: error.name }; });
    }, { operation, options });
    const popup = await Promise.race([popupPromise, fixture.waitForFunction(() => window.ceremonyResult?.error).then(async () => { throw new Error(JSON.stringify(await fixture.evaluate(() => window.ceremonyResult))); })]); observe(popup);
    if (wrongPassword) {
      await popup.getByLabel('Verify with vault passphrase').fill('deliberately-wrong-passphrase');
      await popup.getByRole('button', { name: 'Approve', exact: true }).click();
      await popup.getByText('Could not unlock the vault. Check the passphrase.', { exact: true }).waitFor();
      assert.equal(await fixture.evaluate(() => window.ceremonyResult), null);
      await pause(process.argv.includes('--quick') ? 800 : 32000); // Normal run also checks MV3 idle lifetime.
    }
    await popup.getByLabel('Verify with vault passphrase').fill('a-demo-only-passphrase-2026');
    await popup.getByRole('button', { name: 'Approve', exact: true }).click();
    await fixture.waitForFunction(() => window.ceremonyResult !== null);
    const result = await fixture.evaluate(() => window.ceremonyResult);
    assert.equal(result.error, undefined); assert.equal(result.native, true);
    return result.credential;
  };
  for (const [hostname, rpId, alg] of [['auth.first.localhost', 'first.localhost', -8], ['login.second.localhost', 'second.localhost', -7], ['login.third.localhost', 'third.localhost', -257]]) {
    const origin = `http://${hostname}`;
    await fixture.goto(origin);
    assert.equal(await fixture.evaluate(() => PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()), true);
    const options = { challenge: challenge(), rp: { name: 'Provider fixture', id: rpId }, user: { id: 'dGVzdC11c2Vy', name: 'provider@example.test', displayName: 'Provider check' },
      pubKeyCredParams: [{ type: 'public-key', alg }], timeout: 60000, attestation: 'none',
      authenticatorSelection: { residentKey: 'required', userVerification: 'required', requireResidentKey: true }, extensions: { credProps: true } };
    const bypass = await api('/api/extension/credential', ownerToken, { operation: 'create', origin, options, userVerified: true });
    assert.equal(bypass.status, 400, 'An unlocked vault or caller UV flag must not bypass fresh verification');
    const created = await ceremony('create', options, alg === -8);
    assert.equal(created.clientExtensionResults.credProps.rk, true);
    assert.equal(created.response.publicKeyAlgorithm, alg);
    const creationData = JSON.parse(Buffer.from(created.response.clientDataJSON, 'base64url'));
    assert.equal(creationData.origin, origin); assert.equal(creationData.challenge, options.challenge);
    const creationAuth = Buffer.from(created.response.authenticatorData, 'base64url');
    assert.equal(creationAuth[32] & 5, 5); assert.deepEqual(creationAuth.subarray(0, 32), hash(rpId));
    await pause(800);
    const assertionOptions = { challenge: challenge(), rpId, userVerification: 'required', allowCredentials: [{ id: created.id, type: 'public-key' }] };
    const signed = await ceremony('get', assertionOptions);
    assert.equal(signed.id, created.id);
    const authData = Buffer.from(signed.response.authenticatorData, 'base64url'), clientData = Buffer.from(signed.response.clientDataJSON, 'base64url');
    assert.equal(authData[32] & 5, 5); assert.equal(authData.readUInt32BE(33), 1);
    assert.equal(JSON.parse(clientData).challenge, assertionOptions.challenge); assert.equal(JSON.parse(clientData).origin, origin);
    assert.equal(verify(alg === -8 ? null : 'sha256', Buffer.concat([authData, hash(clientData)]), createPublicKey({ key: Buffer.from(created.response.publicKey, 'base64url'), type: 'spki', format: 'der' }), Buffer.from(signed.response.signature, 'base64url')), true);
    await pause(800);
  }
  const pagesBeforeInvalidRP = ownerContext.pages().length;
  for (const [origin, rpId] of [['https://login.example.com', 'service.example.test'], ['https://login.example.co.uk', 'co.uk']]) {
    await fixture.goto(origin);
    const name = await fixture.evaluate(async rpId => {
      try { await navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rpId, timeout: 3000 } }); return 'unexpected-success'; }
      catch (error) { return error.name; }
    }, rpId);
    assert.equal(name, 'SecurityError');
    assert.equal(ownerContext.pages().length, pagesBeforeInvalidRP, 'Chrome must reject invalid RP scope before showing approval');
  }
  await fixture.close();
  console.log('PASS native WebAuthn across three secure loopback origins, ES256/Ed25519/RS256, fresh UV, wrong-passphrase retry and browser RP/public-suffix checks');
  await owner.locator('#register').waitFor({ state: 'hidden' });
  await owner.getByLabel('Website account', { exact: true }).selectOption('demo');
  await owner.locator('#reusable-link').uncheck();
  await owner.getByRole('button', { name: 'Create invitation' }).click();
  await owner.locator('#open-agent').waitFor({ state: 'visible' });
  const inviteURL = await owner.locator('#open-agent').getAttribute('href');
  agentBrowser = await createBrowser();
  const agentContext = await agentBrowser.newContext();
  const agent = await agentContext.newPage(); observe(agent); await agent.goto(inviteURL);
  await agent.getByLabel('What do you need access for?').fill('Read my upcoming trips and booking references.');
  await agent.getByLabel('Agent name', { exact: true }).fill('Fixture agent');
  const demoChallenge = await (await agentContext.request.post(`${site}/api/auth/options`, { data: {} })).json();
  await agent.getByLabel('Website WebAuthn request options').fill(JSON.stringify(demoChallenge.publicKey));
  await agent.getByRole('button', { name: 'Request passkey approval' }).click();
  await agent.getByRole('heading', { name: 'Waiting for approval' }).waitFor();
  const requestToken = await agent.evaluate(() => sessionStorage.getItem('request-token'));
  assert.equal((await api('/api/owner/state', requestToken)).status, 401);
  assert.equal((await api('/api/agent/redeem', requestToken, {})).status, 400);
  await owner.getByLabel('Vault passphrase for this sign-in').fill('a-demo-only-passphrase-2026');
  await owner.getByRole('button', { name: 'Approve passkey sign-in', exact: true }).click();
  await agent.getByRole('button', { name: 'Collect passkey response once' }).waitFor({ timeout: 35000 });
  assert.ok(!JSON.stringify(await (await api('/api/owner/state', ownerToken)).json()).includes('demo_travel_session'));
  await agent.getByRole('button', { name: 'Collect passkey response once' }).click();
  await agent.getByText('Passkey response collected. Complete the website login from your original client.', { exact: true }).waitFor();
  const bundle = JSON.parse(await agent.locator('#bundle').inputValue());
  assert.equal(bundle.format, 'passkey-proxy/webauthn-v1'); assert.equal(bundle.storageState, undefined);
  assert.ok(!JSON.stringify(bundle).includes('privateKey'));
  assert.equal((await api('/api/agent/redeem', requestToken, {})).status, 400);
  assert.equal((await agentContext.request.get(`${site}/api/me`)).status(), 401);
  assert.equal((await agentContext.request.post(`${site}/api/auth/verify`, { data: { ceremonyId: demoChallenge.ceremonyId, credential: bundle.credential } })).status(), 200);
  const imported = await agentContext.newPage(); observe(imported); await imported.goto(site);
  await imported.getByRole('heading', { name: 'Welcome back, Demo User.' }).waitFor();
  assert.equal((await agentContext.request.get(`${site}/api/me`)).status(), 200);
  const pristine = await agentBrowser.newContext(); assert.equal((await pristine.request.get(`${site}/api/me`)).status(), 401); await pristine.close();
  console.log('PASS fresh passkey login completed by the agent in its own browser context; gateway returns no cookies');
  const externalOptions = { challenge: challenge(), rp: { id: 'example.test', name: 'Independent Website' }, user: { id: 'dGVzdC11c2Vy', name: 'owner@example.test' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], authenticatorSelection: { userVerification: 'discouraged' } };
  const externalCredential = await (await api('/api/extension/credential', ownerToken, { operation: 'create', origin: 'https://login.example.test', options: externalOptions })).json();
  assert.ok(externalCredential.id);
  const chosenSite = 'https://app.example.test';
  const externalPublicKey = verifyRegistration(externalCredential, { challenge: externalOptions.challenge, origin: 'https://login.example.test', rpID: 'example.test' });
  await ownerContext.addCookies([{ name: 'personal_session_must_not_leave', value: 'owner-private-cookie-fixture', domain: '.example.test', path: '/', httpOnly: true, secure: true, sameSite: 'Lax' }]);
  assert.equal((await api('/api/owner/invites', ownerToken, { credentialId: externalCredential.id, site: 'https://evil.test', localPreview: true })).status, 400);
  assert.equal((await api('/api/owner/invites', ownerToken, { credentialId: externalCredential.id, site: chosenSite })).status, 400, 'Do not generate misleading localhost instructions for remote agents');
  const protectedHeaders = { Authorization: `Bearer ${ownerToken}`, 'Content-Type': 'application/json' };
  for (const path of ['/api/owner/state', '/app.js', '/api/owner/vault/lock', '/api/extension/credential', '/api/owner/agent-origin']) {
    assert.equal((await fetch(`${agentGateway}${path}`, { headers: protectedHeaders, ...(path.includes('/state') || path === '/app.js' ? {} : { method: 'POST', body: '{}' }) })).status, 404, `Agent listener exposed ${path}`);
  }
  await owner.getByLabel('Website account', { exact: true }).selectOption(externalCredential.id);
  await owner.getByLabel('Website to open').fill(chosenSite);
  await owner.locator('#local-preview').check();
  await owner.getByRole('button', { name: 'Create invitation' }).click();
  await owner.waitForFunction(() => document.querySelector('#invite-text').value.includes('Independent Website'));
  const externalInviteURL = await owner.locator('#open-agent').getAttribute('href');
  const invitationText = await owner.locator('#invite-text').inputValue();
  assert.ok(invitationText.includes('Independent Website')); assert.ok(invitationText.includes(chosenSite)); assert.ok(!invitationText.includes('Demo Travel'));
  assert.equal(new URL(externalInviteURL).origin, agentGateway);
  const externalAgent = await agentContext.newPage(); observe(externalAgent); await externalAgent.goto(externalInviteURL);
  await externalAgent.getByRole('heading', { name: 'Independent Website', exact: true }).waitFor();
  await externalAgent.getByLabel('What do you need access for?').fill('Verify approved account access in a separate browser.');
  await externalAgent.getByLabel('Agent name', { exact: true }).fill('Fixture agent');
  const externalChallenge = { challenge: challenge(), rpId: 'example.test', userVerification: 'required' };
  await externalAgent.getByLabel('Website WebAuthn request options').fill(JSON.stringify(externalChallenge));
  await externalAgent.getByRole('button', { name: 'Request passkey approval' }).click();
  await externalAgent.getByRole('heading', { name: 'Waiting for approval' }).waitFor();
  const externalToken = await externalAgent.evaluate(() => sessionStorage.getItem('request-token'));
  const externalRequest = await (await fetch(`${agentGateway}/api/agent/request`, { headers: { Authorization: `Bearer ${externalToken}` } })).json();
  assert.equal(externalRequest.target.site, chosenSite);
  assert.equal((await api(`/api/owner/requests/${externalRequest.id}/approve`, ownerToken, {})).status, 400, 'Fresh passphrase verification is required before signing');
  await pause(800);
  await owner.locator(`input[data-passphrase="${externalRequest.id}"]`).fill('a-demo-only-passphrase-2026');
  await owner.locator(`button[data-id="${externalRequest.id}"][data-action="approve"]`).click();
  await externalAgent.getByRole('button', { name: 'Collect passkey response once', exact: false }).waitFor();
  await externalAgent.getByRole('button', { name: 'Collect passkey response once', exact: false }).click();
  await externalAgent.getByText('Passkey response collected. Complete the website login from your original client.', { exact: true }).waitFor();
  const externalBundle = JSON.parse(await externalAgent.locator('#bundle').inputValue());
  assert.equal(externalBundle.format, 'passkey-proxy/webauthn-v1'); assert.equal(externalBundle.storageState, undefined);
  assert.equal(verifyAuthentication(externalBundle.credential, { challenge: externalChallenge.challenge, origin: 'https://login.example.test', rpID: 'example.test', userID: externalOptions.user.id }, externalPublicKey), 1);
  assert.ok(!JSON.stringify(externalBundle).includes('owner-private-cookie-fixture'));
  assert.ok(!JSON.stringify(externalBundle).includes('privateKey'));
  assert.equal((await fetch(`${agentGateway}/api/agent/redeem`, { method: 'POST', headers: { Authorization: `Bearer ${externalToken}`, 'Content-Type': 'application/json' }, body: '{}' })).status, 400);
  assert.equal((await api('/api/owner/agent-origin', ownerToken, { origin: 'http://public.example.test' })).status, 400);
  assert.equal((await api('/api/owner/agent-origin', ownerToken, { origin: 'https://agent.example.test' })).status, 200);
  const publicInvite = await (await api('/api/owner/invites', ownerToken, { credentialId: externalCredential.id, site: chosenSite })).json();
  assert.equal(new URL(publicInvite.url).origin, 'https://agent.example.test'); assert.equal(publicInvite.remote, true);
  assert.equal((await fetch(`${agentGateway}/api/agent/request`, { headers: { Origin: 'https://evil.test', Authorization: `Bearer ${externalToken}` } })).status, 403);
  await api('/api/owner/agent-origin', ownerToken, { origin: '' });
  console.log('PASS real-site instructions, challenge-bound signatures, fresh user verification, no owner-cookie export and isolated agent endpoints');
  mkdirSync(resolve('artifacts'), { recursive: true });
  await owner.getByText('Collected', { exact: true }).first().waitFor();
  await owner.evaluate(() => window.scrollTo(0, 0));
  await owner.screenshot({ path: resolve('artifacts/dashboard.png'), fullPage: true });
  await imported.screenshot({ path: resolve('artifacts/imported-session.png'), fullPage: true });
  const invite2 = await (await api('/api/owner/invites', ownerToken, {})).json();
  const invite2Token = new URLSearchParams(new URL(invite2.url).hash.slice(1)).get('invite');
  const deniedOptions = await (await agentContext.request.post(`${site}/api/auth/options`, { data: {} })).json();
  const denied = await (await api('/api/agent/requests', invite2Token, { agent: 'Second agent', purpose: 'Test denied access', ceremony: { origin: site, options: deniedOptions.publicKey } })).json();
  assert.equal((await api(`/api/owner/requests/${denied.request.id}/deny`, ownerToken, {})).status, 200);
  assert.equal((await api('/api/agent/redeem', denied.accessToken, {})).status, 400);
  await owner.getByRole('button', { name: 'Lock vault', exact: true }).click();
  await owner.getByRole('heading', { name: 'Your keys are safely locked.' }).waitFor();
  const invite3 = await (await api('/api/owner/invites', ownerToken, {})).json();
  const invite3Token = new URLSearchParams(new URL(invite3.url).hash.slice(1)).get('invite');
  const lockedOptions = await (await agentContext.request.post(`${site}/api/auth/options`, { data: {} })).json();
  const locked = await (await api('/api/agent/requests', invite3Token, { agent: 'Third agent', purpose: 'Test locked vault', ceremony: { origin: site, options: lockedOptions.publicKey } })).json();
  assert.equal((await api(`/api/owner/requests/${locked.request.id}/approve`, ownerToken, {})).status, 400);
  assert.equal((await (await api('/api/agent/request', locked.accessToken)).json()).status, 'pending');
  await owner.setViewportSize({ width: 390, height: 844 });
  await owner.evaluate(() => window.scrollTo(0, 0));
  assert.equal(await owner.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, 'Dashboard overflows mobile viewport');
  await owner.screenshot({ path: resolve('artifacts/mobile.png'), fullPage: true });
  assert.deepEqual(errors, []);
  console.log('PASS denied access, locked vault, mobile layout and no browser JavaScript errors');
  // Cross-check the relying-party verifier against Chrome's independent native
  // WebAuthn implementation, rather than only against our software signer.
  const nativeContext = await agentBrowser.newContext();
  const native = await nativeContext.newPage();
  const nativeCDP = await nativeContext.newCDPSession(native);
  await nativeCDP.send('WebAuthn.enable');
  await nativeCDP.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await pause(1100);
  await api('/api/owner/vault/unlock', ownerToken, { passphrase: 'a-demo-only-passphrase-2026' });
  const nativeEnrollment = await (await api('/api/owner/enrollment', ownerToken, {})).json();
  await native.goto(nativeEnrollment.url);
  await native.getByRole('button', { name: 'Create passkey in vault' }).click();
  await native.getByRole('heading', { name: 'Welcome back, Demo User.' }).waitFor();
  await native.getByRole('button', { name: 'Sign out', exact: true }).click();
  await native.getByRole('button', { name: 'Sign in with passkey', exact: true }).click();
  await native.getByRole('heading', { name: 'Welcome back, Demo User.' }).waitFor();
  await nativeContext.close();
  console.log('PASS independent native Chrome WebAuthn registration and authentication');
  await owner.setViewportSize({ width: 1450, height: 1100 });
  await checkPersistentLinks({ owner, agentContext, api, ownerToken, externalCredential, chosenSite, dir, observe, restart: async () => {
    server.kill('SIGTERM'); await new Promise(resolve => server.once('exit', resolve));
    server = spawn(process.execPath, ['src/server.mjs'], { env: { ...process.env, DATA_DIR: dir, GATEWAY_PORT: '4870', DEMO_PORT: '4871', AGENT_PORT: '4872', OWNER_BROWSER_ENDPOINT: `http://127.0.0.1:${debugPort}` }, stdio: ['ignore', 'pipe', 'pipe'] });
    server.stdout.on('data', data => { serverOutput += data; }); server.stderr.on('data', data => { serverOutput += data; });
    for (let i = 0; i < 50; i++) {
      if (server.exitCode !== null) throw new Error('Restarted test server stopped.');
      try { if ((await fetch(`${gateway}/health`)).ok) return; } catch {}
      await pause(100);
    }
    throw new Error('Restarted test server did not become ready.');
  } });
  }
  }
  assert.deepEqual(errors, []);
  console.log(process.argv.includes('--owner-access-only') ? 'All owner access checks passed.' : process.argv.includes('--provider-only') ? 'All provider checks passed.' : 'All browser checks passed. Screenshots saved in artifacts/. No session secrets saved.');
} catch (error) {
  console.error(error.message);
  console.error(serverOutput.slice(-1800));
  if (ownerContext) {
    for (const page of ownerContext.pages()) console.error('Page:', new URL(page.url()).origin, (await page.locator('body').innerText().catch(() => '')).slice(0, 2000));
  }
  process.exitCode = 1;
} finally {
  await importedContext?.close(); await agentBrowser?.close(); await ownerContext?.close();
  if (server) { server.kill('SIGTERM'); await Promise.race([new Promise(r => server.once('exit', r)), pause(2000)]); }
  rmSync(dir, { recursive: true, force: true });
}
