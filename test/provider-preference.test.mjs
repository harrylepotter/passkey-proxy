import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

test('OS preference survives worker startup and re-pairing, and remains selectable without the gateway', async () => {
  const stored = { ownerToken: 'p'.repeat(43), proxyEnabled: false };
  let attaches = 0, detaches = 0, gatewayOnline = true;
  const source = readFileSync(new URL('../extension/background.js', import.meta.url), 'utf8');
  async function startWorker() {
    let listener;
    const event = () => ({ addListener() {} });
    const chrome = {
      storage: { local: { get: async () => ({ ...stored }), set: async value => Object.assign(stored, value), remove: async key => { delete stored[key]; } } },
      runtime: { getURL: path => `chrome-extension://fixture/${path}`, getManifest: () => ({ version: 'test' }), onInstalled: event(), onStartup: event(), onMessage: { addListener(fn) { listener = fn; } } },
      webAuthenticationProxy: { attach: async () => { attaches++; }, detach: async () => { detaches++; }, onCreateRequest: event(), onGetRequest: event(), onRequestCanceled: event(), onIsUvpaaRequest: event() },
      windows: { onRemoved: event() }, action: { setBadgeText: async () => {}, setBadgeBackgroundColor: async () => {} },
    };
    const context = vm.createContext({ chrome, URL, AbortSignal, setTimeout, clearTimeout, fetch: async () => { if (!gatewayOnline) throw new Error('Gateway unavailable'); return { ok: true, json: async () => ({ vault: { unlocked: false } }) }; } });
    context.importScripts = file => vm.runInContext(readFileSync(new URL(`../extension/${file}`, import.meta.url), 'utf8'), context);
    vm.runInContext(source, context);
    await vm.runInContext('attachmentReady', context);
    return (message, sender = { url: 'chrome-extension://fixture/popup.html' }) => new Promise(resolve => listener(message, sender, resolve));
  }
  let send = await startWorker();
  assert.equal(attaches, 0); assert.equal(detaches, 1);
  const paired = await send({ action: 'pair', ownerToken: stored.ownerToken }, { url: 'http://127.0.0.1:4780/', frameId: 0 });
  assert.equal(paired.value.enabled, false); assert.equal(attaches, 0);
  assert.equal((await send({ action: 'toggle', enabled: true })).value.enabled, true);
  gatewayOnline = false;
  const unavailable = await send({ action: 'status' });
  assert.equal(unavailable.value.enabled, true); assert.equal(unavailable.value.gatewayError, 'Gateway unavailable');
  assert.equal((await send({ action: 'use-os', id: 'expired-request' })).value.enabled, false);
  assert.equal(stored.proxyEnabled, false);
  const previousAttaches = attaches;
  send = await startWorker();
  assert.equal(attaches, previousAttaches, 'Restart must not reattach the vault after an OS choice');
  assert.equal((await send({ action: 'status' })).value.enabled, false);
});
