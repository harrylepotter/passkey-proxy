import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const pause = ms => new Promise(r => setTimeout(r, ms));
async function freePort() {
  const server = http.createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const { port } = server.address(); await new Promise(r => server.close(r)); return port;
}
test('cookie session API works without a vault, isolates token roles, and exposes neither cookies nor owner actions before collection', { timeout: 20000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'session-invite-http-'));
  const [ownerPort, demoPort, agentPort] = await Promise.all([freePort(), freePort(), freePort()]);
  const ownerBase = `http://127.0.0.1:${ownerPort}`, agentBase = `http://127.0.0.1:${agentPort}`;
  const server = spawn(process.execPath, ['src/server.mjs'], { env: { ...process.env, DATA_DIR: dir, GATEWAY_PORT: String(ownerPort), DEMO_PORT: String(demoPort), AGENT_PORT: String(agentPort) }, stdio: 'ignore' });
  try {
    for (let i = 0; i < 80; i++) { try { if ((await fetch(`${ownerBase}/health`)).ok) break; } catch {} await pause(50); }
    const owner = readFileSync(join(dir, 'owner-token'), 'utf8').trim();
    const call = (base, path, secret, data, headers = {}) => fetch(`${base}${path}`, { method: data === undefined ? 'GET' : 'POST', headers: { Authorization: `Bearer ${secret}`, ...(data === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers }, ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
    const cookie = { name: 'session', value: 'private-session-fixture', domain: 'app.example.test', path: '/', secure: true, httpOnly: true, hostOnly: true, sameSite: 'strict', session: true };
    const data = { site: 'https://app.example.test', cookies: [cookie], localPreview: true };
    assert.equal((await call(ownerBase, '/api/extension/session-invites', 'wrong', data)).status, 401);
    assert.equal((await call(ownerBase, '/api/extension/session-invites', owner, data, { Origin: 'https://unrelated.test' })).status, 403);
    assert.equal((await call(agentBase, '/api/extension/session-invites', owner, data)).status, 404);
    assert.equal((await call(ownerBase, '/api/extension/session-invites', owner, { ...data, localPreview: false })).status, 400);
    const response = await call(ownerBase, '/api/extension/session-invites', owner, data);
    assert.equal(response.status, 201); assert.equal(response.headers.get('cache-control'), 'no-store');
    const invite = await response.json(), secret = new URLSearchParams(new URL(invite.url).hash.slice(1)).get('session');
    assert.equal(new URL(invite.url).origin, agentBase);
    assert.ok(!JSON.stringify(invite).includes(cookie.value));
    assert.equal((await call(agentBase, '/api/owner/state', owner)).status, 404);
    assert.equal((await call(ownerBase, '/api/owner/state', secret)).status, 401);
    assert.equal((await call(agentBase, '/api/agent/config', secret)).status, 400);
    assert.equal((await call(agentBase, '/api/agent/requests', secret, { agent: 'Agent', purpose: 'Task' })).status, 400);
    assert.equal((await call(agentBase, '/api/agent/session', owner)).status, 400);
    const state = await (await call(ownerBase, '/api/owner/state', owner)).json();
    assert.equal(state.vault.initialized, false); assert.equal(state.vault.unlocked, false);
    assert.deepEqual(state.requests, []); assert.ok(!JSON.stringify(state).includes(cookie.value)); assert.ok(!JSON.stringify(state).includes(secret));
    assert.equal((await fetch(`${agentBase}/session`)).status, 200);
    const metadata = await (await call(agentBase, '/api/agent/session', secret)).json();
    assert.equal(metadata.status, 'ready'); assert.ok(!JSON.stringify(metadata).includes(cookie.value));
    assert.equal(metadata.importRequirements.requiresHttpOnlySupport, true);
    assert.equal(metadata.importRequirements.httpOnlyCount, 1);
    assert.equal((await fetch(`${agentBase}/api/agent/session/redeem`, { headers: { Authorization: `Bearer ${secret}` } })).status, 404);
    const collected = await Promise.all([1, 2].map(() => call(agentBase, '/api/agent/session/redeem', secret, { agent: 'Fixture agent', purpose: 'Read the fixture' })));
    assert.deepEqual(collected.map(r => r.status).sort(), [200, 400]);
    const bundle = await collected.find(r => r.status === 200).json();
    assert.equal(bundle.format, 'passkey-proxy/cookie-session-v1');
    assert.equal(bundle.storageState.cookies[0].httpOnly, true); assert.equal(bundle.storageState.cookies[0].sameSite, 'Strict');
    assert.equal(bundle.storageState.cookies[0].value, cookie.value);
    const another = await (await call(ownerBase, '/api/extension/session-invites', owner, data)).json();
    const next = new URLSearchParams(new URL(another.url).hash.slice(1)).get('session');
    assert.equal((await call(ownerBase, `/api/owner/session-invites/${another.id}/revoke`, owner, {})).status, 200);
    assert.equal((await call(agentBase, '/api/agent/session/redeem', next, { agent: 'Agent', purpose: 'Task' })).status, 400);
    for (const file of readdirSync(dir)) assert.ok(!readFileSync(join(dir, file), 'utf8').includes(cookie.value), 'Cookies must not persist to disk');
  } finally {
    const done = once(server, 'exit'); server.kill('SIGTERM'); await Promise.race([done, pause(1500)]);
    rmSync(dir, { recursive: true, force: true });
  }
});
