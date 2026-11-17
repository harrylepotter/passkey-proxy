import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { verifyRegistration, verifyAuthentication } from '../src/webauthn.mjs';

const pause = ms => new Promise(r => setTimeout(r, ms));
async function freePort() {
  const server = http.createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const { port } = server.address(); await new Promise(r => server.close(r)); return port;
}
const random = () => randomBytes(32).toString('base64url');
const cookieJar = () => {
  const cookies = new Map();
  return async (url, data) => {
    const response = await fetch(url, { method: data === undefined ? 'GET' : 'POST', headers: { Cookie: [...cookies].map(([k,v]) => `${k}=${v}`).join('; '), ...(data === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
    for (const header of response.headers.getSetCookie()) { const pair = header.split(';')[0], eq = pair.indexOf('='); cookies.set(pair.slice(0, eq), pair.slice(eq + 1)); }
    return response;
  };
};

test('HTTP-only agent login: fresh website challenge, owner approval, vault signature, and session issued directly to the requesting client', { timeout: 30_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'passkey-http-test-'));
  const [gatewayPort, demoPort, agentPort] = await Promise.all([freePort(), freePort(), freePort()]);
  const base = `http://127.0.0.1:${gatewayPort}`, agentBase = `http://127.0.0.1:${agentPort}`;
  let server, website, output = '';
  try {
    server = spawn(process.execPath, ['src/server.mjs'], { env: { ...process.env, DATA_DIR: dir, GATEWAY_PORT: String(gatewayPort), DEMO_PORT: String(demoPort), AGENT_PORT: String(agentPort), CHROME_PATH: '/does-not-exist', OWNER_BROWSER_ENDPOINT: 'http://127.0.0.1:1' }, stdio: ['ignore', 'pipe', 'pipe'] });
    server.stdout.on('data', b => { output += b; }); server.stderr.on('data', b => { output += b; });
    for (let i = 0; i < 60; i++) {
      if (server.exitCode !== null) throw new Error(`Gateway failed to start: ${output}`);
      try { if ((await fetch(`${base}/health`)).ok) break; } catch {}
      await pause(50);
    }
    const owner = readFileSync(join(dir, 'owner-token'), 'utf8').trim(), passphrase = 'http-fixture-vault-passphrase';
    const api = (path, token, data, agent = false) => fetch(`${agent ? agentBase : base}${path}`, { method: data === undefined ? 'GET' : 'POST', headers: { Authorization: `Bearer ${token}`, ...(data === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
    for (const origin of [base, agentBase]) {
      const instructions = await fetch(`${origin}/instructions`);
      assert.equal(instructions.status, 200);
      assert.match(await instructions.text(), /\/session-instructions/);
    }
    assert.equal((await api('/api/owner/vault/setup', owner, { passphrase })).status, 200);
    const origin = 'https://login.example.test', rpId = 'example.test', userId = 'dXNlcg';
    const options = { challenge: random(), rp: { id: rpId, name: 'HTTP fixture' }, user: { id: userId, name: 'owner@example.test' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], authenticatorSelection: { userVerification: 'discouraged' } };
    const registration = await (await api('/api/extension/credential', owner, { operation: 'create', origin, options })).json();
    const credential = verifyRegistration(registration, { origin, rpID: rpId, challenge: options.challenge });
    const challenges = new Map(), sessions = new Set();
    // A separate relying party: cookies and challenge state belong to the agent's
    // HTTP client. The gateway never fetches this website or imports its cookies.
    website = http.createServer(async (req, res) => {
      const respond = (status, value) => { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); };
      const cookies = Object.fromEntries((req.headers.cookie || '').split('; ').filter(Boolean).map(x => x.split('=')));
      if (req.url === '/options') {
        const context = random(), challenge = random(); challenges.set(context, challenge);
        res.setHeader('Set-Cookie', `challenge_context=${context}; Path=/; HttpOnly; SameSite=Lax`);
        return respond(200, { challenge, rpId, allowCredentials: [{ id: credential.id, type: 'public-key' }], userVerification: 'required' });
      }
      if (req.url === '/verify' && req.method === 'POST') {
        let raw = ''; for await (const data of req) raw += data;
        const challenge = challenges.get(cookies.challenge_context);
        if (!challenge) return respond(401, { error: 'Missing original challenge context' });
        try {
          credential.counter = verifyAuthentication(JSON.parse(raw).credential, { origin, rpID: rpId, userID: userId, challenge }, credential);
          challenges.delete(cookies.challenge_context);
          const session = random(); sessions.add(session);
          res.setHeader('Set-Cookie', `site_session=${session}; Path=/; HttpOnly; SameSite=Lax`);
          return respond(200, { ok: true });
        } catch { return respond(401, { error: 'Invalid passkey assertion' }); }
      }
      return respond(sessions.has(cookies.site_session) ? 200 : 401, { authenticated: sessions.has(cookies.site_session) });
    });
    website.listen(0, '127.0.0.1'); await once(website, 'listening');
    const site = `http://127.0.0.1:${website.address().port}`;
    const agent = cookieJar(), differentClient = cookieJar();
    assert.equal((await agent(`${site}/me`)).status, 401);
    const challengeOptions = await (await agent(`${site}/options`)).json();
    const invitation = await (await api('/api/owner/invites', owner, { credentialId: credential.id, site: 'https://app.example.test', reusable: true, localPreview: true })).json();
    const link = new URLSearchParams(new URL(invitation.url).hash.slice(1)).get('link');
    assert.ok(link);
    assert.equal((await (await api('/api/agent/config', link, undefined, true)).json()).login.origin, origin);
    assert.equal((await api('/api/agent/requests', link, { agent: 'Agent', purpose: 'Legacy cookie export' }, true)).status, 400);
    const ceremony = { origin, options: challengeOptions }, requestBody = { agent: 'HTTP agent', purpose: 'Sign in with my vault passkey', ceremony };
    const result = await (await api('/api/agent/requests', link, requestBody, true)).json();
    const requestId = result.request.id, token = result.accessToken;
    assert.ok(requestId); assert.equal(result.request.status, 'pending');
    assert.equal((await (await api('/api/agent/requests', link, requestBody, true)).json()).accessToken, token);
    assert.equal((await api('/api/agent/requests', link, { ...requestBody, ceremony: { origin, options: { ...challengeOptions, challenge: random() } } }, true)).status, 400);
    assert.equal((await api('/api/agent/redeem', token, {}, true)).status, 400);
    assert.equal((await api(`/api/owner/requests/${requestId}/approve`, token, { passphrase })).status, 401);
    assert.equal((await api(`/api/owner/requests/${requestId}/approve`, owner, { confirmSession: true, userVerified: true })).status, 400);
    await pause(800);
    assert.equal((await api(`/api/owner/requests/${requestId}/approve`, owner, { passphrase })).status, 200);
    const bundle = await (await api('/api/agent/redeem', token, {}, true)).json();
    assert.equal(bundle.format, 'passkey-proxy/webauthn-v1'); assert.equal(bundle.storageState, undefined);
    assert.equal(bundle.credential.id, credential.id);
    const clientData = JSON.parse(Buffer.from(bundle.credential.response.clientDataJSON, 'base64url'));
    assert.equal(clientData.challenge, challengeOptions.challenge); assert.equal(clientData.origin, origin);
    assert.equal((await differentClient(`${site}/verify`, { credential: bundle.credential })).status, 401, 'The assertion must not establish a session without its original challenge context');
    assert.equal((await agent(`${site}/me`)).status, 401, 'Approval itself must not authenticate the agent');
    assert.equal((await agent(`${site}/verify`, { credential: bundle.credential })).status, 200);
    assert.equal((await agent(`${site}/me`)).status, 200);
    assert.equal((await differentClient(`${site}/me`)).status, 401);
    assert.equal((await agent(`${site}/verify`, { credential: bundle.credential })).status, 401, 'The website must reject challenge replay');
    assert.equal((await api('/api/agent/redeem', token, {}, true)).status, 400);
    assert.equal((await api('/api/owner/state', owner, undefined, true)).status, 404);
    const state = await (await api('/api/owner/state', owner)).json();
    assert.ok(!JSON.stringify(state).includes(challengeOptions.challenge));
    assert.ok(!JSON.stringify(state).includes(bundle.credential.response.signature));
    const persisted = readFileSync(join(dir, 'agent-links.json'), 'utf8');
    assert.ok(!persisted.includes(link)); assert.ok(!persisted.includes(token));
    const second = await (await api('/api/owner/invites', owner, { credentialId: credential.id, site: 'https://app.example.test', reusable: true, localPreview: true })).json();
    const secondLink = new URLSearchParams(new URL(second.url).hash.slice(1)).get('link');
    const fresh = await (await agent(`${site}/options`)).json();
    const secondRequest = await (await api('/api/agent/requests', secondLink, { ...requestBody, ceremony: { origin, options: fresh } }, true)).json();
    assert.equal((await api('/api/agent/cancel', secondRequest.accessToken, {}, true)).status, 200);
    assert.equal((await api('/api/agent/redeem', secondRequest.accessToken, {}, true)).status, 400);
  } finally {
    if (website) { website.closeAllConnections(); await new Promise(r => website.close(r)); }
    if (server && server.exitCode === null) { const exited = once(server, 'exit'); server.kill('SIGTERM'); await Promise.race([exited, pause(2000)]); }
    rmSync(dir, { recursive: true, force: true });
  }
});
