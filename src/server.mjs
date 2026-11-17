import http from 'node:http';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { timingSafeEqual } from 'node:crypto';
import { Vault, saveJSON, validateScope } from './vault.mjs';
import { Handoffs, token, digest } from './handoffs.mjs';
import { verifyRegistration, verifyAuthentication } from './webauthn.mjs';
import { websiteTarget, defaultLoginUrls } from './session-handoff.mjs';
import { loginConfiguration, validateCeremony, signLogin } from './passkey-login.mjs';
import { SessionInvites, SESSION_INVITE_TTL, sessionSite } from './session-invites.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const dataDir = resolve(process.env.DATA_DIR || join(root, '.data'));
const gatewayPort = Number(process.env.GATEWAY_PORT || 4780), demoPort = Number(process.env.DEMO_PORT || 4781);
const gatewayOrigin = `http://127.0.0.1:${gatewayPort}`, demoOrigin = `http://localhost:${demoPort}`;
const agentPort = Number(process.env.AGENT_PORT || 4782), agentLocalOrigin = `http://127.0.0.1:${agentPort}`;
// Persist the owner-configured agent origin so a running tunnel keeps working
// across gateway restarts. This does not start or expose a tunnel by itself.
const agentOriginFile = join(dataDir, 'agent-origin.json');
let publicAgentOrigin = existsSync(agentOriginFile) ? JSON.parse(readFileSync(agentOriginFile, 'utf8')).origin || '' : '';
mkdirSync(dataDir, { recursive: true, mode: 0o700 });
const ownerFile = join(dataDir, 'owner-token');
if (!existsSync(ownerFile)) writeFileSync(ownerFile, token(), { mode: 0o600 });
const ownerToken = readFileSync(ownerFile, 'utf8').trim();
writeFileSync(join(dataDir, 'owner-url.txt'), `${gatewayOrigin}/#owner=${ownerToken}\n`, { mode: 0o600 });
const vault = new Vault(join(dataDir, 'vault.json'), demoOrigin), handoffs = new Handoffs({ linksFile: join(dataDir, 'agent-links.json') });
const sessionInvites = new SessionInvites();
const siteFile = join(dataDir, 'site.json');
const site = existsSync(siteFile) ? JSON.parse(readFileSync(siteFile, 'utf8')) : { credentials: [] };
const userID = Buffer.from('passkey-proxy-demo-user').toString('base64url');
const enrollments = new Map(), ceremonies = new Map(), sessions = new Map(), audit = [];
let unlockDeadline = 0, nextUnlock = 0, nextVerification = 0;
const record = (event, detail = '') => { audit.unshift({ at: Date.now(), event, detail }); audit.splice(80); };
const auth = req => /^Bearer ([A-Za-z0-9_-]+)$/.exec(req.headers.authorization || '')?.[1] || '';
const equals = (a, b) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const fail = (message, status = 400) => { const error = new Error(message); error.status = status; throw error; };
function owner(req) { if (!equals(auth(req), ownerToken)) fail('Owner access required. Open the private owner link created by npm start.', 401); }
function headers(res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
}
function json(res, value, status = 200) { res.writeHead(status, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(value)); }
async function body(req, limit = 65536) {
  if (!req.headers['content-type']?.startsWith('application/json')) fail('Use application/json.', 415);
  let raw = '';
  for await (const chunk of req) { raw += chunk; if (Buffer.byteLength(raw) > limit) fail('Request too large.', 413); }
  try { return JSON.parse(raw || '{}'); } catch { fail('Invalid JSON.'); }
}
function staticFile(res, file, contentType) { res.writeHead(200, { 'Content-Type': contentType }); res.end(readFileSync(join(root, file))); }
function takeCeremony(id, kind) {
  const c = ceremonies.get(id); ceremonies.delete(id);
  if (!c || c.kind !== kind || c.expiresAt < Date.now()) fail('The authentication challenge expired or was already used.');
  return c;
}
function ceremony(kind) {
  const id = token(), challenge = token();
  ceremonies.set(id, { kind, challenge, expiresAt: Date.now() + 60_000 });
  return { ceremonyId: id, challenge };
}
function enrollment(req) {
  const e = enrollments.get(digest(auth(req)));
  if (!e || e.expiresAt <= Date.now()) fail('Open a fresh registration link from the owner dashboard.', 401);
  return e;
}
function issueSession(res) {
  const secret = token(), expiresAt = Date.now() + 15 * 60_000;
  sessions.set(digest(secret), { expiresAt });
  res.setHeader('Set-Cookie', `demo_travel_session=${secret}; Path=/; HttpOnly; SameSite=Lax; Max-Age=900`);
}
function currentSession(req) {
  const cookie = /(?:^|;\s*)demo_travel_session=([A-Za-z0-9_-]+)/.exec(req.headers.cookie || '')?.[1];
  const s = sessions.get(digest(cookie)); return s?.expiresAt > Date.now() ? s : null;
}
function requestOrigin(req, expected) {
  const origin = req.headers.origin;
  if (origin && origin !== expected && !/^chrome-extension:\/\/[a-p]{32}$/.test(origin)) fail('Origin not allowed.', 403);
}
function wrap(expected, handler, extraHosts = []) {
  return async (req, res) => {
    headers(res);
    try {
      const origin = typeof expected === 'function' ? expected() : expected;
      if (req.headers.host !== new URL(origin).host && !extraHosts.includes(req.headers.host)) fail('Unexpected host.', 421);
      requestOrigin(req, origin);
      const path = new URL(req.url, origin).pathname;
      if (path === '/favicon.ico') { res.writeHead(204); return res.end(); }
      if (path === '/styles.css' && req.method === 'GET') return staticFile(res, 'public/styles.css', 'text/css');
      await handler(req, res, path);
    } catch (error) {
      if (!res.headersSent) json(res, { error: error.message }, error.status || 400);
      else res.end();
    }
  };
}

const demoTarget = () => ({ kind: 'demo', name: 'Demo Travel', account: 'user@example.test', site: demoOrigin, rpId: 'localhost', credentialId: site.credentials[0]?.id, authenticationOrigin: demoOrigin });
const targetFor = target => target?.kind === 'demo' || !target ? { ...demoTarget(), ...target, credentialId: target?.credentialId || demoTarget().credentialId } : target;
async function agentRoute(req, res, path) {
  if (req.method === 'GET') {
    if (path === '/session') return staticFile(res, 'public/session.html', 'text/html');
    if (path === '/session.js') return staticFile(res, 'public/session.js', 'text/javascript');
    if (path === '/session-instructions') return staticFile(res, 'public/session-instructions.txt', 'text/plain');
    if (path === '/api/agent/session') return json(res, sessionInvites.public(sessionInvites.byToken(auth(req))));
    if (path === '/' || path === '/agent') return staticFile(res, 'public/agent.html', 'text/html');
    if (path === '/agent.js') return staticFile(res, 'public/agent.js', 'text/javascript');
    if (path === '/instructions') return staticFile(res, 'public/instructions.txt', 'text/plain');
    if (path === '/health') return json(res, { ok: true, service: 'agent-handoff' });
    if (path === '/api/agent/config') {
      const access = handoffs.access(auth(req));
      const target = targetFor(access.target);
      return json(res, { ...target, login: loginConfiguration(target), handoff: 'webauthn', reusable: access.reusable, ...(access.expiresAt ? { invitationExpiresAt: access.expiresAt } : {}) });
    }
    if (path === '/api/agent/request') return json(res, handoffs.public(handoffs.byToken(auth(req))));
  }
  if (req.method === 'POST' && path === '/api/agent/session/redeem') {
    const data = await body(req);
    const result = sessionInvites.redeem(auth(req), data.agent, data.purpose);
    record('Cookie session collected', `${new URL(result.invite.site).hostname} · ${result.invite.agent} · one-time invite consumed`);
    return json(res, result.bundle);
  }
  if (req.method === 'POST' && path === '/api/agent/requests') {
    const data = await body(req);
    const target = targetFor(handoffs.access(auth(req)).target);
    const ceremony = validateCeremony(target, data.ceremony);
    const result = handoffs.request(auth(req), data.agent, data.purpose, ceremony);
    handoffs.byId(result.request.id).target = target;
    if (result.created) {
      record('Access requested', `${result.request.agent} · ${result.request.target?.name || 'Demo Travel'} · ${result.request.requestNumber ? `request #${result.request.requestNumber} · ` : ''}${result.request.purpose}`);
    }
    return json(res, result, result.created ? 201 : 200);
  }
  if (req.method === 'POST' && path === '/api/agent/redeem') {
    await body(req);
    const result = handoffs.redeem(auth(req)); record('Passkey response collected', `${result.request.agent} · ${result.request.target?.name || 'Demo Travel'} · handoff consumed`);
    return json(res, result.bundle);
  }
  if (req.method === 'POST' && path === '/api/agent/cancel') {
    await body(req); const request = handoffs.cancel(auth(req)); record('Request cancelled by agent', request.target?.name || 'Website'); return json(res, request);
  }
  fail('Not found.', 404);
}

const gateway = http.createServer(wrap(gatewayOrigin, async (req, res, path) => {
  if (path.startsWith('/api/agent/')) return agentRoute(req, res, path);
  if (['/session', '/session.js', '/session-instructions'].includes(path)) return agentRoute(req, res, path);
  if (req.method === 'GET') {
    if (path === '/') return staticFile(res, 'public/index.html', 'text/html');
    if (path === '/agent') return staticFile(res, 'public/agent.html', 'text/html');
    if (path === '/app.js') return staticFile(res, 'public/app.js', 'text/javascript');
    if (path === '/agent.js') return staticFile(res, 'public/agent.js', 'text/javascript');
    if (path === '/health') return json(res, { ok: true });
    if (path === '/instructions') return staticFile(res, 'public/instructions.txt', 'text/plain');
    if (path === '/api/owner/state') {
      owner(req);
      return json(res, { vault: vault.status(), loginDefaults: defaultLoginUrls, demo: { origin: demoOrigin, registered: site.credentials.length > 0, account: 'user@example.test' },
        agentAccess: { localOrigin: agentLocalOrigin, publicOrigin: publicAgentOrigin || null }, links: handoffs.listLinks(),
        requests: [...handoffs.requests.values()].reverse().map(r => handoffs.public(r)), audit, unlockDeadline,
        sessionSharing: { version: 1, inviteLifetimeMs: SESSION_INVITE_TTL }, sessionInvites: sessionInvites.list() });
    }
  }
  if (req.method !== 'POST') fail('Not found.', 404);
  if (path.startsWith('/api/owner/') || path.startsWith('/api/extension/')) owner(req);
  const data = await body(req, path === '/api/extension/session-invites' ? 524288 : 65536);
  if (path === '/api/extension/session-invites') {
    const site = sessionSite(data.site);
    if ([gatewayOrigin, agentLocalOrigin, publicAgentOrigin].includes(site)) fail('Open the website you want to share, not the gateway.');
    if (!publicAgentOrigin && data.localPreview !== true) fail('Start remote sharing or configure the public agent gateway URL in the dashboard first.');
    const { secret, invite } = sessionInvites.create(site, data.cookies);
    const remote = data.localPreview !== true;
    record('Cookie session invite created', `${new URL(site).hostname} · ${invite.cookieCount} cookies · one collection · 10 minutes`);
    return json(res, { ...invite, remote, url: `${remote ? publicAgentOrigin : agentLocalOrigin}/session#session=${secret}` }, 201);
  }
  const sessionRevoke = /^\/api\/owner\/session-invites\/([a-f0-9]{24})\/revoke$/.exec(path);
  if (sessionRevoke) {
    const invite = sessionInvites.revoke(sessionRevoke[1]);
    record('Cookie session invite revoked', new URL(invite.site).hostname);
    return json(res, invite);
  }
  const revoke = /^\/api\/owner\/links\/([a-f0-9]{24})\/revoke$/.exec(path);
  if (revoke) { const link = handoffs.revokeLink(revoke[1]); record('Agent link revoked', link.label); return json(res, link); }
  if (path === '/api/owner/vault/setup' || path === '/api/owner/vault/unlock') {
    if (Date.now() < nextUnlock) fail('Wait a moment before trying again.', 429);
    nextUnlock = Date.now() + 1000;
    path.endsWith('/setup') ? vault.setup(data.passphrase) : vault.unlock(data.passphrase);
    unlockDeadline = Date.now() + 15 * 60_000; record('Vault unlocked', 'Automatically locks after 15 minutes.');
    return json(res, { ok: true });
  }
  if (path === '/api/owner/vault/lock') { vault.lock(); unlockDeadline = 0; record('Vault locked'); return json(res, { ok: true }); }
  if (path === '/api/owner/agent-origin') {
    let nextOrigin = '';
    if (data.origin) {
      const url = new URL(data.origin);
      if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash || ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) fail('Enter the public HTTPS origin of the agent-only tunnel.');
      nextOrigin = url.origin;
    }
    saveJSON(agentOriginFile, { origin: nextOrigin }); publicAgentOrigin = nextOrigin;
    record(publicAgentOrigin ? 'Remote agent URL configured' : 'Remote agent URL cleared');
    return json(res, { publicOrigin: publicAgentOrigin || null });
  }
  if (path === '/api/owner/enrollment') {
    if (!vault.status().unlocked) fail('Unlock the vault first.');
    const secret = token(); enrollments.set(digest(secret), { expiresAt: Date.now() + 5 * 60_000 });
    return json(res, { url: `${demoOrigin}/#enroll=${secret}` });
  }
  if (path === '/api/extension/credential') {
    if (!['create', 'get'].includes(data.operation)) fail('Unsupported operation.');
    validateScope(data.origin, (data.operation === 'create' ? data.options?.rp?.id : data.options?.rpId) || new URL(data.origin).hostname);
    let userVerified = false;
    if (typeof data.passphrase === 'string' && data.passphrase.length) {
      if (Date.now() < nextVerification) fail('Wait a moment before verifying again.', 429);
      nextVerification = Date.now() + 750;
      userVerified = vault.verifyUser(data.passphrase);
      unlockDeadline = Date.now() + 15 * 60_000;
    }
    // Never accept a userVerified flag from the caller. UV follows only a fresh
    // passphrase verification originating in the extension's trusted approval UI.
    const verification = { userVerified, credentialId: data.credentialId };
    const response = data.operation === 'create' ? vault.register(data.options, data.origin, verification) : vault.authenticate(data.options, data.origin, verification);
    record(data.operation === 'create' ? 'Passkey created' : 'Passkey used', `${new URL(data.origin).hostname} · ${userVerified ? 'passphrase verified' : 'approved in extension'}`);
    return json(res, response);
  }
  if (path === '/api/owner/invites') {
    let target = demoTarget();
    if (data.credentialId && data.credentialId !== 'demo') {
      if (!vault.status().unlocked) fail('Unlock the vault to select a website account.');
      const credential = vault.status().credentials.find(c => c.id === data.credentialId);
      target = websiteTarget(credential, data.site || credential?.origin, data.loginUrl);
    } else if (!site.credentials.length) fail('Register a passkey or choose an existing website account.');
    if (target.kind !== 'demo' && !publicAgentOrigin && data.localPreview !== true) fail('Remote sharing is not enabled yet. Configure the agent gateway HTTPS URL, or select Local preview to test on this machine.');
    const remote = target.kind !== 'demo' && data.localPreview !== true;
    const origin = remote ? publicAgentOrigin : target.kind === 'demo' ? gatewayOrigin : agentLocalOrigin;
    if (data.reusable === true) {
      if (!vault.status().unlocked) fail('Unlock the vault to create an agent link.');
      const { secret, link } = handoffs.createLink(target, data.label);
      record('Persistent agent link created', `${target.name} · ${link.label} · approval required for every request`);
      return json(res, { url: `${origin}/agent#link=${secret}`, target, remote, reusable: true, link });
    }
    const invite = handoffs.invite(target); record('Agent invitation created', `${target.name} · ${remote ? 'remote agent' : 'local preview'} · one request · one hour`);
    return json(res, { url: `${origin}/agent#invite=${invite}`, target, remote, reusable: false });
  }
  const action = /^\/api\/owner\/requests\/([a-f0-9]{24})\/(approve|deny)$/.exec(path);
  if (action) {
    const [, id, operation] = action;
    if (operation === 'deny') { handoffs.deny(id); record('Access denied', handoffs.byId(id).agent); return json(res, { ok: true }); }
    if (!vault.status().unlocked) fail('Unlock the vault before approving access.');
    if ([...handoffs.requests.values()].some(r => r.status === 'authenticating')) fail('Another sign-in is running. Try again in a moment.');
    const selected = handoffs.byId(id);
    if (!selected.ceremony) fail('This request has no website challenge. The agent must start a fresh passkey login.');
    if (!vault.status().credentials.some(c => c.id === selected.target.credentialId && c.rpId === selected.target.rpId)) fail('The selected passkey is no longer in this vault.');
    if (Date.now() < nextVerification) fail('Wait a moment before verifying again.', 429);
    nextVerification = Date.now() + 750;
    const request = handoffs.begin(id); record('Access approved', `${request.agent} · ${request.target?.name || 'Demo Travel'}`);
    try {
      const bundle = signLogin(vault, request, data.passphrase);
      handoffs.ready(id, bundle); record('Passkey challenge signed', `${request.target.rpId} · ${request.target.account} · single-use response`);
      return json(res, handoffs.public(request));
    } catch (error) {
      if (request.status === 'authenticating') { request.status = 'failed'; request.error = 'Could not sign this challenge. Check your vault passphrase and the selected passkey. If the website challenge expired, the agent must request a fresh one.'; }
      record('Sign-in failed', request.error || 'Request expired');
      // Browser errors can include page content; keep them out of agent responses and logs.
      fail(request.error || 'The request expired during sign-in.');
    }
  }
  fail('Not found.', 404);
}));

// This listener exposes only agent pages and invitation/request/redeem routes.
// It has no owner, vault, signing, browser-debugging or configuration endpoints.
const agentGateway = http.createServer(wrap(() => publicAgentOrigin || agentLocalOrigin, agentRoute, [new URL(agentLocalOrigin).host]));

const demo = http.createServer(wrap(demoOrigin, async (req, res, path) => {
  if (req.method === 'GET') {
    if (path === '/') return staticFile(res, 'public/demo.html', 'text/html');
    if (path === '/demo.js') return staticFile(res, 'public/demo.js', 'text/javascript');
    if (path === '/api/config') return json(res, { registered: site.credentials.length > 0 });
    if (path === '/api/me') {
      const session = currentSession(req); if (!session) fail('Sign in to see your trips.', 401);
      return json(res, { name: 'Demo User', email: 'user@example.test', expiresAt: session.expiresAt, trips: [
        { destination: 'Tokyo, Japan', dates: '18–24 December 2026', reference: 'DEMO-2048', status: 'Confirmed' },
        { destination: 'Hobart, Australia', dates: '8–11 January 2027', reference: 'DEMO-4096', status: 'Confirmed' },
      ] });
    }
  }
  if (req.method !== 'POST') fail('Not found.', 404);
  const data = await body(req);
  if (path === '/api/register/options') {
    enrollment(req);
    const { ceremonyId, challenge } = ceremony('create'); ceremonies.get(ceremonyId).enrollment = digest(auth(req));
    return json(res, { ceremonyId, publicKey: { challenge, rp: { id: 'localhost', name: 'Demo Travel' },
      user: { id: userID, name: 'user@example.test', displayName: 'Demo User' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      timeout: 60000, attestation: 'none', authenticatorSelection: { residentKey: 'required', userVerification: 'discouraged' },
      excludeCredentials: site.credentials.map(c => ({ id: c.id, type: 'public-key' })), extensions: { credProps: true } } });
  }
  if (path === '/api/register/verify') {
    enrollment(req); const c = takeCeremony(data.ceremonyId, 'create');
    if (c.enrollment !== digest(auth(req))) fail('Registration request mismatch.');
    const credential = verifyRegistration(data.credential, { ...c, origin: demoOrigin, rpID: 'localhost' });
    if (site.credentials.some(key => key.id === credential.id)) fail('Credential already registered.');
    site.credentials.push(credential); saveJSON(siteFile, site); enrollments.delete(digest(auth(req)));
    issueSession(res); record('Passkey registered', 'Demo Travel verified the public key.'); return json(res, { ok: true });
  }
  if (path === '/api/auth/options') {
    if (!site.credentials.length) fail('Register a passkey first.');
    const { ceremonyId, challenge } = ceremony('get');
    return json(res, { ceremonyId, publicKey: { challenge, rpId: 'localhost', timeout: 60000, userVerification: 'discouraged',
      allowCredentials: site.credentials.map(c => ({ id: c.id, type: 'public-key' })) } });
  }
  if (path === '/api/auth/verify') {
    const c = takeCeremony(data.ceremonyId, 'get'), credential = site.credentials.find(c => c.id === data.credential?.id);
    if (!credential) fail('Unknown credential.');
    credential.counter = verifyAuthentication(data.credential, { ...c, origin: demoOrigin, rpID: 'localhost', userID }, credential);
    saveJSON(siteFile, site); issueSession(res); return json(res, { ok: true });
  }
  if (path === '/api/logout') {
    const cookie = /(?:^|;\s*)demo_travel_session=([A-Za-z0-9_-]+)/.exec(req.headers.cookie || '')?.[1];
    sessions.delete(digest(cookie)); res.setHeader('Set-Cookie', 'demo_travel_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
    return json(res, { ok: true });
  }
  fail('Not found.', 404);
}));

const cleaner = setInterval(() => {
  if (unlockDeadline && Date.now() >= unlockDeadline) { vault.lock(); unlockDeadline = 0; record('Vault locked', 'Unlock window expired.'); }
  for (const map of [sessions, ceremonies, enrollments]) for (const [key, value] of map) if (value.expiresAt < Date.now()) map.delete(key);
  for (const r of handoffs.requests.values()) handoffs.expire(r);
  handoffs.prune();
  sessionInvites.prune();
}, 1000).unref();
for (const server of [gateway, demo, agentGateway]) server.on('error', error => { console.error(error.message); process.exit(1); });
let readyServers = 0;
function ready() {
  if (++readyServers === 3 && process.argv.includes('--debug-browser')) {
    import('../scripts/open.mjs').catch(error => console.error(`Chrome startup failed: ${error.message.split('\n')[0]}`));
  }
}
gateway.listen(gatewayPort, '127.0.0.1', () => { console.log(`Gateway: ${gatewayOrigin}\nPrivate owner link: ${join(dataDir, 'owner-url.txt')}`); ready(); });
demo.listen(demoPort, '127.0.0.1', () => { console.log(`Demo site: ${demoOrigin}`); ready(); });
agentGateway.listen(agentPort, '127.0.0.1', () => { console.log(`Agent-only endpoint: ${agentLocalOrigin}`); ready(); });
function stop() { clearInterval(cleaner); vault.lock(); gateway.close(); demo.close(); agentGateway.close(); setTimeout(() => process.exit(), 1000).unref(); }
process.on('SIGINT', stop); process.on('SIGTERM', stop);
