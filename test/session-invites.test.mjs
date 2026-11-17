import test from 'node:test';
import assert from 'node:assert/strict';
import { captureSession, SessionInvites, SESSION_INVITE_TTL } from '../src/session-invites.mjs';
import { validateSessionBundle } from '../src/session-handoff.mjs';

const site = 'https://app.example.test';
const cookie = { name: '__Host-session', value: 'private-cookie-fixture', domain: 'app.example.test', path: '/',
  hostOnly: true, httpOnly: true, secure: true, sameSite: 'lax', session: true };
test('cookie captures preserve attributes and reject unrelated, broadened, partitioned and malformed cookies', () => {
  const raw = [cookie, { ...cookie, name: 'parent', domain: '.example.test', hostOnly: false, sameSite: 'strict', session: false, expirationDate: Date.now() / 1000 + 3600 }, { ...cookie, name: 'unspecified', sameSite: 'unspecified' }];
  const bundle = captureSession(site, raw);
  assert.equal(bundle.format, 'passkey-proxy/cookie-session-v1');
  assert.equal(bundle.storageState.cookies[0].domain, 'app.example.test');
  assert.equal(bundle.storageState.cookies[0].httpOnly, true);
  assert.equal(bundle.storageState.cookies[0].secure, true);
  assert.equal(bundle.storageState.cookies[0].sameSite, 'Lax');
  assert.equal(bundle.storageState.cookies[0].expires, -1);
  assert.equal(bundle.storageState.cookies[1].domain, '.example.test');
  assert.equal(bundle.storageState.cookies[1].expires, raw[1].expirationDate);
  assert.equal(Object.hasOwn(bundle.storageState.cookies[2], 'sameSite'), false);
  assert.deepEqual(validateSessionBundle(bundle).storageState, bundle.storageState);
  for (const invalid of [
    { ...cookie, domain: 'other.example.test' }, { ...cookie, domain: 'example.test' },
    { ...cookie, name: 'wrong', hostOnly: false, domain: '.notexample.test' },
    { ...cookie, hostOnly: false }, { ...cookie, secure: false }, { ...cookie, path: '/other' },
    { ...cookie, partitionKey: { topLevelSite: 'https://example.test' } },
    { ...cookie, session: false, expirationDate: 1 }, { ...cookie, sameSite: 'unexpected' },
    { ...cookie, name: 'suffix', hostOnly: false, domain: '.test' },
    { ...cookie, value: 'line\r\ninjection' }, { ...cookie, hostOnly: undefined },
  ]) assert.throws(() => captureSession(site, [invalid]));
  for (const target of ['file:///tmp', `${site}/private`, `${site}?token=private`, `https://user:password@app.example.test`]) assert.throws(() => captureSession(target, [cookie]));
  assert.throws(() => captureSession(site, [cookie, cookie]));
  assert.throws(() => validateSessionBundle({ ...bundle, storageState: { ...bundle.storageState, origins: [{ origin: 'https://other.test' }] } }));
  assert.throws(() => validateSessionBundle({ ...bundle, site: 'https://other.test' }));
});

test('cookie invites approve one collection, expose only metadata and clear cookies on collection, cancellation and expiry', async () => {
  let now = 1_000_000;
  const invites = new SessionInvites({ now: () => now });
  const { secret, invite } = invites.create(site, [cookie]);
  const metadata = JSON.stringify(invites.list());
  assert.equal(invite.expiresAt - now, SESSION_INVITE_TTL);
  assert.deepEqual(invite.importRequirements, { httpOnlyCount: 1, requiresHttpOnlySupport: true, secureCount: 1, hostOnlyCount: 1, domainCookieCount: 0, persistentCookieCount: 0, sameSiteValues: ['Lax'] });
  assert.ok(!metadata.includes(cookie.value)); assert.ok(!metadata.includes(secret)); assert.ok(!metadata.includes('tokenHash'));
  assert.throws(() => invites.redeem(secret, '', 'Task'));
  assert.equal(invites.byToken(secret).status, 'ready');
  const attempts = await Promise.allSettled([1, 2].map(() => Promise.resolve().then(() => invites.redeem(secret, 'Agent', 'Task'))));
  assert.equal(attempts.filter(r => r.status === 'fulfilled').length, 1);
  assert.equal(invites.byToken(secret).bundle, undefined);
  const cancelled = invites.create(site, [cookie]); invites.revoke(cancelled.invite.id);
  assert.throws(() => invites.redeem(cancelled.secret, 'Agent', 'Task'));
  assert.equal(invites.byToken(cancelled.secret).bundle, undefined);
  const expired = invites.create(site, [cookie]); now += SESSION_INVITE_TTL;
  assert.throws(() => invites.redeem(expired.secret, 'Agent', 'Task'));
  assert.equal(invites.byToken(expired.secret).bundle, undefined);
  assert.equal(new SessionInvites().list().length, 0, 'Restart cannot restore captured cookies');
});

test('script-readable cookie invites do not advertise an unnecessary HttpOnly import requirement', () => {
  const invites = new SessionInvites();
  const { invite, secret } = invites.create(site, [{ ...cookie, name: 'visible_session', httpOnly: false }]);
  assert.equal(invite.importRequirements.requiresHttpOnlySupport, false);
  assert.equal(invite.importRequirements.httpOnlyCount, 0);
  const metadata = JSON.stringify(invites.public(invites.byToken(secret)));
  assert.ok(!metadata.includes(cookie.value)); assert.ok(!metadata.includes('visible_session'));
  assert.equal(invites.byToken(secret).status, 'ready', 'Checking requirements must not consume the invite');
});
