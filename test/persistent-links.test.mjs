import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Handoffs } from '../src/handoffs.mjs';

const target = { kind: 'browser-session', credentialId: 'fixture-credential', rpId: 'example.test', account: 'owner@example.test', name: 'Fixture website', site: 'https://app.example.test' };

test('persistent links survive restart, bind the account, and require a fresh approval for every session', () => {
  const dir = mkdtempSync(join(tmpdir(), 'passkey-links-test-'));
  const linksFile = join(dir, 'agent-links.json');
  let now = 1_000_000;
  try {
    let h = new Handoffs({ linksFile, now: () => now });
    const selected = structuredClone(target), { secret, link } = h.createLink(selected, 'My agent');
    selected.site = 'https://evil.test';
    assert.equal(h.access(secret).target.site, target.site);
    assert.equal(h.access(secret).reusable, true);
    assert.ok(!JSON.stringify(h.listLinks()).includes('tokenHash'));
    assert.ok(!readFileSync(linksFile, 'utf8').includes(secret));
    assert.equal(statSync(linksFile).mode & 0o777, 0o600);
    const first = h.request(secret, 'Agent', 'First task');
    assert.equal(first.request.requestNumber, 1);
    assert.throws(() => h.redeem(secret));
    assert.throws(() => h.redeem(first.accessToken));
    h.begin(first.request.id); h.ready(first.request.id, { cookie: 'private-fixture-cookie' });
    assert.deepEqual(h.redeem(first.accessToken).bundle, { cookie: 'private-fixture-cookie' });
    assert.throws(() => h.redeem(first.accessToken));
    assert.throws(() => h.request(secret, 'Agent', 'Too soon'), /one minute/);
    now += 60_001;
    const second = h.request(secret, 'Agent', 'Second task');
    assert.equal(second.request.requestNumber, 2);
    assert.notEqual(first.accessToken, second.accessToken);
    assert.equal(second.request.status, 'pending');
    assert.throws(() => h.redeem(second.accessToken));
    const disk = readFileSync(linksFile, 'utf8');
    for (const value of [secret, first.accessToken, second.accessToken, 'private-fixture-cookie']) assert.ok(!disk.includes(value));
    h = new Handoffs({ linksFile, now: () => now });
    assert.throws(() => h.byToken(second.accessToken), /Invalid request token/);
    assert.equal(h.listLinks()[0].requestCount, 2);
    now += 60_001;
    const third = h.request(secret, 'Agent', 'After restart');
    assert.equal(third.request.requestNumber, 3);
    assert.equal(third.request.target.credentialId, target.credentialId);
    h.revokeLink(link.id);
    assert.equal(h.byToken(third.accessToken).status, 'denied');
    h = new Handoffs({ linksFile, now: () => now });
    assert.throws(() => h.request(secret, 'Agent', 'Revoked'), /revoked/);
    assert.throws(() => h.access(secret), /revoked/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('duplicate link submissions resume one request without new approvals or counters; expiry permits renewal', () => {
  let now = 10_000;
  const h = new Handoffs({ now: () => now }), { secret } = h.createLink(target);
  const first = h.request(secret, 'Agent', 'Task');
  for (const status of ['pending', 'authenticating', 'ready', 'failed']) {
    h.requests.get(first.request.id).status = status;
    const resumed = h.request(secret, 'Different name', 'Different task');
    assert.equal(resumed.created, false);
    assert.equal(resumed.accessToken, first.accessToken);
    assert.equal(resumed.request.id, first.request.id);
    assert.equal(resumed.request.agent, 'Agent');
    assert.equal(resumed.request.purpose, 'Task');
    assert.equal(h.listLinks()[0].requestCount, 1);
  }
  now += 600_001;
  const second = h.request(secret, 'Agent', 'After expiry');
  assert.equal(second.created, true); assert.equal(second.request.requestNumber, 2);
  assert.equal(h.byToken(first.accessToken).status, 'expired');
  assert.throws(() => h.redeem(first.accessToken));
  assert.equal(h.requests.size, 2);
});

test('revoking a link invalidates ready and in-flight handoffs and cannot affect other links', () => {
  const h = new Handoffs(), a = h.createLink(target), b = h.createLink(target);
  const ar = h.request(a.secret, 'Agent A', 'Task'), br = h.request(b.secret, 'Agent B', 'Task');
  h.begin(ar.request.id); h.begin(br.request.id);
  h.ready(ar.request.id, { cookie: 'fixture' });
  h.revokeLink(a.link.id);
  assert.throws(() => h.redeem(ar.accessToken));
  assert.equal(h.byToken(ar.accessToken).bundle, undefined);
  assert.equal(h.byToken(br.accessToken).status, 'authenticating');
  h.revokeLink(b.link.id);
  assert.throws(() => h.ready(br.request.id, { cookie: 'late-result' }));
  assert.throws(() => h.begin(br.request.id));
  assert.throws(() => h.request(b.secret, 'Agent B', 'Retry'), /revoked/);
});
