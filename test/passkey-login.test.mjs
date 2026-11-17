import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { Vault } from '../src/vault.mjs';
import { websiteTarget } from '../src/session-handoff.mjs';
import { validateCeremony, loginConfiguration, signLogin } from '../src/passkey-login.mjs';
import { verifyRegistration, verifyAuthentication } from '../src/webauthn.mjs';
import { Handoffs } from '../src/handoffs.mjs';

const challenge = () => randomBytes(32).toString('base64url');
test('explicit sign-in origins stay bound to the saved relying party', () => {
  const credential = { id: 'fixture', rpId: 'example.test', origin: 'https://account.example.test', userName: 'fixture@example.test' };
  assert.equal(websiteTarget(credential, 'https://example.test').authenticationOrigin, credential.origin);
  const target = websiteTarget(credential, 'https://example.test', 'https://login.example.test/signin');
  const ceremony = { origin: 'https://login.example.test', options: { rpId: 'example.test', challenge: challenge() } };
  assert.equal(loginConfiguration(target).loginUrl, 'https://login.example.test/signin');
  assert.equal(validateCeremony(target, ceremony).origin, ceremony.origin);
  assert.throws(() => validateCeremony(target, { ...ceremony, origin: credential.origin }), /configured sign-in origin/);
  assert.throws(() => websiteTarget(credential, 'https://example.test', 'https://unrelated.test'), /Relying-party ID does not match/);
  const earlier = { ...target, loginUrl: credential.origin, authenticationOrigin: credential.origin };
  assert.throws(() => validateCeremony(earlier, ceremony), /configured sign-in origin/);
});

test('agent login signs only the approved credential, origin and challenge after fresh passphrase verification; no cookies are produced', () => {
  const dir = mkdtempSync(join(tmpdir(), 'passkey-sign-test-'));
  try {
    const vault = new Vault(join(dir, 'vault.json'), 'http://localhost:4781');
    const passphrase = 'fixture-only-vault-passphrase', origin = 'https://auth.example.test';
    vault.setup(passphrase);
    const creation = { challenge: challenge(), rp: { id: 'example.test', name: 'Fixture' }, user: { id: 'dXNlcg', name: 'owner@example.test' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], authenticatorSelection: { userVerification: 'discouraged' } };
    const registered = vault.register(creation, origin), publicKey = verifyRegistration(registered, { challenge: creation.challenge, origin, rpID: 'example.test' });
    const target = websiteTarget(vault.status().credentials[0], 'https://app.example.test');
    const ceremony = validateCeremony(target, { origin, options: { challenge: challenge(), rpId: 'example.test', userVerification: 'required' } });
    const request = { target, ceremony };
    assert.throws(() => signLogin(vault, request, undefined), /passphrase/);
    assert.throws(() => signLogin(vault, request, 'wrong-passphrase'));
    const result = signLogin(vault, request, passphrase);
    assert.equal(result.format, 'passkey-proxy/webauthn-v1');
    assert.equal(result.credential.id, target.credentialId);
    assert.equal(result.storageState, undefined);
    for (const key of ['privateKey', 'cookies', 'passphrase', 'ownerToken']) assert.equal(Object.hasOwn(result, key), false);
    const expected = { origin, rpID: 'example.test', challenge: ceremony.options.challenge, userID: creation.user.id };
    assert.equal(verifyAuthentication(result.credential, expected, publicKey), 1);
    assert.equal(Buffer.from(result.credential.response.authenticatorData, 'base64url')[32] & 4, 4);
    assert.throws(() => verifyAuthentication(result.credential, { ...expected, challenge: challenge() }, publicKey));
    assert.throws(() => verifyAuthentication(result.credential, { ...expected, origin: 'https://evil.test' }, publicKey));
    const second = vault.register({ ...creation, challenge: challenge(), user: { ...creation.user, name: 'other@example.test', id: 'b3RoZXI' } }, origin);
    assert.throws(() => validateCeremony(target, { origin, options: { ...ceremony.options, allowCredentials: [{ type: 'public-key', id: second.id }] } }), /selected vault passkey/);
    for (const bad of [
      { origin: 'https://evil.test', options: ceremony.options },
      { origin, options: { ...ceremony.options, rpId: 'other.test' } },
      { origin, options: { ...ceremony.options, challenge: 'short' } },
      { origin, options: { ...ceremony.options, extensions: { remoteDesktopClientOverride: { origin } } } },
    ]) assert.throws(() => validateCeremony(target, bad));
    const targetWithoutAdapter = { rpId: 'example.test', site: 'https://app.example.test' };
    assert.equal(loginConfiguration(targetWithoutAdapter).adapter, 'webauthn-tools');
    assert.equal(loginConfiguration(targetWithoutAdapter).origin, 'https://app.example.test');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('persistent links bind each approval to one challenge and support cancelling an expired website login', () => {
  let now = 1_000_000;
  const h = new Handoffs({ now: () => now }), target = { credentialId: 'selected', rpId: 'example.test', site: 'https://app.example.test' };
  const { secret } = h.createLink(target);
  const ceremony = { origin: 'https://app.example.test', options: { challenge: challenge(), rpId: 'example.test' } };
  const first = h.request(secret, 'Agent', 'Task', ceremony);
  assert.equal(h.request(secret, 'Agent', 'Task', ceremony).accessToken, first.accessToken);
  assert.throws(() => h.request(secret, 'Agent', 'Task', { ...ceremony, options: { ...ceremony.options, challenge: challenge() } }), /different challenge/);
  const exposed = JSON.stringify(h.public(h.byId(first.request.id)));
  assert.ok(!exposed.includes(ceremony.options.challenge)); assert.ok(!exposed.includes('challengeHash'));
  h.cancel(first.accessToken); assert.equal(h.byToken(first.accessToken).status, 'cancelled');
  assert.throws(() => h.redeem(first.accessToken));
  now += 60_001;
  assert.throws(() => h.request(secret, 'Agent', 'Task', ceremony), /already been requested/);
  const second = h.request(secret, 'Agent', 'Task', { ...ceremony, options: { ...ceremony.options, challenge: challenge() } });
  assert.equal(second.request.requestNumber, 2); assert.equal(second.request.status, 'pending');
  now += 120_001;
  assert.throws(() => h.begin(second.request.id));
});
