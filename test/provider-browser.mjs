import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

export async function checkProviderSwitch({ ownerContext, owner, api, ownerToken, observe }) {
  const worker = ownerContext.serviceWorkers().find(w => w.url().startsWith('chrome-extension:'));
  const extensionOrigin = `chrome-extension://${new URL(worker.url()).host}`;
  let menu = await ownerContext.newPage(); observe(menu); await menu.goto(`${extensionOrigin}/popup.html`);
  await menu.getByText('Vault passkeys active · unlocked', { exact: true }).waitFor();
  const before = (await (await api('/api/owner/state', ownerToken)).json()).vault.credentials.length;
  // Invalid pairing simulates an unavailable vault service. OS selection must
  // still work without a passphrase or a successful gateway request.
  await menu.evaluate(() => chrome.storage.local.set({ ownerToken: 'x'.repeat(43) }));
  await menu.reload();
  assert.equal(await menu.getByRole('button', { name: 'Use OS passkeys', exact: true }).isEnabled(), true);
  const fixture = await ownerContext.newPage(); observe(fixture);
  await fixture.route('**/*', route => route.fulfill({ contentType: 'text/html', body: '<!doctype html><h1>Provider choice fixture</h1>' }));
  await fixture.goto('http://os-choice.localhost');
  const challenge = () => randomBytes(32).toString('base64url');
  const options = { challenge: challenge(), rp: { id: 'os-choice.localhost', name: 'Provider choice test' }, user: { id: 'dGVzdC11c2Vy', name: 'fixture@example.test', displayName: 'Fixture' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }], authenticatorSelection: { residentKey: 'required', userVerification: 'discouraged' }, timeout: 30000 };
  const start = async (operation, options) => {
    await fixture.bringToFront();
    await fixture.evaluate(({ operation, options }) => {
      window.result = null;
      const publicKey = operation === 'create' ? PublicKeyCredential.parseCreationOptionsFromJSON(options) : PublicKeyCredential.parseRequestOptionsFromJSON(options);
      navigator.credentials[operation]({ publicKey }).then(c => { window.result = { native: c instanceof PublicKeyCredential, credential: c.toJSON() }; }, e => { window.result = { name: e.name }; });
    }, { operation, options });
  };
  assert.equal(await fixture.evaluate(() => PublicKeyCredential.isConditionalMediationAvailable()), false, 'Vault proxy should be attached initially');
  const popupPromise = ownerContext.waitForEvent('page');
  await start('create', options);
  const popup = await popupPromise; observe(popup);
  await popup.getByRole('button', { name: 'Use OS passkeys', exact: true }).click();
  await popup.getByRole('heading', { name: 'OS passkeys are on', exact: true }).waitFor();
  await fixture.waitForFunction(() => window.result !== null);
  assert.equal((await fixture.evaluate(() => window.result)).name, 'NotAllowedError');
  await menu.reload(); await menu.getByText('OS passkeys active', { exact: true }).waitFor();
  assert.equal(await menu.evaluate(async () => (await chrome.storage.local.get('proxyEnabled')).proxyEnabled), false);
  assert.equal(await fixture.evaluate(() => PublicKeyCredential.isConditionalMediationAvailable()), true, 'Native mediation must be restored, not just a UI label');
  await popup.getByRole('button', { name: 'Done', exact: true }).click();

  // With the proxy detached, Chrome's own authenticator stores and signs the
  // credential. This is a virtual OS authenticator only in this test profile.
  const cdp = await ownerContext.newCDPSession(fixture);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  const count = ownerContext.pages().length;
  await start('create', { ...options, challenge: challenge() });
  await fixture.waitForFunction(() => window.result !== null);
  const created = await fixture.evaluate(() => window.result);
  assert.equal(created.native, true); assert.equal(ownerContext.pages().length, count);
  const nativeBeforeSign = (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials;
  assert.equal(nativeBeforeSign.length, 1, 'Chrome must store the native credential');
  await start('get', { challenge: challenge(), rpId: 'os-choice.localhost', userVerification: 'discouraged', allowCredentials: [{ type: 'public-key', id: created.credential.id }] });
  await fixture.waitForFunction(() => window.result !== null);
  assert.equal((await fixture.evaluate(() => window.result)).credential.id, created.credential.id);
  const nativeCredentials = (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials;
  assert.equal(nativeCredentials.length, 1, 'Authentication must reuse the native credential'); assert.equal(nativeCredentials[0].signCount, nativeBeforeSign[0].signCount + 1, 'Chrome must sign using its own credential');
  assert.equal((await (await api('/api/owner/state', ownerToken)).json()).vault.credentials.length, before, 'OS credentials must not be copied to the vault');
  await cdp.send('WebAuthn.disable');

  // Reopening the menu and dashboard re-pairing must preserve the choice.
  // The separate startup unit test checks restoration after a worker restart.
  await menu.close();
  menu = await ownerContext.newPage(); observe(menu); await menu.goto(`${extensionOrigin}/popup.html`);
  await menu.getByText('OS passkeys active', { exact: true }).waitFor();
  await owner.reload(); await owner.getByRole('button', { name: 'Connect extension', exact: true }).click();
  await owner.getByText('OS passkeys active', { exact: true }).waitFor();
  await menu.reload(); await menu.getByText('OS passkeys active', { exact: true }).waitFor();
  await menu.getByRole('button', { name: 'Use vault passkeys', exact: true }).click();
  await menu.getByText('Vault passkeys active · unlocked', { exact: true }).waitFor();
  assert.equal(await fixture.evaluate(() => PublicKeyCredential.isConditionalMediationAvailable()), false);

  const getPopupPromise = ownerContext.waitForEvent('page');
  await start('get', { challenge: challenge(), rpId: 'os-choice.localhost', userVerification: 'required', allowCredentials: [{ type: 'public-key', id: created.credential.id }] });
  const getPopup = await getPopupPromise; observe(getPopup);
  await getPopup.getByText('No matching passkey in this vault. Use OS passkeys for a credential stored with another provider.', { exact: true }).waitFor();
  assert.equal(await getPopup.getByRole('button', { name: 'Approve', exact: true }).isEnabled(), false);
  await getPopup.getByRole('button', { name: 'Use OS passkeys', exact: true }).click();
  await getPopup.getByRole('heading', { name: 'OS passkeys are on', exact: true }).waitFor();
  await fixture.waitForFunction(() => window.result !== null); assert.equal((await fixture.evaluate(() => window.result)).name, 'NotAllowedError');
  await getPopup.getByRole('button', { name: 'Done', exact: true }).click();
  await menu.reload(); await menu.getByRole('button', { name: 'Use vault passkeys', exact: true }).click();
  await menu.getByText('Vault passkeys active · unlocked', { exact: true }).waitFor();
  await fixture.close(); await menu.close();
  console.log('PASS OS choice for create/get, native registration/sign-in, unavailable-vault fallback, preference persistence, re-pairing and return to vault');
}
