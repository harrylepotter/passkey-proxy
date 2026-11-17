import assert from 'node:assert/strict';

export async function checkOwnerAccess({ ownerContext, gateway, ownerToken }) {
  const page = await ownerContext.newPage();
  page.setDefaultTimeout(5000);
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  const signIn = async value => {
    await page.locator('#owner-input').fill(value);
    await page.getByRole('button', { name: 'Open workspace', exact: true }).click();
  };
  const checkAuthorized = async () => {
    await page.locator('#workspace').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#owner-login').isVisible(), false);
    assert.equal(await page.locator('#message.error').isVisible(), false);
    assert.equal(await page.evaluate(() => sessionStorage.getItem('owner')), ownerToken);
    assert.equal(new URL(page.url()).hash, '');
  };
  try {
    await page.goto(gateway);
    await signIn('x'.repeat(43));
    await page.getByText('Owner access required.', { exact: false }).waitFor();
    // Pasting the private link over an open dashboard is a same-document
    // navigation. It must replace a stale token and clear the old error.
    await page.goto(`${gateway}/#owner=${ownerToken}`);
    await checkAuthorized();
    await page.reload();
    await checkAuthorized();
    await page.getByRole('link', { name: 'Extension setup' }).click();
    assert.equal(await page.locator('#workspace').isVisible(), true);

    await page.evaluate(() => sessionStorage.clear());
    await page.goto(gateway);
    await page.reload();
    await signIn(`${gateway}/#owner=${ownerToken}`);
    await checkAuthorized();
    assert.equal(await page.locator('#owner-input').inputValue(), '');

    await page.evaluate(() => sessionStorage.clear());
    await page.reload();
    await signIn(`https://unrelated.example/#owner=${ownerToken}`);
    await page.locator('#message.error').waitFor({ state: 'visible' });
    assert.equal(await page.locator('#workspace').isVisible(), false);
    assert.equal(await page.evaluate(() => sessionStorage.getItem('owner')), null);
    await signIn(ownerToken);
    await checkAuthorized();

    // A site can enroll and sign in on different origins within the same RP.
    const stateResponse = await ownerContext.request.get(`${gateway}/api/owner/state`, { headers: { Authorization: `Bearer ${ownerToken}` } });
    const state = await stateResponse.json();
    state.vault = { initialized: true, unlocked: true, credentials: [{ id: 'site-form-fixture', rpId: 'example.test', rpName: 'Example fixture', origin: 'https://account.example.test', userName: 'fixture@example.test' }] };
    let submitted = null;
    await page.route('**/api/owner/state', route => route.fulfill({ json: state }));
    await page.route('**/api/owner/invites', route => {
      submitted = route.request().postDataJSON();
      return route.fulfill({ json: { url: 'https://agent.example.test/agent#link=fixture', target: { name: 'Example fixture', account: 'fixture@example.test', site: 'https://example.test', rpId: 'example.test' }, remote: true, reusable: true } });
    });
    await page.reload();
    await page.getByLabel('Website sign-in page').waitFor();
    assert.equal(await page.getByLabel('Website sign-in page').inputValue(), 'https://account.example.test');
    await page.getByLabel('Website sign-in page').fill('https://login.example.test/signin');
    await page.getByRole('button', { name: 'Create agent link' }).click();
    await page.getByRole('button', { name: 'Copy instructions' }).waitFor();
    assert.equal(submitted.loginUrl, 'https://login.example.test/signin');
    const recipient = { name: 'Example fixture', account: 'fixture@example.test', site: 'https://example.test', rpId: 'example.test', reusable: true,
      login: { origin: 'https://login.example.test', rpId: 'example.test', loginUrl: 'https://login.example.test/signin' } };
    await page.route('**/api/agent/config', route => route.fulfill({ json: recipient }));
    await page.goto(`${gateway}/agent#link=fixture-example`);
    await page.getByRole('heading', { name: 'Example fixture', exact: true }).waitFor();
    assert.equal(await page.locator('#ceremony-origin').inputValue(), 'https://login.example.test');
    assert.deepEqual(errors, []);
    console.log('PASS owner access: same-tab private link, full-link paste, raw token, reload and invalid origin');
  } finally {
    await page.close();
  }
}
