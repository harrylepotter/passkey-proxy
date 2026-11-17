# Passkey Proxy

A local passkey vault and Chrome extension that lets you approve authentication for an agent. It offers two separate workflows:

- **Passkey access:** register a website passkey in your vault. An agent obtains a fresh website challenge, you approve it, and the vault returns a signed response. The website creates the agent's session in the client that started the login. The private key stays in your vault.
- **Session sharing:** open a website where you are already signed in, then create a one-time cookie invite from the extension popup. A compatible agent imports that session into its own browser. No saved passkey is required.

This is a local proof of concept, not an audited password manager. Website compatibility depends on the site's authentication flow and the receiving agent's tools. A working gateway does not by itself give an agent a browser passkey provider or a cookie-import capability.

## Requirements

- Node.js **22 or later** and npm.
- A current desktop Chrome installation. The manual extension setup below uses your regular Chrome profile. The optional development launcher also supports compatible Chromium installations.
- An agent with tools to complete the selected workflow. Browser tasks must finish authentication in the browser context used for the task.
- For access from another machine: an [ngrok account and CLI](https://ngrok.com/docs/start).

Development and browser checks have been exercised on macOS. The browser launcher also checks common Linux installation paths; other installations can use `CHROME_PATH`.

## 1. Install and start the local gateway

```sh
git clone https://github.com/harrylepotter/passkey-proxy.git
cd passkey-proxy
npm ci
npm start
```

Leave this terminal running. On the first run, the gateway creates fresh local state under `.data/`, including a private owner-access link. There are no supplied credentials or default vault password.

| Service | Address | Purpose |
| --- | --- | --- |
| Owner dashboard | `http://127.0.0.1:4780` | Create/unlock the vault, pair Chrome, and approve requests |
| Local demo | `http://localhost:4781` | Try registration and sign-in with synthetic account data |
| Agent gateway | `http://127.0.0.1:4782` | Invitations, approval requests, and one-time collection |

Open `.data/owner-url.txt` locally and paste its **full URL** into Chrome. Opening the dashboard address without the owner token shows “Owner access required.” Keep the owner link on your machine; it is different from an agent invite.

## 2. Load the extension in regular Chrome

1. Open `chrome://extensions`.
2. Turn on **Developer mode**.
3. Click **Load unpacked** and select this repository's `extension` directory.
4. Open the private owner URL from `.data/owner-url.txt`, or reload that dashboard tab if it is already open.
5. Create a vault with your own passphrase of at least 12 characters.
6. Click **Connect extension** in the dashboard. Pin **Passkey Proxy** in Chrome's toolbar if you want quick access to session sharing.

These are Chrome's standard [unpacked-extension installation steps](https://developer.chrome.com/docs/extensions/get-started/tutorial/hello-world#load-unpacked).

The extension menu lets you switch between **Use vault passkeys** and **Use OS passkeys**. The choice applies across that Chrome profile and persists across restarts. After switching providers during a website request, click the website's passkey button again.

Optional development launcher, in another terminal:

```sh
npm run open
```

This opens a separate Chrome profile and loads the extension automatically. It requires a Chrome version supporting the `Extensions.loadUnpacked` debugging command. Use the manual installation above if automatic loading is unavailable. A changed extension build in the development launcher may need **Connect extension** again.

For an installation outside the detected paths:

```sh
CHROME_PATH="/path/to/chrome" npm run open
```

## 3. Give remote agents access through ngrok

On macOS, install ngrok and configure **your own** authtoken:

```sh
brew install ngrok
ngrok config add-authtoken YOUR_NGROK_AUTHTOKEN
```

Use the [official installation instructions](https://ngrok.com/docs/start) for other platforms. The authtoken belongs in ngrok's local configuration, not in this repository or an agent message.

With `npm start` still running, open another terminal in the repository:

```sh
npm run share:agent
```

Wait for:

```text
Remote agent gateway ready: https://YOUR-ASSIGNED-DOMAIN.ngrok-free.app
```

The helper starts an HTTPS tunnel to **port 4782**, disables request inspection, and saves the public agent URL in the local gateway. Keep both terminals running while an agent uses the gateway. Ctrl+C in the sharing terminal closes the tunnel.

For repeat access links, keep the same public hostname. If your ngrok account has an assigned domain, use its exact URL:

```sh
NGROK_URL="https://YOUR-ASSIGNED-DOMAIN.ngrok-free.app" npm run share:agent
```

The hostname above is a placeholder: replace it with the domain assigned to your account. `NGROK_PATH` can select a non-default ngrok executable. See the [ngrok CLI reference](https://ngrok.com/docs/gateway/agent/cli) for installation and endpoint options.

Only expose the agent listener. **Do not tunnel port 4780, a Chrome debugging port, or the `.data/` directory.** The owner dashboard remains local. Remote agents cannot reach the local demo or a localhost invitation on your computer.

## 4A. Share passkey access from the dashboard

1. Sign in to a website normally and open its security settings.
2. Choose **Add passkey** while the extension's vault provider is active. Approve the registration in the extension window. Keep another recovery/sign-in method while evaluating the prototype.
3. In the owner dashboard, choose the saved account under **Agent access**. Set the destination website and its actual **Website sign-in page**. Some sites enroll and authenticate on different subdomains; the configured sign-in origin must match the website's WebAuthn request and stay within the passkey's relying party.
4. Start `npm run share:agent` for a remote agent. Use **Local preview only** only for clients on this machine.
5. Leave **Persistent link** enabled for repeat requests, then create the link and copy its instructions to the intended agent. Save the link when created; the gateway stores its hash and cannot display it again.
6. The agent starts the website's passkey login in its own browser or HTTP client and sends the fresh request options to the gateway. Review the account and purpose, enter your vault passphrase locally, and click **Approve passkey sign-in**.
7. The agent collects the signed response once, submits it to the website from the same client, and verifies the signed-in account before doing the task.

Every new sign-in needs fresh website state and a new approval. The passphrase and private key are not sent to the agent. A persistent link allows requests until revoked; it does not grant unattended approval. A one-use passkey invitation expires after one hour, and a submitted challenge request lasts at most two minutes.

Agent protocol: [public/instructions.txt](public/instructions.txt), also served at `/instructions` on the public agent URL. The gateway supplies a signature, not a universal website login adapter. HTTP-only authentication does not sign in an unrelated browser context.

## 4B. Share an existing session from the extension

1. In the paired Chrome profile, open a page where you are signed in.
2. Open the **Passkey Proxy** popup and select **Create session invite**.
3. Approve Chrome's cookie/site permission prompt. Capture is limited to cookies applicable to that page and its cookie store.
4. Copy the invitation instructions to the intended agent. Creating the invite approves **one collection**, available for **10 minutes**; no additional vault approval is required.
5. The recipient collects and imports the cookies into its task browser, then checks the signed-in account. Keep using that same browser context for the task.

The gateway preserves cookie attributes, including HttpOnly, Secure, SameSite, path and domain scope. The recipient needs a compatible browser-cookie import operation. A page script cannot create an HttpOnly cookie, and an HTTP client's cookie jar does not sign in a separate browser.

The capture excludes unrelated sites, sibling-only cookies, partitioned cookies, and local/session storage. Some sites require additional state or bind sessions to a device. Collection is one-use; cancellation or expiry cannot revoke cookies already imported elsewhere. Cookie invites do not renew themselves.

Agent protocol: [public/session-instructions.txt](public/session-instructions.txt), also served at `/session-instructions`. Session invites and passkey access links use separate tokens and APIs.

## Try the local demo

In the dashboard, register a passkey for **Demo Travel**, approve the extension prompt, and confirm that the demo signs in. Its account uses `user@example.test` and synthetic bookings. Choose that account to create a local agent invitation. The agent must retain the demo's `ceremonyId` and challenge cookies when submitting the approved signature.

The automated checks below exercise the complete demo and independent synthetic websites without accessing real accounts.

## Restart, update, and troubleshoot

- **Owner access required:** use the complete URL in `.data/owner-url.txt`, then reload the dashboard. The page also accepts that full URL in its owner-token field.
- **Extension not detected:** load the correct `extension` directory in the same Chrome profile, reload the dashboard, and click **Connect extension**.
- **Changes do not appear:** click **Reload** for the extension at `chrome://extensions`, reload the dashboard, and restart `npm start` after server-code changes. Restart `npm run share:agent` if its tunnel has stopped.
- **Remote agent cannot open a link:** keep the gateway and ngrok running and check the public URL in the dashboard. Use the assigned ngrok hostname consistently. Local preview links work only on your machine.
- **Session expired or already collected:** create a new cookie invite, or reuse a persistent passkey link with a fresh website challenge and owner approval. Do not repeatedly redeem a consumed token.
- **Agent has a cookie jar but its browser is signed out:** ensure the session is installed in the actual task browser. HTTP access alone is not browser authentication.
- **Website or tool rejects a required operation:** report the actual step and response. This project does not bypass website protections or provide missing agent tools.
- **Automatic browser launch fails:** use regular Chrome with the manual extension installation, or set `CHROME_PATH` correctly.

The vault locks after 15 minutes and on restart. Encrypted keys, persistent-link hashes and the configured public agent origin survive restarts. Pending approvals and uncollected bundles do not. There is no passphrase recovery; keep `.data/` private and back it up securely if you need to preserve the vault. Do not delete it to resolve a routine pairing issue.

## Tests and development

```sh
npm test
npm run check -- --quick
npm run check:sessions
```

Browser checks use disposable profiles, synthetic accounts, and separate ports from the running application. Omit `--quick` to include the longer extension-worker idle check. Browser checks require Chrome; `npm test` covers the core protocol without launching it.

`npm run open:debug` is an optional development mode exposing a loopback Chrome debugging endpoint on port 9223. It is not needed for regular Chrome setup or remote agent access.

See [the architecture and flowcharts](docs/flow.md) and [the security model](SECURITY.md). The project uses the ISC license; bundled third-party notices remain in `extension/tldts.LICENSE.txt`.
