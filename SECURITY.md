# Security model and limitations

This project is an unaudited local proof of concept. Use test accounts and retain an independent recovery/sign-in method while evaluating it.

The vault encrypts passkey private keys at rest using a passphrase-derived key. Keys are present in the local process while unlocked. The vault locks on restart and after 15 minutes. Agent signatures require explicit approval and a fresh passphrase check; merely unlocking the vault is insufficient.

The extension uses Chrome's native WebAuthn proxy API. It is a software authenticator, not a physical hardware security key. Hardware attestation, PRF results and several optional WebAuthn extensions are not implemented. Unsupported requirements fail explicitly.

Remote signing validates the saved relying party, configured origin and selected credential, but the agent supplies the challenge and origin. The gateway cannot independently prove where the agent obtained that challenge. Agent names and task descriptions are self-reported. Approval grants account access; the stated task does not restrict the website account's permissions.

Cookie invitations deliberately transfer a session credential. Creation approves one collection; it does not restrict the resulting website session to one task or ten minutes. A collected session lasts until the destination website expires or revokes it. Cookie attributes are preserved, and the project does not automatically remove HttpOnly or other protections for import compatibility.

Keep owner links, vault passphrases, invitation tokens, signed responses, cookies, ngrok credentials, browser profiles and `.data/` private. The repository ignores runtime data, environment files, captures and generated artifacts. Ignore rules do not protect files that someone explicitly force-adds or includes in an issue, screenshot or chat.

The ngrok helper tunnels only the agent listener and disables request inspection. The tunnel provider and receiving agent are part of the trust boundary. Do not expose the owner listener, a debugging endpoint, or a directory containing runtime state. Do not change tool or website protections to make an unsupported workflow appear successful.

There is no multi-user isolation, account recovery service, distributed rate limiting, or production deployment hardening. If reporting a problem publicly, use synthetic reproduction data; never include real credentials or session material.
