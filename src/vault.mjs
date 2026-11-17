import { createCipheriv, createDecipheriv, createHash, createPrivateKey, generateKeyPairSync, randomBytes, scryptSync, sign } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { encode } from './cbor.mjs';

export const b64 = (value) => Buffer.from(value).toString('base64url');
const bytes = (value) => Buffer.from(value, 'base64url');
const hash = (value) => createHash('sha256').update(value).digest();
export function saveJSON(path, value) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(`${path}.tmp`, JSON.stringify(value, null, 2), { mode: 0o600 });
  renameSync(`${path}.tmp`, path);
}

export function validateScope(origin, rpId) {
  const url = new URL(origin);
  const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]' || url.hostname.endsWith('.localhost');
  if (url.origin !== origin || (url.protocol !== 'https:' && !(url.protocol === 'http:' && local))) throw new Error('A secure website origin is required.');
  if (typeof rpId !== 'string' || !rpId || (rpId !== url.hostname && !url.hostname.endsWith(`.${rpId}`))) throw new Error('Relying-party ID does not match the calling website.');
  // Chrome performs full public-suffix / Permissions Policy validation before
  // dispatching native proxy events. Only the paired extension can call this API.
  return rpId;
}

// Software authenticator: ES256, Ed25519, RS256, presence and per-ceremony
// vault-passphrase verification. No hardware attestation, PRF, or iframe ceremonies.
export class Vault {
  constructor(path, origin) {
    this.path = path;
    this.origin = origin;
    this.rpID = new URL(origin).hostname;
    this.key = null;
    this.records = null;
  }
  status() {
    return {
      initialized: existsSync(this.path),
      unlocked: !!this.key,
      credentials: this.records?.map(({ id, rpId, origin, rpName, userName, createdAt }) => ({ id, rpId, origin, rpName, userName, createdAt })) ?? [],
    };
  }
  setup(passphrase) {
    if (existsSync(this.path)) throw new Error('The vault already exists. Unlock it instead.');
    if (typeof passphrase !== 'string' || passphrase.length < 12 || passphrase.length > 1024) throw new Error('Use a passphrase between 12 and 1,024 characters.');
    this.salt = randomBytes(16);
    this.key = scryptSync(passphrase, this.salt, 32, { N: 32768, maxmem: 64 * 1024 * 1024 });
    this.records = [];
    this.persist();
  }
  unlock(passphrase) {
    if (typeof passphrase !== 'string' || passphrase.length > 1024) throw new Error('Enter your vault passphrase.');
    const file = JSON.parse(readFileSync(this.path, 'utf8'));
    const key = scryptSync(passphrase, bytes(file.salt), 32, { N: 32768, maxmem: 64 * 1024 * 1024 });
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, bytes(file.iv));
      decipher.setAAD(Buffer.from('passkey-proxy-vault:v1'));
      decipher.setAuthTag(bytes(file.tag));
      const records = JSON.parse(Buffer.concat([decipher.update(bytes(file.ciphertext)), decipher.final()]).toString());
      this.lock();
      this.salt = bytes(file.salt);
      this.key = key;
      this.records = records;
    } catch {
      key.fill(0);
      throw new Error('Could not unlock the vault. Check the passphrase.');
    }
  }
  lock() {
    this.key?.fill(0);
    this.key = null;
    this.records = null;
  }
  persist() {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from('passkey-proxy-vault:v1'));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(this.records)), cipher.final()]);
    saveJSON(this.path, { version: 1, kdf: 'scrypt-N32768-r8-p1', salt: b64(this.salt), iv: b64(iv), tag: b64(cipher.getAuthTag()), ciphertext: b64(ciphertext) });
  }
  verifyUser(passphrase) {
    // A fresh passphrase check is required for each UV assertion; an already
    // unlocked vault is not treated as verification of the current operation.
    this.unlock(passphrase);
    return true;
  }
  validate(options, origin, registration = false, { userVerified = false } = {}) {
    if (!this.key) throw new Error('Unlock the vault in the owner dashboard first.');
    const rpId = (registration ? options.rp?.id : options.rpId) || new URL(origin).hostname;
    validateScope(origin, rpId);
    if (typeof options.challenge !== 'string' || bytes(options.challenge).length < 16) throw new Error('Invalid WebAuthn challenge.');
    const uv = registration ? options.authenticatorSelection?.userVerification : options.userVerification;
    if (uv === 'required' && !userVerified) throw new Error('Verify with your vault passphrase for this request.');
    if (options.extensions?.appid || options.extensions?.appidExclude) throw new Error('Legacy U2F AppID credentials are not supported. Pause the proxy to use another authenticator.');
    if (options.extensions?.enforceCredentialProtectionPolicy || options.extensions?.largeBlob?.support === 'required') throw new Error('This request requires an authenticator extension that this provider does not implement.');
    return rpId;
  }
  register(options, origin, verification = {}) {
    const rpId = this.validate(options, origin, true, verification);
    if (typeof options.user?.id !== 'string' || !bytes(options.user.id).length || bytes(options.user.id).length > 64 || typeof options.user.name !== 'string') throw new Error('Invalid WebAuthn user.');
    const algorithm = options.pubKeyCredParams?.find(p => p.type === 'public-key' && [-7, -8, -257].includes(p.alg))?.alg;
    if (!algorithm) throw new Error('The site requires an unsupported algorithm. ES256, Ed25519 and RS256 are available.');
    if (options.excludeCredentials?.some(c => this.records.some(r => r.rpId === rpId && r.id === c.id))) throw new Error('A passkey for this account already exists.');
    const { privateKey, publicKey } = algorithm === -8 ? generateKeyPairSync('ed25519') : algorithm === -257 ? generateKeyPairSync('rsa', { modulusLength: 2048 }) : generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const jwk = publicKey.export({ format: 'jwk' });
    const cose = encode(new Map(algorithm === -8 ? [[1, 1], [3, -8], [-1, 6], [-2, bytes(jwk.x)]] : algorithm === -257 ? [[1, 3], [3, -257], [-1, bytes(jwk.n)], [-2, bytes(jwk.e)]] : [[1, 2], [3, -7], [-1, 1], [-2, bytes(jwk.x)], [-3, bytes(jwk.y)]]));
    const id = randomBytes(32);
    const idLength = Buffer.alloc(2);
    idLength.writeUInt16BE(id.length);
    // UP + AT; UV only after the trusted approval UI freshly verifies the passphrase.
    const authData = Buffer.concat([hash(rpId), Buffer.from([0x41 | (verification.userVerified ? 4 : 0)]), Buffer.alloc(4), Buffer.alloc(16), idLength, id, cose]);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false }));
    this.records.push({ id: b64(id), algorithm, rpId, origin, rpName: options.rp?.name || rpId, userId: options.user.id, userName: options.user.name,
      privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64url'), counter: 0, createdAt: new Date().toISOString() });
    this.persist();
    return { id: b64(id), rawId: b64(id), type: 'public-key', authenticatorAttachment: 'platform',
      response: { clientDataJSON: b64(clientDataJSON), attestationObject: b64(encode({ fmt: 'none', attStmt: {}, authData })), transports: ['internal'],
        publicKeyAlgorithm: algorithm, publicKey: b64(publicKey.export({ type: 'spki', format: 'der' })), authenticatorData: b64(authData) },
      clientExtensionResults: options.extensions?.credProps ? { credProps: { rk: true } } : {} };
  }
  authenticate(options, origin, verification = {}) {
    const rpId = this.validate(options, origin, false, verification);
    const matches = this.records.filter(r => r.rpId === rpId && (!options.allowCredentials?.length || options.allowCredentials.some(c => c.id === r.id)));
    if (matches.length > 1 && !verification.credentialId) throw new Error('More than one matching account. Unlock the dashboard, retry, and choose an account in the extension.');
    const record = verification.credentialId ? matches.find(r => r.id === verification.credentialId) : matches[0];
    if (!record) throw new Error('No matching passkey in the vault.');
    const count = Buffer.alloc(4);
    count.writeUInt32BE(++record.counter);
    const authenticatorData = Buffer.concat([hash(rpId), Buffer.from([1 | (verification.userVerified ? 4 : 0)]), count]);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin, crossOrigin: false }));
    const signature = sign(record.algorithm === -8 ? null : 'sha256', Buffer.concat([authenticatorData, hash(clientDataJSON)]), createPrivateKey({ key: bytes(record.privateKey), type: 'pkcs8', format: 'der' }));
    this.persist();
    return { id: record.id, rawId: record.id, type: 'public-key', authenticatorAttachment: 'platform',
      response: { clientDataJSON: b64(clientDataJSON), authenticatorData: b64(authenticatorData), signature: b64(signature), userHandle: record.userId }, clientExtensionResults: {} };
  }
}
