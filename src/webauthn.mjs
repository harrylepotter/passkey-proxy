import { createHash, createPublicKey, timingSafeEqual, verify } from 'node:crypto';
import { decode } from './cbor.mjs';
const bytes = s => {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s)) throw new Error('Invalid base64url.');
  return Buffer.from(s, 'base64url');
};
const hash = value => createHash('sha256').update(value).digest();
function client(response, expected, type) {
  if (response.type !== 'public-key' || response.id !== response.rawId) throw new Error('Invalid public-key credential.');
  const raw = bytes(response.response.clientDataJSON), data = JSON.parse(raw.toString());
  if (data.type !== type || data.challenge !== expected.challenge || data.origin !== expected.origin || data.crossOrigin === true) throw new Error('WebAuthn challenge or origin did not match.');
  return hash(raw);
}
function authenticator(data, rpID) {
  if (data.length < 37 || !timingSafeEqual(data.subarray(0, 32), hash(rpID))) throw new Error('WebAuthn RP ID did not match.');
  if (!(data[32] & 1)) throw new Error('User presence is required.');
  if (data[32] & 0x80) throw new Error('Authenticator extensions are not supported by this demo.');
  return data.readUInt32BE(33);
}
export function verifyRegistration(response, expected) {
  client(response, expected, 'webauthn.create');
  const attestation = decode(bytes(response.response.attestationObject));
  if (attestation.get('fmt') !== 'none' || attestation.get('attStmt')?.size !== 0) throw new Error('Only none attestation is supported.');
  const data = attestation.get('authData');
  if (!(data instanceof Uint8Array)) throw new Error('Missing authenticator data.');
  const counter = authenticator(data, expected.rpID);
  if (!(data[32] & 0x40) || data.length < 55) throw new Error('Missing attested credential data.');
  const size = data.readUInt16BE(53), id = data.subarray(55, 55 + size);
  if (!size || id.toString('base64url') !== response.id) throw new Error('Credential ID mismatch.');
  const key = decode(data.subarray(55 + size));
  if (key.get(1) !== 2 || key.get(3) !== -7 || key.get(-1) !== 1 || key.get(-2)?.length !== 32 || key.get(-3)?.length !== 32) throw new Error('Expected an ES256 public key.');
  const jwk = { kty: 'EC', crv: 'P-256', x: key.get(-2).toString('base64url'), y: key.get(-3).toString('base64url') };
  createPublicKey({ key: jwk, format: 'jwk' });
  return { id: response.id, publicKey: jwk, counter };
}
export function verifyAuthentication(response, expected, credential) {
  const clientHash = client(response, expected, 'webauthn.get');
  if (response.id !== credential.id || response.response.userHandle !== expected.userID) throw new Error('Credential or account mismatch.');
  const data = bytes(response.response.authenticatorData), counter = authenticator(data, expected.rpID);
  if (data.length !== 37 || data[32] & 0x40) throw new Error('Unexpected assertion data.');
  if (!verify('sha256', Buffer.concat([data, clientHash]), createPublicKey({ key: credential.publicKey, format: 'jwk' }), bytes(response.response.signature))) throw new Error('Invalid WebAuthn signature.');
  if ((counter !== 0 || credential.counter !== 0) && counter <= credential.counter) throw new Error('WebAuthn signature counter did not advance.');
  return counter;
}
