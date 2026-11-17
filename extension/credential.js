// Shared by the extension and the gateway's isolated authentication browser.
// The result is shaped like a PublicKeyCredential for the demo site's ordinary WebAuthn calls.
(() => {
  const encode = value => {
    if (value instanceof ArrayBuffer) value = new Uint8Array(value);
    if (ArrayBuffer.isView(value)) return btoa(String.fromCharCode(...new Uint8Array(value.buffer, value.byteOffset, value.byteLength))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    if (Array.isArray(value)) return value.map(encode);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, encode(v)]));
    return value;
  };
  const decode = value => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0)).buffer;
  const restore = json => {
    const response = Object.fromEntries(Object.entries(json.response).map(([k, v]) => [k, typeof v === 'string' ? decode(v) : v]));
    response.getTransports = () => json.response.transports ?? [];
    response.getPublicKeyAlgorithm = () => json.response.publicKeyAlgorithm;
    response.getPublicKey = () => json.response.publicKey ? decode(json.response.publicKey) : null;
    response.getAuthenticatorData = () => json.response.authenticatorData ? decode(json.response.authenticatorData) : null;
    return { id: json.id, rawId: decode(json.rawId), type: json.type, authenticatorAttachment: json.authenticatorAttachment, response,
      getClientExtensionResults: () => json.clientExtensionResults, toJSON: () => json };
  };
  window.PasskeyProxyCredential = { encode, restore };
})();
