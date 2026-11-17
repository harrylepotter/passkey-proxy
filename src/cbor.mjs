// Small, bounded CBOR subset for this demo's ES256/none WebAuthn messages.
// Production relying parties should use a maintained WebAuthn verification library.
function head(type, n) {
  if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) throw new Error('Unsupported CBOR length.');
  if (n < 24) return Buffer.from([(type << 5) | n]);
  if (n < 256) return Buffer.from([(type << 5) | 24, n]);
  const b = Buffer.alloc(n < 65536 ? 3 : 5); b[0] = (type << 5) | (n < 65536 ? 25 : 26);
  n < 65536 ? b.writeUInt16BE(n, 1) : b.writeUInt32BE(n, 1); return b;
}
export function encode(value) {
  if (Number.isInteger(value)) return head(value < 0 ? 1 : 0, value < 0 ? -1 - value : value);
  if (typeof value === 'string') { const b = Buffer.from(value); return Buffer.concat([head(3, b.length), b]); }
  if (value instanceof Uint8Array) return Buffer.concat([head(2, value.length), value]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(encode)]);
  if (value && typeof value === 'object') {
    const entries = value instanceof Map ? [...value] : Object.entries(value);
    return Buffer.concat([head(5, entries.length), ...entries.flatMap(([k, v]) => [encode(k), encode(v)])]);
  }
  throw new Error('Unsupported CBOR value.');
}
export function decode(input) {
  const b = Buffer.from(input); let p = 0;
  function read(depth = 0) {
    if (depth > 12 || p >= b.length) throw new Error('Invalid CBOR.');
    const first = b[p++], type = first >> 5, info = first & 31;
    let n = info;
    if (info >= 24) {
      const size = { 24: 1, 25: 2, 26: 4 }[info];
      if (!size || p + size > b.length) throw new Error('Unsupported CBOR encoding.');
      n = b.readUIntBE(p, size); p += size;
    }
    if (type === 0) return n;
    if (type === 1) return -1 - n;
    if (type === 2 || type === 3) {
      if (p + n > b.length) throw new Error('Truncated CBOR.');
      const result = b.subarray(p, p + n); p += n; return type === 2 ? result : result.toString('utf8');
    }
    if (n > 100) throw new Error('CBOR collection is too large.');
    if (type === 4) return Array.from({ length: n }, () => read(depth + 1));
    if (type === 5) {
      const result = new Map();
      for (let i = 0; i < n; i++) { const k = read(depth + 1); if (result.has(k)) throw new Error('Duplicate CBOR key.'); result.set(k, read(depth + 1)); }
      return result;
    }
    throw new Error('Unsupported CBOR type.');
  }
  const result = read(); if (p !== b.length) throw new Error('Trailing CBOR data.'); return result;
}
