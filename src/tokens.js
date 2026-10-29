// Tokens (wire contract, section 6): v1.<payload>.<signature>, the payload base64url JSON and the signature
// Ed25519 over the ASCII bytes of "v1.<payload>". There is no algorithm field and nothing to negotiate; the
// key is the snapshot key the payload's kid names. Assurance cookies and action tokens both use it.

const crypto = require('node:crypto');

const VERSION = 'v1';
const MAX_TOKEN_LENGTH = 4096;
const MAX_FUTURE_SECONDS = 30;
const BASE64URL = /^[A-Za-z0-9_-]+$/;

// Strict base64url: the alphabet, no padding, and the one canonical spelling of the bytes, so a token can't
// be re-spelled (spare bits set, say) and still verify.
function decodeBase64url(text) {
  if (typeof text !== 'string' || !BASE64URL.test(text)) return null;
  const bytes = Buffer.from(text, 'base64url');
  return bytes.toString('base64url') === text ? bytes : null;
}

const encodeJson = (value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');

// Home Base's side (SID-005), and the tests'. privateKey is a KeyObject or anything crypto.createPrivateKey
// takes; the payload must name its kid.
function signToken(payload, privateKey) {
  if (!payload || typeof payload !== 'object' || typeof payload.kid !== 'string' || !payload.kid) throw new Error('a token payload names its kid');
  const signed = `${VERSION}.${encodeJson(payload)}`;
  const signature = crypto.sign(null, Buffer.from(signed, 'ascii'), privateKey);
  return `${signed}.${signature.toString('base64url')}`;
}

const isSeconds = (value) => Number.isSafeInteger(value) && value >= 0;

// verifyToken(token, { keys, now }) checks the format, the signature against keys.get(kid) and the token's
// own times. It returns { ok: true, payload } or { ok: false, reason }: malformed, unknown_kid,
// bad_signature, expired or not_yet_valid. What the payload claims is the caller's to check.
function verifyToken(token, { keys, now = Date.now } = {}) {
  if (typeof token !== 'string' || token.length > MAX_TOKEN_LENGTH) return { ok: false, reason: 'malformed' };
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== VERSION) return { ok: false, reason: 'malformed' };
  const payloadBytes = decodeBase64url(parts[1]);
  const signature = decodeBase64url(parts[2]);
  if (!payloadBytes || !signature) return { ok: false, reason: 'malformed' };
  let payload;
  try {
    payload = JSON.parse(payloadBytes.toString('utf8'));
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return { ok: false, reason: 'malformed' };
  if (typeof payload.kid !== 'string' || !isSeconds(payload.iat) || !isSeconds(payload.exp)) return { ok: false, reason: 'malformed' };
  const key = keys?.get(payload.kid);
  if (!key) return { ok: false, reason: 'unknown_kid' };
  let valid = false;
  try {
    valid = crypto.verify(null, Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii'), key, signature);
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, reason: 'bad_signature' };
  const seconds = Math.floor(now() / 1000);
  if (payload.exp <= seconds) return { ok: false, reason: 'expired' };
  if (payload.iat > seconds + MAX_FUTURE_SECONDS) return { ok: false, reason: 'not_yet_valid' };
  return { ok: true, payload };
}

module.exports = { MAX_TOKEN_LENGTH, signToken, verifyToken };
