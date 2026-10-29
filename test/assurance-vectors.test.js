// Runs vectors/assurance.json: tokens, request digests and assurance decisions. A port in another language
// runs the same file.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { createAssurance, createIdentity, parseSnapshot, requestDigest, signToken, verifyToken } = require('..');

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vectors', 'assurance.json'), 'utf8'));
const SNAPSHOT = parseSnapshot(vectors.snapshot);
const NOW_MS = vectors.now * 1000;
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
const KEYS = new Map(Object.entries(vectors.signing_keys).map(([kid, seed]) => [
  kid,
  crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, Buffer.from(seed, 'base64url')]), format: 'der', type: 'pkcs8' }),
]));

function claimsFor(kind, { set = {}, remove = [] } = {}, digest = null) {
  const claims = { ...vectors.base_claims[kind], ...set };
  for (const field of remove) delete claims[field];
  if (claims.dig === '<digest>') claims.dig = digest;
  return claims;
}

function sign(claims, signWith) {
  const key = KEYS.get(signWith || claims.kid);
  // signToken insists on a kid, so a vector without one is signed by hand.
  if (typeof claims.kid !== 'string') {
    const signed = `v1.${Buffer.from(JSON.stringify(claims)).toString('base64url')}`;
    return `${signed}.${crypto.sign(null, Buffer.from(signed), key).toString('base64url')}`;
  }
  return signToken(claims, key);
}

const byName = new Map(vectors.tokens.map((entry) => [entry.name, entry]));

function tokenFor(entry) {
  if (entry.token !== undefined) return entry.token;
  const token = sign(claimsFor(entry.kind, entry.claims), entry.sign_with);
  const [version, payload, signature] = token.split('.');
  const transform = entry.token_transform || '';
  if (transform === 'pad_payload') return `${version}.${payload}=.${signature}`;
  if (transform === 'respell_signature') {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alphabet[alphabet.indexOf(signature.at(-1)) ^ 1];
    return `${version}.${payload}.${signature.slice(0, -1)}${last}`;
  }
  if (transform === 'extra_part') return `${token}.x`;
  if (transform === 'drop_signature') return `${version}.${payload}.`;
  if (transform === 'version_v2') return `v2.${payload}.${signature}`;
  if (transform.startsWith('swap_payload_from:')) return `${version}.${tokenFor(byName.get(transform.slice(18))).split('.')[1]}.${signature}`;
  assert.equal(transform, '', `unknown transform ${transform}`);
  return token;
}

test('token vectors', () => {
  for (const entry of vectors.tokens) {
    const result = verifyToken(tokenFor(entry), { keys: SNAPSHOT.keys, now: () => NOW_MS });
    assert.equal(result.ok, entry.expect.ok, `${entry.name}: ${result.reason}`);
    if (!entry.expect.ok) assert.equal(result.reason, entry.expect.reason, entry.name);
  }
});

test('the re-spelled signature decodes to the same bytes, so only strict decoding refuses it', () => {
  const entry = vectors.tokens.find((item) => item.token_transform === 'respell_signature');
  const original = sign(claimsFor(entry.kind, entry.claims)).split('.')[2];
  const respelled = tokenFor(entry).split('.')[2];
  assert.notEqual(respelled, original);
  assert.deepEqual(Buffer.from(respelled, 'base64url'), Buffer.from(original, 'base64url'));
});

test('digest vectors', () => {
  for (const entry of vectors.digests) assert.equal(requestDigest(entry), entry.digest, `${entry.method} ${entry.url}`);
});

test('assurance vectors', async () => {
  const identity = createIdentity({ appId: vectors.app, mode: 'tailnet', listen: 'unix:/run/sovereign-apps/test/app.sock', reader: { current: () => ({ ok: true, snapshot: SNAPSHOT }) } });
  for (const entry of vectors.assurance) {
    const calls = [];
    const assurance = createAssurance({
      appId: vectors.app,
      hostname: vectors.hostname,
      identity,
      now: () => NOW_MS,
      isAdministrator: (member) => vectors.administrators.includes(member.userId),
      redeem: async (request) => {
        calls.push(request);
        return entry.redeem === 'redeemed' ? { redeemed: true } : { redeemed: false, reason: entry.redeem };
      },
    });
    const target = entry.target ?? '';
    const headers = { ...entry.identity };
    if (entry.cookie) headers.cookie = entry.cookie.replaceAll('<token>', sign(claimsFor('assurance', entry.claims)));
    if (entry.action) {
      const digest = requestDigest({ ...entry.request, target });
      headers['x-sovereign-action-token'] = sign(claimsFor('action', entry.action, digest));
    }
    const decision = await assurance.check(entry.policy, { ...entry.request, headers }, { target });
    if (entry.expect.allowed) {
      assert.equal(decision.allowed, true, `${entry.name}: ${decision.reason}`);
      assert.equal(decision.level, entry.expect.level, entry.name);
    } else {
      assert.deepEqual({ allowed: decision.allowed, status: decision.status, body: decision.body, reason: decision.reason }, entry.expect, entry.name);
    }
    if (entry.redeem_calls !== undefined) assert.equal(calls.length, entry.redeem_calls, `${entry.name}: redemptions`);
    for (const call of calls) {
      assert.deepEqual(Object.keys(call).sort(), ['digest', 'policy', 'target', 'token'], entry.name);
      assert.equal(call.policy, entry.policy);
      assert.equal(call.target, target);
      assert.equal(call.token, headers['x-sovereign-action-token']);
    }
  }
});
