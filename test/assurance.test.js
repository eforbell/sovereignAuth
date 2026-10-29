// createAssurance's configuration and adapters; the decisions themselves are in vectors/assurance.json.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { POLICY, assuranceCookie, assuranceExpress, createAssurance, createIdentity, parseSnapshot, policyFor, requestDigest, sendAssuranceRefusal, signToken } = require('..');

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vectors', 'assurance.json'), 'utf8'));
const SNAPSHOT = parseSnapshot(vectors.snapshot);
const NOW_MS = vectors.now * 1000;
const K1 = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(vectors.signing_keys.k1, 'base64url')]), format: 'der', type: 'pkcs8' });
const PARENT = { 'x-sovereign-user-id': '1001', 'x-sovereign-login': 'parent@example.com' };
const reader = { current: () => ({ ok: true, snapshot: SNAPSHOT }) };
const identity = createIdentity({ appId: 'family-pulse', mode: 'tailnet', listen: 'unix:/run/sovereign-apps/family-pulse/app.sock', reader });

function assurance(options = {}) {
  return createAssurance({ appId: 'family-pulse', hostname: vectors.hostname, identity, now: () => NOW_MS, isAdministrator: (member) => member.userId === '1001', redeem: async () => ({ redeemed: true }), ...options });
}

test('the policy matrix: every level known, windows where sessions need them, hardware only for every-time', () => {
  const levels = new Set(['tailnet', 'session', 'recent', 'every-time']);
  for (const [key, policy] of Object.entries(POLICY.policies)) {
    assert.ok(levels.has(policy.level), key);
    assert.ok(['any', 'hardware'].includes(policy.kind), key);
    assert.equal(policy.level === 'session', Number.isSafeInteger(policy.window_seconds), key);
  }
  assert.equal(POLICY.recent_seconds, 300);
  assert.equal(policyFor('open-admin').window_seconds, 8 * 3600);
  assert.equal(policyFor('open-operator').window_seconds, 24 * 3600);
  assert.equal(policyFor('open-documents').window_seconds, 30 * 86400);
  for (const key of ['privileged-plan', 'grant-administrator', 'manage-admin-credential']) {
    assert.deepEqual([policyFor(key).level, policyFor(key).kind, policyFor(key).administrator], ['every-time', 'hardware', true], key);
  }
  assert.throws(() => policyFor('constructor'), /no assurance policy/);
  assert.throws(() => policyFor('Open-Admin'), /no assurance policy/);
});

test('configuration errors stop the app, they are never a quiet allow', async () => {
  assert.throws(() => createAssurance({ hostname: vectors.hostname, identity }), /app's ID/);
  assert.throws(() => createAssurance({ appId: 'family-pulse', hostname: 'Smith-Pulse.example.ts.net', identity }), /hostname/);
  assert.throws(() => createAssurance({ appId: 'family-pulse', hostname: vectors.hostname, identity: createIdentity({ appId: 'family-pulse', mode: 'local' }) }), /tailnet identity/);
  assert.throws(() => createAssurance({ appId: 'helm', hostname: vectors.hostname, identity }), /tailnet identity/, 'another app\'s identity');
  await assert.rejects(assurance().check('no-such-policy', { method: 'GET', url: '/', headers: PARENT }), /no assurance policy/);
  await assert.rejects(assurance({ isAdministrator: undefined }).check('open-admin', { method: 'GET', url: '/', headers: PARENT }), /needs isAdministrator/);
  await assert.rejects(assurance().check('privileged-plan', { method: 'POST', url: '/', headers: PARENT, body: '' }, { target: 'a\nb' }), /no line breaks/);
  await assert.rejects(assurance().check('privileged-plan', { method: 'POST', url: '/', headers: { ...PARENT, 'content-length': '12' } }, { target: '' }), /raw request body/);
  assert.throws(() => requestDigest({ method: 'POST', url: '/', body: { plan: 'restore' }, target: '' }), /raw body bytes/);
});

test('cookie parsing: exact name, one value, other cookies ignored', () => {
  assert.deepEqual(assuranceCookie({ cookie: 'a=1; __Host-sv_assurance=v1.x.y; b=2' }), { token: 'v1.x.y', reason: null });
  assert.deepEqual(assuranceCookie({ cookie: ['a=1', '__Host-sv_assurance=v1.x.y'] }), { token: 'v1.x.y', reason: null });
  assert.deepEqual(assuranceCookie({ cookie: ['__Host-sv_assurance=a', '__Host-sv_assurance=b'] }), { token: null, reason: 'duplicate_cookie' });
  assert.deepEqual(assuranceCookie({ cookie: 'sv_assurance=v1.x.y; __Secure-sv_assurance=v1.x.y; __Host-sv_assurance_old=x' }), { token: null, reason: 'no_cookie' });
  assert.deepEqual(assuranceCookie({}), { token: null, reason: 'no_cookie' });
});

test('a refusal is logged with the reason, never the token or the query', async () => {
  const lines = [];
  const token = signToken({ ...vectors.base_claims.assurance, aud: 'smith-home.example-tailnet.ts.net' }, K1);
  const decision = await assurance({ log: (line) => lines.push(line) }).check('open-documents', { method: 'GET', url: '/documents?code=secret', headers: { ...PARENT, cookie: `__Host-sv_assurance=${token}` } });
  assert.equal(decision.status, 401);
  assert.deepEqual(lines, ['[sovereign-auth] open-documents not met for GET /documents: wrong_audience']);
});

async function withServer(handler, run) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    return await run(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function send(base, { method = 'GET', url = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(`${base}${url}`, { method, headers }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, cacheControl: res.headers['cache-control'], body: text ? JSON.parse(text) : null }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

test('Node http: the 401 step-up answer reaches the client as the contract writes it', async () => {
  const gate = assurance();
  await withServer(async (req, res) => {
    const decision = await gate.check('export-data', req);
    if (!decision.allowed) return sendAssuranceRefusal(res, decision);
    res.writeHead(200).end('{}');
  }, async (base) => {
    assert.deepEqual(await send(base, { headers: PARENT }), { status: 401, cacheControl: 'no-store', body: { error: 'step_up_required', policy: 'export-data', level: 'recent', kind: 'any' } });
  });
});

// A minimal stand-in for Express: middleware is (req, res, next), the body parser keeps req.rawBody.
function expressLike(middleware, handler, { keepRawBody = true } = {}) {
  return (req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const raw = Buffer.concat(chunks);
      if (raw.length) {
        req.body = JSON.parse(raw);
        if (keepRawBody) req.rawBody = raw;
      }
      req.originalUrl = req.url;
      middleware(req, res, (error) => {
        if (error) {
          res.writeHead(500).end(JSON.stringify({ error: error.message }));
          return;
        }
        handler(req, res);
      });
    });
  };
}

test('Express: every-time binds the raw body; a parsed body alone is an error, not an unbound token', async () => {
  const redeemed = [];
  const gate = assurance({ redeem: async (request) => { redeemed.push(request); return { redeemed: true }; } });
  const middleware = assuranceExpress(gate, 'privileged-plan', { target: async () => 'backup 1' });
  const ok = (req, res) => res.writeHead(200).end(JSON.stringify({ member: req.sovereignMember.memberId }));
  const body = '{"plan":"restore"}';
  const headers = { ...PARENT, 'content-type': 'application/json' };

  await withServer(expressLike(middleware, ok), async (base) => {
    const first = await send(base, { method: 'POST', url: '/api/plans', headers, body });
    assert.equal(first.status, 401);
    assert.equal(first.body.digest, requestDigest({ method: 'POST', url: '/api/plans', body, target: 'backup 1' }));
    const claims = { ...vectors.base_claims.action, act: 'privileged-plan', tgt: 'backup 1', dig: first.body.digest };
    const retry = await send(base, { method: 'POST', url: '/api/plans', headers: { ...headers, 'x-sovereign-action-token': signToken(claims, K1) }, body });
    assert.deepEqual(retry, { status: 200, cacheControl: undefined, body: { member: 'm_parent' } });
    assert.equal(redeemed.length, 1);
    const otherBody = await send(base, { method: 'POST', url: '/api/plans', headers: { ...headers, 'x-sovereign-action-token': signToken(claims, K1) }, body: '{"plan":"uninstall"}' });
    assert.equal(otherBody.status, 401, 'the same token for another body');
  });

  await withServer(expressLike(middleware, ok, { keepRawBody: false }), async (base) => {
    const result = await send(base, { method: 'POST', url: '/api/plans', headers, body });
    assert.deepEqual(result.body, { error: 'every-time actions need the raw request body' });
  });
});
