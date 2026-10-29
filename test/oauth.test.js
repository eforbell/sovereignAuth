// The OAuth callback helper (wire contract, section 10): completion decisions from vectors/oauth.json, then
// start, the landing page and the store, including the landing page in a real browser-like run.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createMemoryStateStore, createOAuthFlow, pkceChallenge } = require('..');

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vectors', 'oauth.json'), 'utf8'));
const member = (userId) => (userId ? { userId } : null);

function flow(options = {}) {
  return createOAuthFlow({ hostname: vectors.hostname, landingPath: vectors.landing_path, completionPath: 'complete', donePath: '../settings', ...options });
}

test('completion vectors', async () => {
  for (const entry of vectors.cases) {
    const store = createMemoryStateStore({ now: () => vectors.now });
    const record = entry.record === null ? null : { ...vectors.base.record, ...entry.record_set };
    if (record) store.put(record);
    const headers = { ...vectors.base.headers };
    for (const [name, value] of Object.entries(entry.headers_set || {})) {
      if (value === null) delete headers[name];
      else headers[name] = value;
    }
    const result = await flow({ store, now: () => vectors.now + (entry.now_offset_ms || 0) }).complete({
      member: member(entry.member === undefined ? vectors.base.member : entry.member),
      headers,
      body: entry.body === undefined ? vectors.base.body : entry.body,
    });
    if (entry.expect.ok) {
      assert.equal(result.ok, true, `${entry.name}: ${result.reason}`);
      assert.equal(result.code, vectors.base.body.code);
      assert.equal(result.codeVerifier, vectors.base.record.codeVerifier);
      assert.deepEqual(result.data, vectors.base.record.data);
    } else {
      assert.deepEqual({ ok: result.ok, status: result.status, reason: result.reason }, entry.expect, entry.name);
      assert.deepEqual(result.body, { error: 'oauth_refused', reason: entry.expect.reason }, entry.name);
    }
    assert.equal(result.clearCookie, '__Host-sv_oauth=; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age=0', entry.name);
    if (record && entry.expect.reason !== 'malformed') assert.equal(store.take(record.state), null, `${entry.name}: the record is used up`);
  }
});

test('PKCE vectors', () => {
  for (const { verifier, challenge } of vectors.pkce) assert.equal(pkceChallenge(verifier), challenge);
});

test('start stores a single-use record and sets the correlation cookie; the code works once', async () => {
  let clock = vectors.now;
  const store = createMemoryStateStore({ now: () => clock });
  const oauth = flow({ store, now: () => clock });
  const started = await oauth.start(member('1001'), { data: { provider: 'schwab' } });
  assert.match(started.state, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(started.codeChallengeMethod, 'S256');
  const correlation = started.setCookie.match(/^__Host-sv_oauth=([A-Za-z0-9_-]{43}); Secure; HttpOnly; Path=\/; SameSite=Strict; Max-Age=600$/)[1];
  assert.notEqual(correlation, started.state);

  clock += 30_000;
  const request = { member: member('1001'), headers: { cookie: `__Host-sv_oauth=${correlation}`, referer: oauth.landingUrl }, body: { code: 'abc', state: started.state } };
  const done = await oauth.complete(request);
  assert.equal(done.ok, true, done.reason);
  assert.equal(pkceChallenge(done.codeVerifier), started.codeChallenge, 'the verifier matches the challenge sent to the provider');
  assert.deepEqual(done.data, { provider: 'schwab' });
  assert.equal((await oauth.complete(request)).reason, 'unknown_state', 'replayed');

  const plain = await oauth.start(member('1001'), { pkce: false });
  assert.equal(plain.codeChallenge, null);
  assert.equal(plain.codeChallengeMethod, null);
  await assert.rejects(oauth.start(null), /starts for a member/);
});

test('a wrong attempt uses the state up, so the right one can\'t follow it', async () => {
  const store = createMemoryStateStore();
  const oauth = flow({ store });
  const started = await oauth.start(member('1001'));
  const correlation = started.setCookie.split(';')[0].split('=')[1];
  const right = { member: member('1001'), headers: { cookie: `__Host-sv_oauth=${correlation}`, referer: oauth.landingUrl }, body: { code: 'abc', state: started.state } };
  assert.equal((await oauth.complete({ ...right, member: member('1002') })).reason, 'wrong_member');
  assert.equal((await oauth.complete(right)).reason, 'unknown_state');
});

test('the memory store forgets expired records and stays bounded', () => {
  let clock = 0;
  const store = createMemoryStateStore({ maxEntries: 3, now: () => clock });
  const put = (state) => store.put({ state, created: clock });
  put('a');
  clock = 601_000;
  put('b');
  assert.equal(store.take('a'), null, 'expired and swept');
  put('c');
  put('d');
  put('e');
  assert.equal(store.take('b'), null, 'the oldest went to make room');
  assert.deepEqual(['c', 'd', 'e'].map((state) => store.take(state)?.state), ['c', 'd', 'e']);
  assert.equal(store.take('c'), null, 'taken once');
});

test('configuration that could point the page elsewhere is refused', () => {
  const base = { hostname: vectors.hostname, landingPath: '/oauth/callback', completionPath: 'complete' };
  for (const [name, options, message] of [
    ['upper-case hostname', { hostname: 'Smith-Helm.example.ts.net' }, /hostname/],
    ['relative landing path', { landingPath: 'oauth/callback' }, /landingPath/],
    ['landing path with a query', { landingPath: '/oauth/callback?x=1' }, /landingPath/],
    ['completion on another origin', { completionPath: 'https://evil.example/complete' }, /completionPath/],
    ['protocol-relative completion', { completionPath: '//evil.example/complete' }, /completionPath/],
    ['javascript: done path', { donePath: 'javascript:alert(1)' }, /donePath/],
    ['backslash done path', { donePath: '\\\\evil.example' }, /donePath/],
    ['a store without take', { store: { put() {} } }, /put\(record\) and take\(state\)/],
  ]) assert.throws(() => createOAuthFlow({ ...base, ...options }), message, name);
  assert.throws(() => flow().landing({ nonce: '"><script>' }), /nonce/);
});

// Runs the landing page's script against a stand-in for the browser: the address bar, history and fetch.
function runLanding(page, href, respond) {
  const script = page.body.match(/<script[^>]*>([\s\S]*)<\/script>/)[1];
  const url = new URL(href);
  const status = { textContent: page.body.match(/<p id="status">([^<]*)/)[1] };
  const calls = { fetches: [], replaced: null, history: [] };
  const sandbox = {
    URLSearchParams,
    JSON,
    document: { getElementById: () => status },
    history: { replaceState: (state, title, to) => { calls.history.push(to); url.search = ''; } },
    location: {
      get search() { return url.search; },
      get pathname() { return url.pathname; },
      replace: (to) => { calls.replaced = to; },
    },
    fetch: async (to, init) => { calls.fetches.push({ to, init, addressAtSend: url.href }); return respond(); },
  };
  vm.runInNewContext(script, sandbox);
  return new Promise((resolve) => setImmediate(() => setImmediate(() => resolve({ ...calls, status: status.textContent }))));
}

test('the landing page needs no cookie, strips the code from the address, posts it once, then moves on', async () => {
  const page = flow().landing();
  assert.equal(page.status, 200);
  assert.deepEqual(page.headers, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'referrer-policy': 'same-origin' });

  const ok = await runLanding(page, `https://${vectors.hostname}/oauth/callback?code=abc&state=xyz&scope=read`, () => ({ ok: true, json: async () => ({ ok: true }) }));
  assert.deepEqual(ok.history, ['/oauth/callback']);
  assert.equal(ok.fetches.length, 1);
  assert.equal(ok.fetches[0].to, 'complete');
  assert.equal(ok.fetches[0].addressAtSend, `https://${vectors.hostname}/oauth/callback`, 'the code is gone from the address, so not in the Referer');
  assert.deepEqual(JSON.parse(ok.fetches[0].init.body), { code: 'abc', state: 'xyz' });
  assert.equal(ok.fetches[0].init.method, 'POST');
  assert.equal(ok.fetches[0].init.credentials, 'same-origin');
  assert.equal(ok.fetches[0].init.headers['content-type'], 'application/json');
  assert.equal(ok.replaced, '../settings');

  const refused = await runLanding(page, `https://${vectors.hostname}/oauth/callback?code=abc&state=xyz`, () => ({ ok: false, status: 403, json: async () => ({ reason: 'expired' }) }));
  assert.equal(refused.replaced, null);
  assert.match(refused.status, /expired/);

  const reload = await runLanding(page, `https://${vectors.hostname}/oauth/callback`, () => assert.fail('nothing to send'));
  assert.equal(reload.fetches.length, 0);
  assert.match(reload.status, /Nothing to finish/);

  const denied = await runLanding(page, `https://${vectors.hostname}/oauth/callback?error=access_denied&state=xyz`, () => assert.fail('nothing to send'));
  assert.equal(denied.fetches.length, 0);
  assert.match(denied.status, /access_denied/);
});

test('the landing page can\'t be talked into another script or address', () => {
  const page = flow({ completionPath: 'a</script><script>alert(1)</script>', donePath: '/x' }).landing({ nonce: 'abc123' });
  assert.equal((page.body.match(/<script/g) || []).length, 1);
  assert.match(page.body, /<script nonce="abc123">/);
  assert.match(page.body, /a\\u003c\/script>\\u003cscript>alert\(1\)\\u003c\/script>/);
});

// How an app wires it: the completion route behind the mutation guard, which refuses a sibling hostname's
// post before the helper runs, so the post can't even use the state up.
test('a sibling hostname\'s post to the completion route never reaches the helper', async () => {
  const http = require('node:http');
  const { createRequestGuard, guardHttp } = require('..');
  const store = createMemoryStateStore();
  const oauth = flow({ store });
  const guardRequest = guardHttp(createRequestGuard({ origin: `https://${vectors.hostname}` }), { log: () => {} });
  const server = http.createServer((req, res) => {
    if (!guardRequest(req, res)) return;
    let text = '';
    req.on('data', (chunk) => { text += chunk; });
    req.on('end', async () => {
      const result = await oauth.complete({ member: member('1001'), headers: req.headers, body: JSON.parse(text) });
      res.writeHead(result.ok ? 200 : result.status, { 'content-type': 'application/json', 'set-cookie': result.clearCookie });
      res.end(JSON.stringify(result.ok ? { linked: true } : result.body));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const post = (headers, body) => new Promise((resolve, reject) => {
    const req = http.request(`http://127.0.0.1:${server.address().port}/oauth/complete`, { method: 'POST', headers }, (res) => {
      let text = '';
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(text) }));
    });
    req.on('error', reject);
    req.end(JSON.stringify(body));
  });
  try {
    const started = await oauth.start(member('1001'));
    const body = { code: 'abc', state: started.state };
    const cookie = started.setCookie.split(';')[0];
    const sibling = await post({ 'content-type': 'application/json', origin: 'https://smith-home.example-tailnet.ts.net', 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', cookie, referer: 'https://smith-home.example-tailnet.ts.net/' }, body);
    assert.equal(sibling.status, 403);
    assert.equal(sibling.body.error, 'request_refused');
    const own = await post({ 'content-type': 'application/json', origin: `https://${vectors.hostname}`, 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', cookie, referer: oauth.landingUrl }, body);
    assert.deepEqual(own, { status: 200, body: { linked: true } }, 'the state was still there for the real landing page');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
