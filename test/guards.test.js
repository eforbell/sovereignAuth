const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createRequestGuard, guardExpress, guardHttp, normalizeOrigin } = require('..');

const ORIGIN = 'https://homebase.example-tailnet.ts.net';
const SIBLING = 'https://home.example-tailnet.ts.net';
const SAME_ORIGIN_JSON = { origin: ORIGIN, 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty', 'content-type': 'application/json' };
const SIBLING_FORM = { origin: SIBLING, 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document', 'content-type': 'text/plain' };

test('origins are normalized once, and anything that is not an origin is refused at configuration', () => {
  assert.equal(normalizeOrigin('https://HomeBase.example-tailnet.ts.net/'), ORIGIN);
  assert.equal(normalizeOrigin('https://homebase.example-tailnet.ts.net:443'), ORIGIN);
  for (const bad of ['homebase.example-tailnet.ts.net', 'https://homebase.example-tailnet.ts.net/admin', 'https://a@homebase.example-tailnet.ts.net', 'https://homebase.example-tailnet.ts.net/?x=1', 'ftp://homebase.example-tailnet.ts.net', '']) {
    assert.throws(() => normalizeOrigin(bad), /origin/, bad);
  }
  assert.throws(() => createRequestGuard({}), /origin/);
  assert.throws(() => createRequestGuard({ origin: [] }), /origin/);
  assert.throws(() => createRequestGuard({ origin: ORIGIN, contentTypes: [] }), /content type/);
});

test('a guard accepts any of several origins, compared exactly', () => {
  const guard = createRequestGuard({ origin: [ORIGIN, 'https://host.example-tailnet.ts.net'] });
  assert.equal(guard.check({ method: 'POST', headers: SAME_ORIGIN_JSON }).allowed, true);
  assert.equal(guard.check({ method: 'POST', headers: { ...SAME_ORIGIN_JSON, origin: 'https://host.example-tailnet.ts.net' } }).allowed, true);
  assert.equal(guard.check({ method: 'POST', headers: { ...SAME_ORIGIN_JSON, origin: SIBLING } }).reason, 'origin_mismatch');
  assert.deepEqual(guard.origins, [ORIGIN, 'https://host.example-tailnet.ts.net']);
});

test('isolation is on unless turned off, and methods are compared case-insensitively', () => {
  assert.equal(createRequestGuard({ origin: ORIGIN }).isolate, true);
  const guard = createRequestGuard({ origin: ORIGIN });
  assert.equal(guard.check({ method: 'post', headers: { ...SAME_ORIGIN_JSON, 'content-type': 'text/plain' } }).reason, 'content_type');
  assert.equal(guard.check({ method: 'get', headers: { 'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' } }).allowed, true);
});

test('a header Node gives as a list counts as several values, so it is malformed', () => {
  const guard = createRequestGuard({ origin: ORIGIN });
  assert.equal(guard.check({ method: 'GET', headers: { 'sec-fetch-site': ['same-origin', 'same-origin'] } }).reason, 'fetch_metadata_malformed');
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

// node:http, not fetch: fetch replaces Sec-Fetch-Mode with its own, so it can't send a navigation.
function post(base, headers, path = '/api/change?code=secret') {
  return new Promise((resolve, reject) => {
    const req = http.request(`${base}${path}`, { method: 'POST', headers }, (res) => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(text), cacheControl: res.headers['cache-control'] ?? null }));
    });
    req.on('error', reject);
    req.end('{}');
  });
}

test('guardHttp enforces: a refused request gets the 403 refusal body and never reaches the handler', async () => {
  const logs = [];
  let reached = 0;
  const guardRequest = guardHttp(createRequestGuard({ origin: ORIGIN }), { log: (line) => logs.push(line) });
  await withServer((req, res) => {
    if (!guardRequest(req, res)) return;
    reached += 1;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"ok":true}');
  }, async (base) => {
    assert.deepEqual(await post(base, SAME_ORIGIN_JSON), { status: 200, body: { ok: true }, cacheControl: null });
    const refused = await post(base, SIBLING_FORM);
    assert.equal(refused.status, 403);
    assert.equal(refused.cacheControl, 'no-store');
    assert.deepEqual(Object.keys(refused.body), ['error', 'reason', 'message']);
    assert.equal(refused.body.error, 'request_refused');
    assert.equal(refused.body.reason, 'not_same_origin');
  });
  assert.equal(reached, 1);
  assert.equal(logs.length, 1);
  assert.match(logs[0], /^\[sovereign-auth\] refused POST \/api\/change: not_same_origin \(origin https:\/\/home\.example-tailnet\.ts\.net, sec-fetch-site same-site\)$/);
  assert.doesNotMatch(logs[0], /secret/, 'the query is never logged');
});

test('guardHttp reports: the refusal is logged and the request goes on; off is silent', async () => {
  for (const [mode, expectedLogs] of [['report', 1], ['off', 0]]) {
    const logs = [];
    const guardRequest = guardHttp(createRequestGuard({ origin: ORIGIN }), { mode, log: (line) => logs.push(line) });
    await withServer((req, res) => {
      if (!guardRequest(req, res)) return;
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    }, async (base) => {
      assert.equal((await post(base, SIBLING_FORM)).status, 200, mode);
    });
    assert.equal(logs.length, expectedLogs, mode);
    if (expectedLogs) assert.match(logs[0], /would refuse POST/);
  }
});

function get(base, headers, path = '/app.js') {
  return new Promise((resolve, reject) => {
    const req = http.request(`${base}${path}`, { headers }, (res) => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode, vary: res.headers.vary ?? null }));
    });
    req.on('error', reject);
    req.end();
  });
}

const SAME_ORIGIN_SCRIPT = { 'sec-fetch-site': 'same-origin', 'sec-fetch-mode': 'no-cors', 'sec-fetch-dest': 'script' };
const SIBLING_SCRIPT = { ...SAME_ORIGIN_SCRIPT, 'sec-fetch-site': 'same-site' };
const VARY = 'Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest';

// A response cached for the app's own page must not be served to a sibling's <script> without asking the app.
test('an isolating guard makes every response vary on fetch metadata, so the browser cache cannot skip it', async () => {
  const serve = (guardRequest, appVary) => (req, res) => {
    if (appVary) res.setHeader('Vary', appVary);
    if (!guardRequest(req, res)) return;
    res.writeHead(200, { 'content-type': 'text/javascript', 'cache-control': 'public, max-age=300' });
    res.end('');
  };
  for (const mode of ['enforce', 'report']) {
    const guardRequest = guardHttp(createRequestGuard({ origin: ORIGIN }), { mode, log: () => {} });
    await withServer(serve(guardRequest), async (base) => {
      assert.deepEqual(await get(base, SAME_ORIGIN_SCRIPT), { status: 200, vary: VARY }, mode);
      assert.deepEqual(await get(base, SIBLING_SCRIPT), { status: mode === 'enforce' ? 403 : 200, vary: VARY }, mode);
    });
  }
  const guardRequest = guardHttp(createRequestGuard({ origin: ORIGIN }), { log: () => {} });
  await withServer(serve(guardRequest, 'Accept-Encoding, sec-fetch-site'), async (base) => {
    assert.equal((await get(base, SAME_ORIGIN_SCRIPT)).vary, 'Accept-Encoding, sec-fetch-site, Sec-Fetch-Mode, Sec-Fetch-Dest', 'kept, and not repeated');
  });
  await withServer(serve(guardRequest, '*'), async (base) => {
    assert.equal((await get(base, SAME_ORIGIN_SCRIPT)).vary, '*', 'already varies on everything');
  });
});

test('no Vary is added when nothing depends on fetch metadata: guard off, or isolation off', async () => {
  const cases = [
    ['off', createRequestGuard({ origin: ORIGIN })],
    ['enforce', createRequestGuard({ origin: ORIGIN, isolate: false })],
  ];
  for (const [mode, guard] of cases) {
    const guardRequest = guardHttp(guard, { mode, log: () => {} });
    await withServer((req, res) => {
      if (!guardRequest(req, res)) return;
      res.writeHead(200);
      res.end();
    }, async (base) => {
      assert.deepEqual(await get(base, SIBLING_SCRIPT), { status: 200, vary: null }, `${mode}, isolate ${guard.isolate}`);
    });
  }
});

test('an unknown mode is a configuration error, not a quiet fallback', () => {
  const guard = createRequestGuard({ origin: ORIGIN });
  for (const mode of ['enforced', 'on', '', 'ENFORCE', null]) {
    assert.throws(() => guardHttp(guard, { mode }), /off, report or enforce/);
    assert.throws(() => guardExpress(guard, { mode }), /off, report or enforce/);
  }
});

test('guardExpress calls next only for allowed requests, in every mode', () => {
  const guard = createRequestGuard({ origin: ORIGIN });
  const run = (mode, headers) => {
    const sent = [];
    let nexts = 0;
    const headers_ = {};
    const res = {
      getHeader: (name) => headers_[name.toLowerCase()],
      setHeader: (name, value) => { headers_[name.toLowerCase()] = value; },
      writeHead: (status, h) => sent.push({ status, h }),
      end: (body) => sent.push({ body }),
    };
    guardExpress(guard, { mode, log: () => {} })({ method: 'POST', url: '/x', headers }, res, () => { nexts += 1; });
    return { nexts, sent, vary: headers_.vary };
  };
  assert.deepEqual(run('enforce', SAME_ORIGIN_JSON), { nexts: 1, sent: [], vary: VARY });
  const refused = run('enforce', SIBLING_FORM);
  assert.equal(refused.nexts, 0);
  assert.equal(refused.vary, VARY);
  assert.equal(refused.sent[0].status, 403);
  assert.equal(JSON.parse(refused.sent[1].body).reason, 'not_same_origin');
  assert.deepEqual(run('report', SIBLING_FORM), { nexts: 1, sent: [], vary: VARY });
  assert.deepEqual(run('off', SIBLING_FORM), { nexts: 1, sent: [], vary: undefined });
});
