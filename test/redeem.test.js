// The redemption client against a fake Home Base on a Unix socket (D19): only a clear yes redeems.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { createRedeemer, redemptionSocket } = require('..');

const REQUEST = { token: 'v1.payload.signature', policy: 'privileged-plan', target: 'backup 1', digest: 'abc' };

async function fakeHomeBase(t, handler) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-redeem-'));
  const socketPath = path.join(dir, 'family-pulse.sock');
  const seen = [];
  const sockets = new Set();
  const server = http.createServer((req, res) => {
    let text = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => { text += chunk; });
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, contentType: req.headers['content-type'], body: text ? JSON.parse(text) : null });
      handler(req, res);
    });
  });
  server.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  await new Promise((resolve) => server.listen(socketPath, resolve));
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return { socketPath, seen };
}

const answer = (status, body) => (req, res) => {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
};

test('the app redeems over its own socket, sending the token, policy, target and digest', async (t) => {
  const { socketPath, seen } = await fakeHomeBase(t, answer(200, { redeemed: true }));
  assert.deepEqual(await createRedeemer({ appId: 'family-pulse', socketPath })(REQUEST), { redeemed: true });
  assert.deepEqual(seen, [{ method: 'POST', url: '/v1/redeem', contentType: 'application/json', body: REQUEST }]);
  assert.equal(redemptionSocket('family-pulse'), '/run/sovereign-identity/family-pulse.sock');
  assert.throws(() => redemptionSocket('../etc/passwd'), /not an app ID/);
  assert.throws(() => createRedeemer({}), /not an app ID/);
});

test('Home Base\'s refusals keep their reason', async (t) => {
  for (const [status, reason] of [[409, 'replayed'], [403, 'not_authorized'], [400, 'invalid']]) {
    const { socketPath } = await fakeHomeBase(t, answer(status, { error: reason }));
    assert.deepEqual(await createRedeemer({ appId: 'family-pulse', socketPath })(REQUEST), { redeemed: false, reason }, String(status));
  }
});

test('anything but a clear yes is a refusal', async (t) => {
  const cases = [
    ['500', answer(500, { error: 'boom' })],
    ['200 without redeemed: true', answer(200, { redeemed: 'yes' })],
    ['200 that is not JSON', answer(200, 'redeemed')],
    ['a redirect', answer(302, {})],
    ['an oversized answer', answer(200, `{"redeemed":true,"pad":"${'x'.repeat(32 * 1024)}"}`)],
    ['the connection dropped mid-answer', (req, res) => { res.writeHead(200, { 'content-length': '100' }); res.write('{"redeemed":'); setTimeout(() => res.socket.destroy(), 10); }],
  ];
  for (const [name, handler] of cases) {
    const { socketPath } = await fakeHomeBase(t, handler);
    assert.deepEqual(await createRedeemer({ appId: 'family-pulse', socketPath })(REQUEST), { redeemed: false, reason: 'unavailable' }, name);
  }
});

test('no Home Base, or one that never answers, is a refusal within the timeout', async (t) => {
  const missing = path.join(os.tmpdir(), `sovereign-redeem-missing-${process.pid}.sock`);
  assert.deepEqual(await createRedeemer({ appId: 'family-pulse', socketPath: missing })(REQUEST), { redeemed: false, reason: 'unavailable' });

  const { socketPath } = await fakeHomeBase(t, () => {});
  const started = Date.now();
  assert.deepEqual(await createRedeemer({ appId: 'family-pulse', socketPath, timeoutMs: 200 })(REQUEST), { redeemed: false, reason: 'unavailable' });
  const took = Date.now() - started;
  assert.ok(took >= 190 && took < 2_000, `took ${took} ms`);

  // A Home Base that starts answering but never finishes is held to the same deadline.
  const slow = await fakeHomeBase(t, (req, res) => { res.writeHead(200); res.write('{"redeemed":'); });
  assert.deepEqual(await createRedeemer({ appId: 'family-pulse', socketPath: slow.socketPath, timeoutMs: 200 })(REQUEST), { redeemed: false, reason: 'unavailable' });
});
