const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { authMode, createIdentity, parseSnapshot } = require('..');

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vectors', 'snapshot.json'), 'utf8'));
const SNAPSHOT = parseSnapshot(vectors.snapshot);
const PARENT = { 'x-sovereign-user-id': '1001', 'x-sovereign-login': 'parent@example.com' };
const goodReader = { current: () => ({ ok: true, snapshot: SNAPSHOT }) };
const SOCKET = 'unix:/run/sovereign-apps/family-pulse/app.sock';

test('the mode is local or tailnet, and nothing else starts', () => {
  assert.equal(authMode('local'), 'local');
  assert.equal(authMode(' tailnet\n'), 'tailnet');
  for (const bad of [undefined, '', 'Tailnet', 'both', 'off', 'true']) assert.throws(() => authMode(bad), /local or tailnet/, String(bad));
});

test('tailnet mode refuses to start unless the app listens on its socket', () => {
  for (const listen of [undefined, '', '127.0.0.1:3000', 'unix:', 'unix:relative.sock']) {
    assert.throws(() => createIdentity({ appId: 'family-pulse', mode: 'tailnet', listen, reader: goodReader }), /SOVEREIGN_LISTEN/, String(listen));
  }
  assert.throws(() => createIdentity({ appId: 'family-pulse', mode: 'tailnet', listen: SOCKET }), /snapshot reader/);
  assert.throws(() => createIdentity({ mode: 'local' }), /app's ID/);
});

test('tailnet mode resolves the member from the snapshot', () => {
  const identity = createIdentity({ appId: 'family-pulse', mode: 'tailnet', listen: SOCKET, reader: goodReader });
  const result = identity.identify(PARENT);
  assert.equal(result.member.memberId, 'm_parent');
  assert.equal(result.snapshot, SNAPSHOT);
  assert.equal(identity.identify({ ...PARENT, 'x-sovereign-login': ['parent@example.com', 'parent@example.com'] }).reason, 'no_identity', 'a repeated header is not a login');
});

test('no snapshot means no member, with the snapshot\'s reason', () => {
  const identity = createIdentity({ appId: 'family-pulse', mode: 'tailnet', listen: SOCKET, reader: { current: () => ({ ok: false, reason: 'stale' }) } });
  assert.deepEqual(identity.identify(PARENT), { member: null, reason: 'no_snapshot', snapshotReason: 'stale', snapshot: null });
});

test('local mode ignores the identity headers and needs no socket or snapshot', () => {
  const identity = createIdentity({ appId: 'family-pulse', mode: 'local' });
  assert.deepEqual(identity.identify(PARENT), { member: null, reason: 'local_mode', snapshot: null });
});
