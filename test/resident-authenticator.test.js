const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createWebAuthn } = require('..');
const { createResidentAuthenticator } = require('./support/resident-authenticator');

const rpID = 'example.ts.net';
const member = { userId: '1001', login: 'parent@example.com' };
const request = (suite, purpose = 'enroll') => ({ hostname: suite + '-homebase.' + rpID, member, purpose });
const options = (user, rp = rpID) => ({ rp: { id: rp }, user: { id: Buffer.from(user).toString('base64url') }, challenge: crypto.randomBytes(32).toString('base64url') });
const assertion = (ids, rp = rpID) => ({ rpId: rp, allowCredentials: ids.map((id) => ({ id })), challenge: crypto.randomBytes(32).toString('base64url') });

async function enroll(service, key, suite) {
  const context = request(suite);
  const generated = await service.registrationOptions(context);
  const result = await service.verifyRegistration({ ...context, response: key.register(generated, { origin: 'https://' + context.hostname }) });
  assert.equal(result.ok, true, JSON.stringify(result));
  return result.credential;
}

async function check(service, key, suite, credential) {
  const context = request(suite, 'step-up');
  const generated = await service.authenticationOptions({ ...context, credentials: [credential] });
  return service.verifyAuthentication({ ...context, credentials: [credential], response: key.authenticate(generated, { origin: 'https://' + context.hostname }) });
}

test('characterizes the incident: independent services with one RP/user replace the earlier resident key', async () => {
  const a = createWebAuthn({ rpID });
  const b = createWebAuthn({ rpID });
  const key = createResidentAuthenticator();
  const first = await enroll(a, key, 'prod');
  assert.equal((await check(a, key, 'prod', first)).ok, true);
  const second = await enroll(b, key, 'rehearsal');
  assert.notEqual(first.id, second.id);
  assert.notEqual(first.publicKey, second.publicKey);
  assert.equal(key.hasCredential(first.id), false);
  await assert.rejects(check(a, key, 'prod', first), { name: 'NotAllowedError' });
  assert.equal((await check(b, key, 'rehearsal', second)).ok, true);
});

test('different raw user handles coexist on a resident authenticator under the same RP', () => {
  const key = createResidentAuthenticator();
  const first = key.register(options('suite-a'), { origin: 'https://a.' + rpID });
  const second = key.register(options('suite-b'), { origin: 'https://b.' + rpID });
  for (const [response, user] of [[first, 'suite-a'], [second, 'suite-b']]) {
    const answer = key.authenticate(assertion([response.id]), { origin: 'https://a.' + rpID });
    assert.equal(answer.id, response.id);
    assert.equal(answer.response.userHandle, Buffer.from(user).toString('base64url'));
  }
});

test('exclusions match only held IDs on the same RP, not overwritten IDs', () => {
  const key = createResidentAuthenticator();
  const first = key.register(options('same'), { origin: 'https://a.' + rpID });
  assert.throws(() => key.register({ ...options('other'), excludeCredentials: [{ id: first.id }] }), { name: 'InvalidStateError' });
  const second = key.register(options('same'), { origin: 'https://b.' + rpID });
  const third = key.register({ ...options('isolated'), excludeCredentials: [{ id: first.id }] });
  assert.equal(key.hasCredential(second.id), true);
  assert.equal(key.hasCredential(third.id), true);
  const otherRP = key.register({ ...options('same', 'other.ts.net'), excludeCredentials: [{ id: second.id }] });
  assert.equal(key.hasCredential(second.id), true);
  assert.equal(key.hasCredential(otherRP.id), true);
});

test('assertions cannot use another RP or an unheld allow-list ID', () => {
  const key = createResidentAuthenticator();
  const registered = key.register(options('user'));
  assert.throws(() => key.authenticate(assertion([registered.id], 'other.ts.net')), { name: 'NotAllowedError' });
  assert.throws(() => key.authenticate(assertion(['unknown'])), { name: 'NotAllowedError' });
  assert.equal(key.authenticate(assertion([])).id, registered.id);
});

test('non-discoverable credentials do not replace the same user, require an allow-list, and omit handles', () => {
  const key = createResidentAuthenticator({ resident: false });
  const first = key.register(options('same'));
  const second = key.register(options('same'));
  assert.equal(key.hasCredential(first.id), true);
  assert.equal(key.hasCredential(second.id), true);
  assert.throws(() => key.authenticate(assertion([])), { name: 'NotAllowedError' });
  assert.equal(Object.hasOwn(key.authenticate(assertion([first.id])).response, 'userHandle'), false);
  assert.equal(key.authenticate(assertion([second.id]), { userHandle: null }).response.userHandle, null);
  assert.throws(() => key.register({ ...options('x'), authenticatorSelection: { residentKey: 'required' } }), { name: 'NotSupportedError' });
});
