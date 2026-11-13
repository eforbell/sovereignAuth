const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createWebAuthn } = require('..');
const { createResidentAuthenticator } = require('./support/resident-authenticator');

const rpID = 'example.ts.net';
const userId = '1001';
const handle = () => crypto.randomBytes(32).toString('base64url');
const request = (suite, userHandle, purpose = 'enroll') => ({ hostname: suite + '-homebase.' + rpID, member: { userId, userHandle }, purpose });
const origin = (context) => 'https://' + context.hostname;
const legacyHandle = Buffer.from(userId).toString('base64url');

async function enroll(service, key, context) {
  const options = await service.registrationOptions(context);
  const response = key.register(options, { origin: origin(context) });
  const result = await service.verifyRegistration({ ...context, response });
  assert.equal(result.ok, true, JSON.stringify(result));
  return { options, response, credential: result.credential };
}

async function startCheck(service, key, context, credential, settings = {}) {
  const request = { ...context, purpose: 'step-up' };
  const options = await service.authenticationOptions({ ...request, credentials: [credential] });
  return { request, response: key.authenticate(options, { origin: origin(context), ...settings }) };
}

async function check(service, key, context, credential, settings = {}) {
  const started = await startCheck(service, key, context, credential, settings);
  return service.verifyAuthentication({ ...started.request, response: started.response, credentials: [credential] });
}

test('strict handles let independent suites for the same identity retain one physical key', async () => {
  const a = createWebAuthn({ rpID, requireUserHandle: true });
  const b = createWebAuthn({ rpID, requireUserHandle: true });
  const alice = request('prod', handle());
  const rehearsal = request('rehearsal', handle());
  const key = createResidentAuthenticator();
  const first = await enroll(a, key, alice);
  const second = await enroll(b, key, rehearsal);
  assert.equal(first.options.user.id, alice.member.userHandle);
  assert.equal(second.options.user.id, rehearsal.member.userHandle);
  assert.equal(first.credential.userHandle, alice.member.userHandle);
  assert.equal(second.credential.userHandle, rehearsal.member.userHandle);
  for (const [service, context, credential] of [[a, alice, first.credential], [b, rehearsal, second.credential], [a, alice, first.credential]]) {
    assert.equal(key.hasCredential(credential.id), true);
    assert.equal((await check(service, key, context, credential)).ok, true);
  }
});

test('default callers preserve legacy bytes and return trusted expected-handle metadata', async () => {
  const service = createWebAuthn({ rpID });
  const key = createResidentAuthenticator();
  const context = request('legacy', undefined);
  const { options, credential } = await enroll(service, key, context);
  assert.equal(options.user.id, legacyHandle);
  assert.equal(credential.userHandle, legacyHandle);
  assert.equal((await check(service, key, context, credential)).ok, true);
});

test('strict registration requires explicit handles; malformed explicit values never fall back', async () => {
  const strict = createWebAuthn({ rpID, requireUserHandle: true });
  await assert.rejects(strict.registrationOptions(request('x', undefined)), /userHandle/);
  const invalid = [null, '', true, 0, 'AB', 'AA==', 'not base64!', Buffer.alloc(65).toString('base64url')];
  for (const service of [strict, createWebAuthn({ rpID })]) {
    for (const value of invalid) await assert.rejects(service.registrationOptions(request('x', value)), /userHandle/);
    for (const size of [1, 32, 64]) {
      const value = Buffer.alloc(size, 255).toString('base64url');
      const options = await service.registrationOptions(request('x', value));
      assert.equal(options.user.id, value);
    }
  }
  assert.throws(() => createWebAuthn({ rpID, requireUserHandle: 'false' }), /requireUserHandle/);
});

test('registration claims bind the resolved handle and ignore forged output metadata', async () => {
  const service = createWebAuthn({ rpID, requireUserHandle: true });
  const key = createResidentAuthenticator();
  const context = request('prod', handle());
  const options = await service.registrationOptions(context);
  const response = key.register(options, { origin: origin(context) });
  response.userHandle = handle();
  response.handle_format = 'legacy-v1';
  const changed = { ...context, member: { ...context.member, userHandle: handle() } };
  assert.equal((await service.verifyRegistration({ ...changed, response })).reason, 'wrong_user_handle');
  assert.equal((await service.verifyRegistration({ ...context, response })).reason, 'unknown_challenge');
  const freshOptions = await service.registrationOptions(context);
  const freshResponse = createResidentAuthenticator().register(freshOptions, { origin: origin(context) });
  freshResponse.userHandle = handle();
  freshResponse.handle_format = 'legacy-v1';
  const enrolled = await service.verifyRegistration({ ...context, response: freshResponse });
  assert.equal(enrolled.ok, true);
  assert.equal(enrolled.credential.userHandle, context.member.userHandle);
});

test('strict assertions use the selected credential expectation, not the current enrollment handle', async () => {
  const legacyService = createWebAuthn({ rpID });
  const strict = createWebAuthn({ rpID, requireUserHandle: true });
  const key = createResidentAuthenticator();
  const context = request('prod', undefined);
  const { credential } = await enroll(legacyService, key, context);
  const withNewHandle = request('prod', handle());
  assert.equal((await check(strict, key, withNewHandle, credential)).ok, true);
  for (const userHandle of [handle(), '', legacyHandle + '=']) {
    assert.equal((await check(strict, key, withNewHandle, credential, { userHandle })).reason, 'wrong_member');
  }
});

test('missing or corrupt candidate expectations refuse even an absent response handle', async () => {
  const service = createWebAuthn({ rpID, requireUserHandle: true });
  const context = request('prod', handle());
  const key = createResidentAuthenticator({ resident: false });
  const { credential } = await enroll(service, key, context);
  for (const value of [undefined, null, '', 'AB', 'AA==', true, Buffer.alloc(65).toString('base64url')]) {
    const started = await startCheck(service, key, context, credential);
    const broken = { ...credential, userHandle: value };
    const result = await service.verifyAuthentication({ ...started.request, response: started.response, credentials: [broken] });
    assert.equal(result.reason, 'invalid_credential_handle', String(value));
    assert.equal(result.update, undefined);
  }
  for (const settings of [{}, { userHandle: null }]) assert.equal((await check(service, key, context, credential, settings)).ok, true);
});

test('non-strict missing metadata is legacy-only, while explicit corrupt metadata always refuses', async () => {
  const service = createWebAuthn({ rpID });
  const context = request('prod', undefined);
  const key = createResidentAuthenticator();
  const { credential } = await enroll(service, key, context);
  const oldDescriptor = { ...credential };
  delete oldDescriptor.userHandle;
  assert.equal((await check(service, key, context, oldDescriptor)).ok, true);
  for (const value of [null, '', 'not base64!']) assert.equal((await check(service, key, context, { ...credential, userHandle: value })).reason, 'invalid_credential_handle');
});

test('credential ownership is checked before handle metadata, and handles cannot replace signatures', async () => {
  const service = createWebAuthn({ rpID, requireUserHandle: true });
  const context = request('prod', handle());
  const key = createResidentAuthenticator();
  const { credential } = await enroll(service, key, context);
  const started = await startCheck(service, key, context, credential);
  assert.equal((await service.verifyAuthentication({ ...started.request, response: started.response, credentials: [] })).reason, 'unknown_credential');
  const forged = await startCheck(service, key, context, credential);
  forged.response.response.signature = Buffer.alloc(64).toString('base64url');
  assert.equal((await service.verifyAuthentication({ ...forged.request, response: forged.response, credentials: [credential] })).reason, 'not_verified');
});
