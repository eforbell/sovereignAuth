const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {
  AppAttestError,
  appInstanceClientData,
  appInstanceReason,
  createHandoff,
  createMemoryHandoffStore,
  handoffClientData,
  handoffCookie,
  verifyAttestation,
} = require('..');
const { createFakeApple } = require('./support/appattest');

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vectors', 'handoff.json'), 'utf8'));
const APP_ID = vectors.app_id;
const H = vectors.base.hostname;

// Applies "x_set" changes: a null value removes the field.
function changed(base, changes = {}) {
  const result = structuredClone(base);
  for (const [key, value] of Object.entries(changes)) {
    if (value === null) delete result[key];
    else result[key] = structuredClone(value);
  }
  return result;
}

function memoryInstances(list = []) {
  const keys = new Map(list.map((instance) => [instance.keyId, { ...instance }]));
  return {
    keys,
    get: (keyId) => (keys.has(keyId) ? { ...keys.get(keyId) } : null),
    advance(keyId, from, to) {
      const stored = keys.get(keyId);
      if (!stored || stored.counter !== from) return false;
      stored.counter = to;
      return true;
    },
  };
}

test('handoff vectors', async (t) => {
  for (const vector of vectors.cases) {
    await t.test(vector.name, async () => {
      const now = () => vectors.now;
      const store = createMemoryHandoffStore({ now });
      const record = vector.record === null ? null : changed(vectors.base.record, vector.record_set);
      if (record) store.put(record);
      const instance = changed(vectors.base.instance, vector.instance_set);
      const instances = memoryInstances([instance]);
      const handoff = createHandoff({ appId: APP_ID, scheme: vectors.scheme, store, instances, now });
      const member = vector.member === undefined ? vectors.base.member : vector.member;
      const calls = { issue: 0, verify: 0 };
      const request = {
        member: member === null ? null : { userId: member },
        hostname: vector.hostname || H,
        headers: changed(vectors.base.headers, vector.headers_set),
        body: vector.body || changed(vectors.base.body[vector.step], vector.body_set),
        issue: async () => { calls.issue += 1; return { challenge: vectors.issued_challenge }; },
        verify: async () => { calls.verify += 1; return vector.verify || { ok: true, result: 'token' }; },
      };
      const answer = await handoff[vector.step](request);
      const { expect } = vector;
      assert.equal(answer.ok, expect.ok, JSON.stringify(answer.body));
      if (!expect.ok) {
        assert.equal(answer.status, expect.status);
        assert.deepEqual(answer.body, { error: expect.error, reason: expect.reason });
      }
      // A refused handoff never reaches the ceremony: no challenge issued, no assertion verified, no token minted.
      if (expect.error === 'handoff_refused') assert.deepEqual(calls, { issue: 0, verify: 0 });
      if (expect.return) assert.deepEqual(answer.body, { return: expect.return });
      if (expect.result) assert.deepEqual(answer.result, expect.result);
      if (vector.step === 'redeem' && expect.reason !== 'malformed') assert.equal(answer.clearCookie, vectors.cookies[0].clear_cookie);
      const after = record && store.get(record.id);
      assert.equal(after ? after.state : null, expect.state);
      if (expect.challenge) assert.equal(after.challenge, expect.challenge);
      if (expect.instance_counter !== undefined) assert.equal(instances.keys.get(instance.keyId).counter, expect.instance_counter);
    });
  }
});

test('the vectors cover every refusal reason of every step', () => {
  const seen = (step, error) => new Set(vectors.cases.filter((vector) => vector.step === step && vector.expect.error === error).map((vector) => vector.expect.reason));
  const common = ['expired', 'malformed', 'unknown_handoff', 'wrong_hostname', 'wrong_member'];
  assert.deepEqual([...seen('attest', 'handoff_refused')].sort(), [...common, 'not_pending'].sort());
  assert.deepEqual([...seen('attest', 'app_instance_refused')].sort(), ['bad_signature', 'counter_not_increasing', 'malformed', 'unknown_key', 'wrong_app', 'wrong_member']);
  assert.deepEqual([...seen('options', 'handoff_refused')].sort(), [...common, 'not_attested'].sort());
  assert.deepEqual([...seen('finish', 'handoff_refused')].sort(), [...common, 'not_attested', 'stale_challenge'].sort());
  assert.deepEqual([...seen('redeem', 'handoff_refused')].sort(), [...common, 'duplicate_cookie', 'no_cookie', 'not_done', 'wrong_correlation'].sort());
  for (const step of ['attest', 'options', 'finish', 'redeem']) {
    assert.ok(vectors.cases.some((vector) => vector.step === step && vector.expect.ok), `${step} has a valid case`);
  }
});

test('client data and cookies match the vectors', () => {
  const [handoff, instance] = vectors.client_data;
  const text = handoffClientData(handoff.hostname, handoff.id);
  assert.equal(text.toString('utf8'), handoff.text);
  assert.equal(crypto.createHash('sha256').update(text).digest('base64'), handoff.sha256);
  const registering = appInstanceClientData({ household: instance.household, userId: instance.user_id, challenge: instance.challenge });
  assert.equal(registering.toString('utf8'), instance.text);
  assert.equal(crypto.createHash('sha256').update(registering).digest('base64'), instance.sha256);
  const [cookie] = vectors.cookies;
  assert.deepEqual(handoffCookie({ cookie: `${cookie.name}=x` }, cookie.id), { value: 'x', reason: null });
  assert.deepEqual(handoffCookie({ cookie: `${cookie.name}=` }, cookie.id), { value: '', reason: null });
});

test('client data refuses what could be read two ways', () => {
  assert.throws(() => handoffClientData('Smith-Home.example.ts.net', vectors.base.record.id), /lower case/);
  assert.throws(() => handoffClientData(`${H}\nx`, vectors.base.record.id), /lower case/);
  assert.throws(() => handoffClientData(H, 'IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIF'), /32 bytes/);
  assert.throws(() => appInstanceClientData({ household: 'smith', userId: '1001\nsmith', challenge: 'x' }), /no line breaks/);
  assert.throws(() => appInstanceClientData({ household: 'smith', userId: '', challenge: 'x' }), /no line breaks/);
});

test('App Attest refusals map to wire reasons', () => {
  const reason = (code) => appInstanceReason(new AppAttestError(code, 'x'));
  assert.equal(reason('malformed'), 'malformed');
  assert.equal(reason('format'), 'malformed');
  assert.equal(reason('app_id'), 'wrong_app');
  assert.equal(reason('receipt_app_id'), 'wrong_app');
  assert.equal(reason('environment'), 'wrong_environment');
  assert.equal(reason('signature'), 'bad_signature');
  for (const code of ['chain', 'nonce', 'key', 'counter', 'receipt', 'receipt_chain', 'receipt_signer', 'receipt_signature', 'receipt_key', 'receipt_client', 'receipt_time']) {
    assert.equal(reason(code), 'untrusted_attestation', code);
  }
  assert.equal(appInstanceReason(new Error('boom')), 'malformed');
});

test('createHandoff needs its settings', () => {
  const instances = memoryInstances();
  assert.throws(() => createHandoff({ scheme: 'homebase', instances }), /TEAMID/);
  assert.throws(() => createHandoff({ appId: APP_ID, scheme: 'HB', instances }), /callback scheme/);
  assert.throws(() => createHandoff({ appId: APP_ID, scheme: 'homebase' }), /get and advance/);
  assert.throws(() => createHandoff({ appId: APP_ID, scheme: 'homebase', instances, store: { put() {}, take() {} } }), /put, get, update and take/);
  assert.equal(createHandoff({ appId: APP_ID, scheme: 'homebase', instances }).returnUrl, 'homebase://sovereign-auth/done');
});

test('begin stores a pending record and sets its own cookie', async () => {
  const now = () => 1000;
  const store = createMemoryHandoffStore({ now });
  const handoff = createHandoff({ appId: APP_ID, scheme: 'homebase', store, instances: memoryInstances(), now });
  const member = { userId: '1001' };
  const first = await handoff.begin({ member, hostname: H, purpose: 'check', policy: 'open-admin', kind: 'any', data: { app: 'home-base' } });
  const second = await handoff.begin({ member, hostname: H, purpose: 'action', policy: 'restore-backup', kind: 'hardware', action: { target: 'nightly', digest: 'd'.repeat(43) } });
  assert.match(first.id, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(first.id, second.id);
  assert.deepEqual(first.body, { id: first.id });
  const record = store.get(first.id);
  assert.deepEqual({ ...record, id: undefined, correlation: undefined }, {
    id: undefined, correlation: undefined, userId: '1001', hostname: H, purpose: 'check', policy: 'open-admin', kind: 'any',
    action: null, data: { app: 'home-base' }, created: 1000, state: 'pending', keyId: null, challenge: null, result: null,
  });
  assert.equal(first.setCookie, `__Host-sv_handoff_${first.id.slice(0, 16)}=${record.correlation}; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age=300`);
  assert.notEqual(first.setCookie.split('=')[0], second.setCookie.split('=')[0]);
  assert.deepEqual(store.get(second.id).action, { target: 'nightly', digest: 'd'.repeat(43) });
});

test('begin refuses what Home Base should never pass', async () => {
  const handoff = createHandoff({ appId: APP_ID, scheme: 'homebase', instances: memoryInstances() });
  const good = { member: { userId: '1001' }, hostname: H, purpose: 'check', policy: 'open-admin', kind: 'any' };
  await assert.rejects(handoff.begin({ ...good, member: null }), /for a member/);
  await assert.rejects(handoff.begin({ ...good, hostname: 'Smith-Home.example.ts.net' }), /lower case/);
  await assert.rejects(handoff.begin({ ...good, purpose: 'activate' }), /a check, an action or an enrollment/);
  await assert.rejects(handoff.begin({ ...good, purpose: 'enroll', action: { target: 'x', digest: 'd'.repeat(43) } }), /an enrollment has no action/);
  await assert.rejects(handoff.begin({ ...good, policy: '' }), /names its policy/);
  await assert.rejects(handoff.begin({ ...good, kind: 'synced' }), /any or hardware/);
  await assert.rejects(handoff.begin({ ...good, action: { target: 'x', digest: 'd'.repeat(43) } }), /a check has no action/);
  await assert.rejects(handoff.begin({ ...good, purpose: 'action' }), /target, digest/);
  await assert.rejects(handoff.begin({ ...good, purpose: 'action', action: { target: 'a\nb', digest: 'd'.repeat(43) } }), /target, digest/);
  await assert.rejects(handoff.begin({ ...good, purpose: 'action', action: { target: 'x', digest: 'short' } }), /target, digest/);
});

test('the memory store hands out copies and never brings back a taken record', () => {
  const store = createMemoryHandoffStore();
  const put = { id: 'a', created: Date.now(), state: 'pending', action: { target: 'x' } };
  store.put(put);
  put.state = 'done';
  put.action.target = 'z';
  const read = store.get('a');
  read.state = 'done';
  read.action.target = 'y';
  assert.equal(store.get('a').state, 'pending');
  assert.equal(store.get('a').action.target, 'x');
  assert.equal(store.update('a', { state: 'attested' }, { state: 'done' }), false);
  assert.equal(store.update('a', { state: 'pending' }, { state: 'attested' }), true);
  assert.equal(store.take('a').state, 'attested');
  assert.equal(store.take('a'), null);
  assert.equal(store.update('a', {}, { state: 'done' }), false);
  assert.equal(store.get('a'), null);
});

test('the memory store forgets records older than five minutes', () => {
  let clock = 0;
  const store = createMemoryHandoffStore({ now: () => clock });
  store.put({ id: 'old', created: 0 });
  clock = 300001;
  store.put({ id: 'new', created: clock });
  assert.equal(store.get('old'), null);
  assert.ok(store.get('new'));
});

// The whole flow, with a fake Apple: register an app instance, then begin, attest, options, finish, redeem.
async function setUp() {
  const apple = await createFakeApple({ appId: APP_ID });
  const challenge = crypto.randomBytes(32).toString('base64url');
  const clientData = appInstanceClientData({ household: 'smith', userId: '1001', challenge });
  const registration = await apple.attest({ clientData });
  const verified = verifyAttestation({ attestation: registration.attestation, keyId: registration.keyId, clientData, appId: APP_ID, issuedAt: new Date(Date.now() - 1000), roots: apple.roots });
  const instances = memoryInstances([{ keyId: verified.keyId, userId: '1001', publicKey: verified.publicKey, counter: verified.counter }]);
  const store = createMemoryHandoffStore();
  const handoff = createHandoff({ appId: APP_ID, scheme: 'homebase', store, instances });
  const member = { userId: '1001' };
  const started = await handoff.begin({ member, hostname: H, purpose: 'check', policy: 'open-admin', kind: 'any' });
  const cookie = started.setCookie.split(';')[0];
  const attestBody = (id = started.id) => ({ id, keyId: verified.keyId, assertion: apple.assert(registration.device, { clientData: handoffClientData(H, id) }) });
  let issued = 0;
  const issue = async () => ({ challenge: `challenge-${++issued}` });
  const sheet = (challenge) => ({ id: started.id, assertion: { id: 'credential-1', response: { clientDataJSON: Buffer.from(JSON.stringify({ challenge })).toString('base64url') } } });
  return { apple, registration, verified, instances, store, handoff, member, started, cookie, attestBody, issue, sheet };
}

test('a handoff runs end to end once', async () => {
  const { handoff, member, started, cookie, attestBody, issue, sheet, store } = await setUp();
  assert.equal((await handoff.attest({ member, hostname: H, body: attestBody() })).ok, true);
  const options = await handoff.options({ member, hostname: H, body: { id: started.id }, issue });
  assert.equal(options.ok, true);
  assert.equal(options.options.challenge, 'challenge-1');
  assert.equal(options.record.policy, 'open-admin');
  assert.equal(options.record.correlation, undefined);
  let seen;
  const finished = await handoff.finish({ member, hostname: H, body: sheet('challenge-1'), verify: async (record, assertion) => { seen = { record, assertion }; return { ok: true, result: 'assurance-token' }; } });
  assert.deepEqual(finished, { ok: true, body: { return: 'homebase://sovereign-auth/done' } });
  assert.equal(seen.record.id, started.id);
  assert.equal(seen.record.correlation, undefined);
  assert.equal(seen.assertion.id, 'credential-1');
  const redeemed = await handoff.redeem({ member, hostname: H, headers: { cookie }, body: { id: started.id } });
  assert.equal(redeemed.ok, true);
  assert.equal(redeemed.result, 'assurance-token');
  assert.equal(redeemed.purpose, 'check');
  assert.match(redeemed.clearCookie, /Max-Age=0$/);
  assert.equal(store.get(started.id), null);
  const again = await handoff.redeem({ member, hostname: H, headers: { cookie }, body: { id: started.id } });
  assert.equal(again.reason, 'unknown_handoff');
});

test('the app\'s assertion counts once, and a racing one by the same key loses', async () => {
  const { apple, registration, handoff, member, started, instances, verified } = await setUp();
  const second = await handoff.begin({ member, hostname: H, purpose: 'check', policy: 'open-admin', kind: 'any' });
  const one = { id: started.id, keyId: verified.keyId, assertion: apple.assert(registration.device, { clientData: handoffClientData(H, started.id) }) };
  const two = { id: second.id, keyId: verified.keyId, assertion: apple.assert(registration.device, { clientData: handoffClientData(H, second.id), counter: 1 }) };
  const results = await Promise.all([handoff.attest({ member, hostname: H, body: one }), handoff.attest({ member, hostname: H, body: two })]);
  assert.deepEqual(results.map((result) => result.ok), [true, false]);
  assert.equal(results[1].reason, 'counter_not_increasing');
  assert.equal(instances.keys.get(verified.keyId).counter, 1);
  // The same assertion again is a replay.
  const replay = await handoff.attest({ member, hostname: H, body: one });
  assert.equal(replay.reason, 'not_pending');
});

test('a lost compare-and-swap on the key refuses the attest', async () => {
  const { handoff, member, instances, attestBody } = await setUp();
  instances.advance = async () => false;
  const result = await handoff.attest({ member, hostname: H, body: attestBody() });
  assert.equal(result.body.error, 'app_instance_refused');
  assert.equal(result.reason, 'counter_not_increasing');
});

test('options during a finish are refused: one record, one verify', async () => {
  const { handoff, member, started, attestBody, issue, sheet, store } = await setUp();
  await handoff.attest({ member, hostname: H, body: attestBody() });
  await handoff.options({ member, hostname: H, body: { id: started.id }, issue });
  let late;
  const finished = await handoff.finish({
    member,
    hostname: H,
    body: sheet('challenge-1'),
    verify: async (record) => {
      assert.equal(record.state, 'finishing');
      late = await handoff.options({ member, hostname: H, body: { id: started.id }, issue });
      return { ok: true, result: 'token' };
    },
  });
  assert.equal(late.reason, 'not_attested');
  assert.equal(finished.ok, true);
  assert.equal(store.get(started.id).state, 'done');
  assert.equal(store.get(started.id).challenge, 'challenge-1');
});

test('two finishes at once verify once', async () => {
  const { handoff, member, started, attestBody, issue, sheet, store } = await setUp();
  await handoff.attest({ member, hostname: H, body: attestBody() });
  await handoff.options({ member, hostname: H, body: { id: started.id }, issue });
  let verified = 0;
  const verify = async () => { verified += 1; await new Promise((resolve) => setImmediate(resolve)); return { ok: true, result: 'enrolled' }; };
  const answers = await Promise.all([1, 2].map(() => handoff.finish({ member, hostname: H, body: sheet('challenge-1'), verify })));
  assert.equal(verified, 1);
  assert.deepEqual(answers.map((answer) => answer.ok).sort(), [false, true]);
  assert.equal(answers.find((answer) => !answer.ok).reason, 'not_attested');
  assert.equal(store.get(started.id).state, 'done');
});

test('a refused verify leaves the record finishing: the challenge had its one attempt', async () => {
  const { handoff, member, started, attestBody, issue, sheet, store } = await setUp();
  await handoff.attest({ member, hostname: H, body: attestBody() });
  await handoff.options({ member, hostname: H, body: { id: started.id }, issue });
  const refusal = { ok: false, status: 403, body: { error: 'step_up_refused', reason: 'not_verified' }, reason: 'not_verified' };
  assert.deepEqual(await handoff.finish({ member, hostname: H, body: sheet('challenge-1'), verify: async () => refusal }), refusal);
  assert.equal(store.get(started.id).state, 'finishing');
  assert.equal((await handoff.options({ member, hostname: H, body: { id: started.id }, issue })).reason, 'not_attested');
  assert.equal((await handoff.finish({ member, hostname: H, body: sheet('challenge-1'), verify: async () => ({ ok: true, result: 'token' }) })).reason, 'not_attested');
});

test('options that lose to a finish leave the finished record alone', async () => {
  const { handoff, member, started, attestBody, issue, sheet, store } = await setUp();
  await handoff.attest({ member, hostname: H, body: attestBody() });
  await handoff.options({ member, hostname: H, body: { id: started.id }, issue });
  const late = await handoff.options({
    member,
    hostname: H,
    body: { id: started.id },
    issue: async () => {
      await handoff.finish({ member, hostname: H, body: sheet('challenge-1'), verify: async () => ({ ok: true, result: 'token' }) });
      return { challenge: 'challenge-late' };
    },
  });
  assert.equal(late.reason, 'not_attested');
  assert.equal(store.get(started.id).state, 'done');
  assert.equal(store.get(started.id).challenge, 'challenge-1');
});

test('two finishes on one challenge: one wins', async () => {
  const { handoff, member, started, attestBody, issue, sheet } = await setUp();
  await handoff.attest({ member, hostname: H, body: attestBody() });
  await handoff.options({ member, hostname: H, body: { id: started.id }, issue });
  const verify = async () => ({ ok: true, result: 'token' });
  const results = await Promise.all([
    handoff.finish({ member, hostname: H, body: sheet('challenge-1'), verify }),
    handoff.finish({ member, hostname: H, body: sheet('challenge-1'), verify }),
  ]);
  assert.deepEqual(results.map((result) => result.ok).sort(), [false, true]);
  assert.equal(results.find((result) => !result.ok).reason, 'not_attested');
});

test('a redeem during a finish: the taken record stays gone', async () => {
  const { handoff, member, started, cookie, attestBody, issue, sheet, store } = await setUp();
  await handoff.attest({ member, hostname: H, body: attestBody() });
  await handoff.options({ member, hostname: H, body: { id: started.id }, issue });
  let redeemed;
  const finished = await handoff.finish({
    member,
    hostname: H,
    body: sheet('challenge-1'),
    verify: async () => {
      redeemed = await handoff.redeem({ member, hostname: H, headers: { cookie }, body: { id: started.id } });
      return { ok: true, result: 'token' };
    },
  });
  assert.equal(redeemed.reason, 'not_done');
  assert.equal(finished.reason, 'unknown_handoff');
  assert.equal(store.get(started.id), null);
});

test('an attest that loses to an expiry or another attest says so', async () => {
  const { handoff, member, started, attestBody, store } = await setUp();
  const body = attestBody();
  const update = store.update;
  store.update = (id, expected, change) => {
    store.update = update;
    update(id, { state: 'pending' }, { state: 'attested', keyId: 'someone else' });
    return update(id, expected, change);
  };
  const result = await handoff.attest({ member, hostname: H, body });
  assert.equal(result.reason, 'not_pending');
  assert.equal(store.get(started.id).keyId, 'someone else');
});

test('options and finish need their callbacks to answer properly', async () => {
  const { handoff, member, started, attestBody, issue, sheet } = await setUp();
  await handoff.attest({ member, hostname: H, body: attestBody() });
  await assert.rejects(handoff.options({ member, hostname: H, body: { id: started.id } }), /issue\(record\)/);
  await assert.rejects(handoff.options({ member, hostname: H, body: { id: started.id }, issue: async () => ({}) }), /its challenge/);
  await handoff.options({ member, hostname: H, body: { id: started.id }, issue });
  await assert.rejects(handoff.finish({ member, hostname: H, body: sheet('challenge-1') }), /verify\(record, assertion\)/);
  await assert.rejects(handoff.finish({ member, hostname: H, body: sheet('challenge-1'), verify: async () => ({ ok: true }) }), /result/);
  // The bad answer came after the claim: the record is used up.
  assert.equal((await handoff.finish({ member, hostname: H, body: sheet('challenge-1'), verify: async () => ({ ok: true, result: 'token' }) })).reason, 'not_attested');
  const again = await setUp();
  await again.handoff.attest({ member: again.member, hostname: H, body: again.attestBody() });
  await again.handoff.options({ member: again.member, hostname: H, body: { id: again.started.id }, issue: again.issue });
  await assert.rejects(again.handoff.finish({ member: again.member, hostname: H, body: again.sheet('challenge-1'), verify: async () => undefined }), /or a refusal/);
});
