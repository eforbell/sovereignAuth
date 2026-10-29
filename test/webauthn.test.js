// WebAuthn ceremonies against a software authenticator: kinds come from what the authenticator proves (D15,
// bugBase #147), challenges are bound and single-use (D17), and attestation chains must reach a pinned root.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const {
  ATTESTATION_ROOTS,
  attestationRoot,
  createMemoryChallengeStore,
  createWebAuthn,
  credentialKind,
  loadRoots,
} = require('..');
const { createAuthenticator, createCertificate } = require('./support/authenticator');

const RP_ID = 'example.ts.net';
const HOST = 'home-admin.example.ts.net';
const ORIGIN = `https://${HOST}`;
const PARENT = { userId: 'u-parent', login: 'parent@example.com', name: 'Parent' };
const KID = { userId: 'u-kid', login: 'kid@example.com', name: 'Kid' };
const ENROLL = { hostname: HOST, member: PARENT, purpose: 'enroll' };
const STEP_UP = { hostname: HOST, member: PARENT, purpose: 'step-up', audience: 'family-pulse', action: { act: 'export-data', tgt: 'all' } };
const handle = (member) => Buffer.from(member.userId).toString('base64url');

// A test PKI: a root, an intermediate under it, and an attestation leaf under that. None of it is pinned
// anywhere but in the tests that pin it.
let pki;
test.before(async () => {
  const root = await createCertificate({ name: 'Test Root' });
  const intermediate = await createCertificate({ name: 'Test Intermediate', issuer: root });
  pki = {
    root,
    intermediate,
    leaf: await createCertificate({ name: 'Test Attestation', issuer: intermediate, ca: false }),
    leafUnderRoot: await createCertificate({ name: 'Test Attestation Direct', issuer: root, ca: false }),
  };
});

const chain = (leaf, ...issuers) => ({ x5c: [leaf.der, ...issuers.map((cert) => cert.der)], key: leaf.key });
const pinnedTest = (options = {}) => createWebAuthn({ rpID: RP_ID, roots: [pki.root.pin()], ...options });

async function enroll(webauthn, authenticator, { attestation = 'none', register = {}, request = ENROLL, finish = request } = {}) {
  const options = await webauthn.registrationOptions({ ...request, attestation });
  return webauthn.verifyRegistration({ ...finish, response: authenticator.register(options, { origin: ORIGIN, ...register }) });
}

async function stepUp(webauthn, authenticator, credentials, { authenticate = {}, kind = 'any', request = STEP_UP, finish = request } = {}) {
  const options = await webauthn.authenticationOptions({ ...request, credentials, kind });
  return webauthn.verifyAuthentication({ kind, ...finish, credentials, response: authenticator.authenticate(options, { origin: ORIGIN, ...authenticate }) });
}

test('the pinned roots are Yubico\'s, as published, and each matches its fingerprint', () => {
  assert.deepEqual(ATTESTATION_ROOTS.map(({ name, fingerprint }) => [name, fingerprint]), [
    ['Yubico U2F Root CA Serial 457200631', '0F:A1:38:6F:80:EB:87:13:26:3A:E5:C1:D8:4D:EB:45:5B:DF:08:AE:A5:0A:B0:55:03:CE:FE:E8:2B:09:2D:42'],
    ['Yubico FIDO Root CA Serial 450203556', '35:F1:A5:4B:35:3B:FB:71:1E:6D:42:AD:BE:B7:6C:0E:9D:EA:D0:95:01:8E:6A:94:78:3B:A2:19:2F:D6:FA:AD'],
    ['Yubico Attestation Root 1', '62:76:0C:6A:6E:F9:16:79:F4:54:C8:90:2B:80:FD:00:98:25:B3:F2:5D:A9:0F:1F:BA:CE:2E:C6:58:6C:D5:A8'],
  ]);
  assert.equal(loadRoots().length, 3);
  const [first, second] = ATTESTATION_ROOTS;
  assert.throws(() => loadRoots([{ ...first, pem: second.pem }]), /does not match its fingerprint/);
  assert.throws(() => createWebAuthn({ rpID: RP_ID, roots: [{ ...first, fingerprint: second.fingerprint }] }), /does not match/);
});

test('ceremonies require user verification and ask for nothing derived (no PRF)', async () => {
  const webauthn = createWebAuthn({ rpID: RP_ID });
  const registration = await webauthn.registrationOptions({ ...ENROLL, excludeCredentials: [{ id: 'AAAA', transports: ['usb'] }] });
  assert.equal(registration.rp.id, RP_ID);
  assert.equal(registration.user.id, handle(PARENT));
  assert.equal(registration.user.name, PARENT.login);
  assert.equal(registration.attestation, 'none');
  assert.equal(registration.authenticatorSelection.userVerification, 'required');
  assert.deepEqual(registration.extensions, { credProps: true });
  assert.deepEqual(registration.pubKeyCredParams.map(({ alg }) => alg), [-8, -7, -257]);
  assert.deepEqual(registration.excludeCredentials, [{ id: 'AAAA', transports: ['usb'], type: 'public-key' }]);
  assert.equal((await webauthn.registrationOptions({ ...ENROLL, attestation: 'direct' })).attestation, 'direct');

  const hardware = { id: 'BBBB', kind: 'hardware', root: ATTESTATION_ROOTS[0].fingerprint, deviceType: 'singleDevice', backedUp: false, transports: ['usb'] };
  const synced = { id: 'CCCC', kind: 'synced', deviceType: 'multiDevice', backedUp: true };
  const authentication = await webauthn.authenticationOptions({ ...STEP_UP, credentials: [hardware, synced] });
  assert.equal(authentication.rpId, RP_ID);
  assert.equal(authentication.userVerification, 'required');
  assert.equal(authentication.extensions, undefined);
  assert.deepEqual(authentication.allowCredentials.map(({ id }) => id), ['BBBB', 'CCCC']);
  const hardwareOnly = await webauthn.authenticationOptions({ ...STEP_UP, credentials: [hardware, synced], kind: 'hardware' });
  assert.deepEqual(hardwareOnly.allowCredentials.map(({ id }) => id), ['BBBB']);
  await assert.rejects(webauthn.authenticationOptions({ ...STEP_UP, credentials: [synced], kind: 'hardware' }), /no hardware credential/);
  await assert.rejects(webauthn.authenticationOptions({ ...STEP_UP, credentials: [] }), /no credential/);
});

test('mistakes in configuration or in the caller\'s request throw', async () => {
  assert.throws(() => createWebAuthn({}), /tailnet domain/);
  assert.throws(() => createWebAuthn({ rpID: 'Example.ts.net' }), /lower case/);
  assert.throws(() => createWebAuthn({ rpID: RP_ID, store: {} }), /put\(record\) and take\(challenge\)/);
  const webauthn = createWebAuthn({ rpID: RP_ID });
  for (const hostname of [RP_ID, 'home-admin.other.ts.net', 'evilexample.ts.net', 'HOME-ADMIN.example.ts.net', 'home admin.example.ts.net', undefined]) {
    await assert.rejects(webauthn.registrationOptions({ ...ENROLL, hostname }), /is not a hostname in/, String(hostname));
  }
  await assert.rejects(webauthn.registrationOptions({ ...ENROLL, member: { login: PARENT.login } }), /for a member/);
  for (const purpose of [undefined, '', 'Step-Up', 'step up', '../enroll']) {
    await assert.rejects(webauthn.registrationOptions({ ...ENROLL, purpose }), /needs a purpose/, String(purpose));
  }
  await assert.rejects(webauthn.registrationOptions({ ...ENROLL, attestation: 'indirect' }), /none or direct/);
  await assert.rejects(webauthn.registrationOptions({ ...ENROLL, attestation: 'enterprise' }), /none or direct/);
  await assert.rejects(webauthn.authenticationOptions({ ...STEP_UP, credentials: [{ id: 'AAAA' }], kind: 'synced' }), /any or hardware/);
});

test('a credential\'s kind comes from what the authenticator proves, not from what was asked for (#147)', async () => {
  const webauthn = pinnedTest();
  const cases = [
    ['no attestation, single-device', {}, {}, 'device-bound'],
    ['no attestation, backup eligible', { backupEligible: true }, {}, 'synced'],
    ['no attestation, backed up', { backupEligible: true, backedUp: true }, {}, 'synced'],
    ['self-attestation', {}, { fmt: 'packed' }, 'device-bound'],
    ['a pinned chain', {}, { fmt: 'packed', attestation: () => chain(pki.leaf, pki.intermediate) }, 'hardware'],
    ['a pinned chain that includes its root', {}, { fmt: 'packed', attestation: () => chain(pki.leaf, pki.intermediate, pki.root) }, 'hardware'],
    ['a leaf issued by the root itself', {}, { fmt: 'packed', attestation: () => chain(pki.leafUnderRoot) }, 'hardware'],
    ['a pinned chain on a backup-eligible key', { backupEligible: true }, { fmt: 'packed', attestation: () => chain(pki.leaf, pki.intermediate) }, 'synced'],
  ];
  for (const [name, authenticatorOptions, { attestation, ...register }, kind] of cases) {
    for (const asked of ['none', 'direct']) {
      const result = await enroll(webauthn, createAuthenticator(authenticatorOptions), { attestation: asked, register: { ...register, attestation: attestation?.() } });
      assert.equal(result.ok, true, `${name}: ${result.reason} ${result.detail || ''}`);
      assert.equal(result.credential.kind, kind, `${name}, asked for ${asked}`);
      assert.equal(result.credential.root, kind === 'hardware' ? pki.root.pin().fingerprint : null, name);
    }
  }
  assert.equal(credentialKind({ deviceType: 'singleDevice', backedUp: false, root: null }), 'device-bound');
  assert.equal(credentialKind({ deviceType: 'singleDevice', backedUp: undefined, root: {} }), 'synced');
  assert.equal(credentialKind({ deviceType: undefined, backedUp: false, root: {} }), 'synced');
});

test('a registration returns everything the caller stores, and what it was for', async () => {
  const authenticator = createAuthenticator();
  const request = { ...STEP_UP, purpose: 'enroll' };
  const result = await enroll(pinnedTest(), authenticator, { request, attestation: 'direct', register: { fmt: 'packed', attestation: chain(pki.leaf, pki.intermediate) } });
  assert.equal(result.ok, true);
  assert.deepEqual(Object.keys(result.credential).sort(), ['aaguid', 'backedUp', 'counter', 'deviceType', 'id', 'kind', 'publicKey', 'root', 'transports']);
  assert.equal(result.credential.id, authenticator.id);
  assert.equal(result.credential.aaguid, [...authenticator.aaguid.toString('hex').matchAll(/(.{8})(.{4})(.{4})(.{4})(.{12})/g)][0].slice(1).join('-'));
  assert.deepEqual({ purpose: result.purpose, audience: result.audience, action: result.action }, { purpose: 'enroll', audience: 'family-pulse', action: STEP_UP.action });
});

test('an attestation chain that does not reach a pinned root is refused, not downgraded', async () => {
  const attacker = await createCertificate({ name: 'Test Root' }); // the pinned root's name, not its key
  const attackerIntermediate = await createCertificate({ name: 'Test Intermediate', issuer: attacker });
  const attackerLeaf = await createCertificate({ name: 'Test Attestation', issuer: attackerIntermediate, ca: false });
  const leafIssuedLeaf = await createCertificate({ name: 'Leaf Under Leaf', issuer: pki.leaf, ca: false });
  const expiredIntermediate = await createCertificate({ name: 'Expired Intermediate', issuer: pki.root, from: -10 * 864e5, to: -864e5 });
  const leafUnderExpired = await createCertificate({ name: 'Under Expired', issuer: expiredIntermediate, ca: false });
  const futureLeaf = await createCertificate({ name: 'Future', issuer: pki.intermediate, ca: false, from: 864e5, to: 2 * 864e5 });
  const expiredRoot = await createCertificate({ name: 'Expired Root', from: -10 * 864e5, to: -864e5 });
  const leafUnderExpiredRoot = await createCertificate({ name: 'Under Expired Root', issuer: expiredRoot, ca: false });
  const second = await createCertificate({ name: 'Second Intermediate', issuer: pki.intermediate });
  const third = await createCertificate({ name: 'Third Intermediate', issuer: second });
  const deepLeaf = await createCertificate({ name: 'Deep Attestation', issuer: third, ca: false });
  assert.notEqual(attestationRoot([deepLeaf.der, third.der, second.der, pki.intermediate.der], loadRoots([pki.root.pin()]), new Date()), null, 'four is the most');
  const cases = [
    ['a CA certificate as the leaf', pinnedTest(), { x5c: [pki.intermediate.der], key: pki.intermediate.key }],
    ['a valid chain of five', pinnedTest(), chain(deepLeaf, third, second, pki.intermediate, pki.root)],
    ['a pinned root that has expired', pinnedTest({ roots: [expiredRoot.pin()] }), chain(leafUnderExpiredRoot)],
    ['a chain to an unpinned root', createWebAuthn({ rpID: RP_ID }), chain(pki.leaf, pki.intermediate)],
    ['any chain when no roots are loaded', createWebAuthn({ rpID: RP_ID, roots: [] }), chain(pki.leaf, pki.intermediate)],
    // GHSA-6hxq-p678-4hr2: a self-signed certificate the client sends must not end the walk.
    ['an attacker chain ending in its own self-signed root', pinnedTest(), chain(attackerLeaf, attackerIntermediate, attacker)],
    ['an attacker chain named like the pinned one', pinnedTest(), chain(attackerLeaf, attackerIntermediate)],
    ['a leaf used as an issuer', pinnedTest(), chain(leafIssuedLeaf, pki.leaf, pki.intermediate)],
    ['an expired intermediate', pinnedTest(), chain(leafUnderExpired, expiredIntermediate)],
    ['a leaf not yet valid', pinnedTest(), chain(futureLeaf, pki.intermediate)],
    ['a chain out of order', pinnedTest(), chain(pki.leaf, pki.root, pki.intermediate)],
    ['a certificate that does not parse', pinnedTest(), { x5c: [Buffer.from('not a certificate')], key: pki.leaf.key }],
    ['an empty chain', pinnedTest(), { x5c: [], key: pki.leaf.key }],
  ];
  for (const [name, webauthn, attestation] of cases) {
    const result = await enroll(webauthn, createAuthenticator(), { attestation: 'direct', register: { fmt: 'packed', attestation } });
    assert.deepEqual(result, { ok: false, reason: 'untrusted_attestation' }, name);
  }
  // The leaf must have signed: a pinned chain with a signature from another key is not verified.
  const forged = await enroll(pinnedTest(), createAuthenticator(), { attestation: 'direct', register: { fmt: 'packed', attestation: { ...chain(pki.leaf, pki.intermediate), key: attackerLeaf.key } } });
  assert.equal(forged.reason, 'not_verified');

  const at = new Date();
  const anchors = loadRoots([pki.root.pin()]);
  assert.equal(attestationRoot([pki.leaf.der, pki.intermediate.der], anchors, at).name, 'Test Root');
  assert.equal(attestationRoot([pki.leaf.der, pki.intermediate.der], anchors, new Date(at.getTime() + 400 * 864e5)), null);
  assert.equal(attestationRoot('not a chain', anchors, at), null);
});

test('only none and packed attestation are accepted, so no client certificate is ever fetched from', async (t) => {
  const requests = [];
  const server = http.createServer((req, res) => { requests.push(req.url); res.end(); });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const leaf = await createCertificate({ name: 'Fetch Me', issuer: pki.root, ca: false, crl: `http://127.0.0.1:${server.address().port}/crl` });
  const webauthn = pinnedTest();
  for (const fmt of ['apple', 'android-key', 'android-safetynet', 'tpm', 'fido-u2f', 'unknown']) {
    const result = await enroll(webauthn, createAuthenticator(), { attestation: 'direct', register: { fmt, attestation: chain(leaf, pki.root) } });
    assert.deepEqual(result, { ok: false, reason: 'unsupported_attestation' }, fmt);
  }
  assert.deepEqual(requests, []);
});

test('a registration challenge is for one hostname, member, purpose, audience and action, once', async () => {
  let clock = Date.now();
  const webauthn = createWebAuthn({ rpID: RP_ID, now: () => clock });
  const authenticator = createAuthenticator();
  const request = { ...ENROLL, audience: HOST, action: { label: 'laptop' } };
  const refusals = [
    ['another hostname', { hostname: 'home-docs.example.ts.net' }, 'wrong_hostname'],
    ['another member', { member: KID }, 'wrong_member'],
    ['another purpose', { purpose: 'step-up' }, 'wrong_purpose'],
    ['another audience', { audience: 'family-pulse' }, 'wrong_audience'],
    ['another action', { action: { label: 'phone' } }, 'wrong_action'],
  ];
  for (const [name, change, reason] of refusals) {
    const result = await enroll(webauthn, authenticator, { request, finish: { ...request, ...change } });
    assert.deepEqual(result, { ok: false, reason }, name);
  }
  // The same action written in another order is the same action.
  assert.equal((await enroll(webauthn, authenticator, { request: { ...request, action: { b: 1, a: [1, { d: 2, c: 3 }] } }, finish: { ...request, action: { a: [1, { c: 3, d: 2 }], b: 1 } } })).ok, true);

  // Used, refused or not, a challenge is gone.
  const options = await webauthn.registrationOptions(request);
  const response = authenticator.register(options, { origin: ORIGIN });
  assert.equal((await webauthn.verifyRegistration({ ...request, member: KID, response })).reason, 'wrong_member');
  assert.equal((await webauthn.verifyRegistration({ ...request, response })).reason, 'unknown_challenge');
  const again = await webauthn.registrationOptions(request);
  const fresh = authenticator.register(again, { origin: ORIGIN });
  assert.equal((await webauthn.verifyRegistration({ ...request, response: fresh })).ok, true);
  assert.equal((await webauthn.verifyRegistration({ ...request, response: fresh })).reason, 'unknown_challenge');

  // A step-up challenge doesn't enroll, and a challenge lasts five minutes.
  const stepUpOptions = await webauthn.authenticationOptions({ ...request, credentials: [{ id: authenticator.id }] });
  assert.equal((await webauthn.verifyRegistration({ ...request, response: authenticator.register({ ...stepUpOptions, rp: { id: RP_ID } }, { origin: ORIGIN }) })).reason, 'wrong_ceremony');
  const late = await webauthn.registrationOptions(request);
  clock += 300_001;
  assert.equal((await webauthn.verifyRegistration({ ...request, response: authenticator.register(late, { origin: ORIGIN }) })).reason, 'expired');
});

test('clientData must be ours: same origin, not framed, the right ceremony type', async () => {
  const webauthn = createWebAuthn({ rpID: RP_ID });
  const cases = [
    ['crossOrigin true', { extra: { crossOrigin: true } }, 'cross_origin'],
    ['crossOrigin as a string', { extra: { crossOrigin: 'false' } }, 'cross_origin'],
    ['a topOrigin', { extra: { topOrigin: ORIGIN } }, 'cross_origin'],
    ['a sibling hostname\'s origin', { origin: 'https://home.example.ts.net' }, 'not_verified'],
    ['http', { origin: `http://${HOST}` }, 'not_verified'],
    ['another RP ID', { rpID: 'other.ts.net' }, 'not_verified'],
    ['no user verification', { flagOptions: { userVerified: false } }, 'not_verified'],
    ['an assertion\'s type', { extra: { type: 'webauthn.get' } }, 'not_verified'],
  ];
  for (const [name, register, reason] of cases) {
    const result = await enroll(webauthn, createAuthenticator(), { register });
    assert.equal(result.reason, reason, name);
  }
  for (const response of [undefined, {}, { response: {} }, { response: { clientDataJSON: '!!' } }, { response: { clientDataJSON: Buffer.from('{}').toString('base64url') } }]) {
    assert.deepEqual(await webauthn.verifyRegistration({ ...ENROLL, response }), { ok: false, reason: 'malformed' });
  }
  const options = await webauthn.registrationOptions(ENROLL);
  const response = createAuthenticator().register(options, { origin: ORIGIN });
  response.response.attestationObject = 'AAAA';
  assert.deepEqual(await webauthn.verifyRegistration({ ...ENROLL, response }), { ok: false, reason: 'malformed' });
});

test('a step-up proves the member\'s own credential, and reports its kind now', async () => {
  const webauthn = pinnedTest();
  const key = createAuthenticator();
  const { credential } = await enroll(webauthn, key, { attestation: 'direct', register: { fmt: 'packed', attestation: chain(pki.leaf, pki.intermediate) } });
  assert.equal(credential.kind, 'hardware');

  const ok = await stepUp(webauthn, key, [credential], { kind: 'hardware', authenticate: { userHandle: handle(PARENT) } });
  assert.deepEqual(ok, { ok: true, purpose: 'step-up', audience: 'family-pulse', action: STEP_UP.action, credentialId: credential.id, kind: 'hardware', update: { kind: 'hardware', counter: 1, deviceType: 'singleDevice', backedUp: false } });
  assert.equal((await stepUp(webauthn, key, [{ ...credential, counter: 1 }])).ok, true, 'no user handle is fine');

  const other = createAuthenticator();
  const { credential: kidCredential } = await enroll(webauthn, other, { request: { ...ENROLL, member: KID } });
  assert.equal((await stepUp(webauthn, other, [credential], { authenticate: {} })).reason, 'unknown_credential');
  assert.equal((await stepUp(webauthn, key, [credential], { authenticate: { userHandle: handle(KID) } })).reason, 'wrong_member');
  assert.equal((await stepUp(webauthn, key, [{ ...credential, publicKey: kidCredential.publicKey }])).reason, 'not_verified');
  assert.equal((await stepUp(webauthn, key, [{ ...credential, counter: 50 }], { authenticate: { signCount: 10 } })).reason, 'not_verified');
  assert.equal((await stepUp(webauthn, key, [credential], { authenticate: { flagOptions: { userVerified: false } } })).reason, 'not_verified');
  assert.equal((await stepUp(webauthn, key, [credential], { authenticate: { extra: { crossOrigin: true } } })).reason, 'cross_origin');
  assert.equal((await stepUp(webauthn, key, [credential], { finish: { ...STEP_UP, action: { act: 'export-data', tgt: 'one' } } })).reason, 'wrong_action');
  assert.equal((await stepUp(webauthn, key, [credential], { finish: { ...STEP_UP, purpose: 'enroll' } })).reason, 'wrong_purpose');

  // Removing the root demotes the key: a hardware step-up started before a release that drops it is refused
  // at the finish after, and an ordinary one still passes.
  const store = createMemoryChallengeStore();
  const before = pinnedTest({ store });
  const after = createWebAuthn({ rpID: RP_ID, roots: [], store });
  const started = await before.authenticationOptions({ ...STEP_UP, credentials: [credential], kind: 'hardware' });
  const refused = await after.verifyAuthentication({ ...STEP_UP, kind: 'hardware', credentials: [credential], response: key.authenticate(started, { origin: ORIGIN, signCount: 90 }) });
  assert.deepEqual(refused, { ok: false, reason: 'insufficient_kind', credentialId: credential.id, update: { kind: 'device-bound', counter: 90, deviceType: 'singleDevice', backedUp: false } });
  assert.equal(after.currentKind(credential), 'device-bound');
  const ordinary = await stepUp(after, key, [credential], { authenticate: { signCount: 91 } });
  assert.deepEqual([ordinary.ok, ordinary.kind], [true, 'device-bound']);
});

test('a stored kind never rises, and falls with the flags or the root', () => {
  const webauthn = pinnedTest();
  const hardware = { kind: 'hardware', root: pki.root.pin().fingerprint, deviceType: 'singleDevice', backedUp: false };
  assert.equal(webauthn.currentKind(hardware), 'hardware');
  assert.equal(webauthn.currentKind(hardware, { deviceType: 'singleDevice', backedUp: true }), 'synced');
  assert.equal(webauthn.currentKind(hardware, { deviceType: 'multiDevice', backedUp: false }), 'synced');
  assert.equal(webauthn.currentKind({ ...hardware, backedUp: true }, { deviceType: 'singleDevice', backedUp: false }), 'synced', 'stored flags count too');
  assert.equal(webauthn.currentKind({ ...hardware, root: ATTESTATION_ROOTS[0].fingerprint }), 'device-bound');
  assert.equal(webauthn.currentKind({ ...hardware, root: null }), 'device-bound');
  assert.equal(webauthn.currentKind({ ...hardware, kind: 'device-bound' }), 'device-bound');
  assert.equal(webauthn.currentKind({ ...hardware, kind: 'synced' }), 'synced');
  assert.equal(webauthn.currentKind({ ...hardware, kind: 'platform' }), 'synced');
  assert.equal(webauthn.currentKind(null, hardware), 'synced');
});

test('a kind that fell stays down, through the update the caller stores', async () => {
  const webauthn = pinnedTest();
  const key = createAuthenticator();
  let { credential } = await enroll(webauthn, key, { attestation: 'direct', register: { fmt: 'packed', attestation: chain(pki.leaf, pki.intermediate) } });
  // The key says it is backed up once: the hardware step-up is refused, and the update says synced.
  const backedUp = await stepUp(webauthn, key, [credential], { kind: 'hardware', authenticate: { flagOptions: { eligible: true, backed: true } } });
  assert.equal(backedUp.reason, 'insufficient_kind');
  assert.equal(backedUp.update.kind, 'synced');
  credential = { ...credential, ...backedUp.update };
  // Then single-device again: still synced, so no hardware challenge can even be issued for it.
  await assert.rejects(webauthn.authenticationOptions({ ...STEP_UP, credentials: [credential], kind: 'hardware' }), /no hardware credential/);
  const later = await stepUp(webauthn, key, [credential]);
  assert.deepEqual([later.ok, later.kind, later.update.kind], [true, 'synced', 'synced']);
  // A caller that kept only the flags, not the kind, gets the same answer.
  const { kind, ...flagsOnly } = credential;
  assert.equal(webauthn.currentKind({ ...flagsOnly, kind: 'hardware' }), 'synced');
});

test('a step-up challenge finishes only under the kind it was issued for', async () => {
  const webauthn = pinnedTest();
  const key = createAuthenticator();
  const { credential: hardware } = await enroll(webauthn, key, { attestation: 'direct', register: { fmt: 'packed', attestation: chain(pki.leaf, pki.intermediate) } });
  const plain = createAuthenticator();
  const { credential: deviceBound } = await enroll(webauthn, plain);
  assert.equal((await stepUp(webauthn, plain, [deviceBound], { kind: 'any', finish: { ...STEP_UP, kind: 'hardware' } })).reason, 'wrong_kind');
  assert.equal((await stepUp(webauthn, key, [hardware], { kind: 'hardware', finish: { ...STEP_UP, kind: 'any' } })).reason, 'wrong_kind');
  await assert.rejects(webauthn.verifyAuthentication({ ...STEP_UP, kind: 'synced', credentials: [hardware], response: {} }), /any or hardware/);
});

test('of many finishes racing with one challenge, exactly one succeeds', async () => {
  const webauthn = createWebAuthn({ rpID: RP_ID });
  const options = await webauthn.registrationOptions(ENROLL);
  const response = createAuthenticator().register(options, { origin: ORIGIN });
  const results = await Promise.all(Array.from({ length: 50 }, () => webauthn.verifyRegistration({ ...ENROLL, response })));
  assert.equal(results.filter((result) => result.ok).length, 1);
  assert.ok(results.filter((result) => !result.ok).every((result) => result.reason === 'unknown_challenge'));
});

test('the memory store gives each challenge out once and forgets old ones', () => {
  let clock = 0;
  const store = createMemoryChallengeStore({ maxEntries: 2, now: () => clock });
  store.put({ challenge: 'a', expires: 10 });
  store.put({ challenge: 'b', expires: 100 });
  assert.equal(store.take('a').challenge, 'a');
  assert.equal(store.take('a'), null);
  store.put({ challenge: 'c', expires: 100 });
  store.put({ challenge: 'd', expires: 100 });
  assert.equal(store.take('b'), null, 'the oldest goes when full');
  clock = 200;
  store.put({ challenge: 'e', expires: 300 });
  assert.equal(store.take('c'), null, 'expired ones go');
  assert.equal(store.take('d'), null, 'every expired one');
  assert.equal(store.take('e').challenge, 'e');
});
