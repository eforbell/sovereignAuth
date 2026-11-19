// App Attest: attestations and assertions from a fake Apple, each check shown to refuse, plus real device
// output from a local file (never committed: it names the household's App ID).
//   SOVEREIGN_APPATTEST_FIXTURE=<appattest-fixtures.json> SOVEREIGN_APPATTEST_APP_ID=<TEAMID.bundle> npm test
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const { APP_ATTEST_ROOTS, AppAttestError, verifyAssertion, verifyAttestation } = require('..');
const { createFakeApple } = require('./support/appattest');

const APP_ID = 'ABCDE12345.org.example.homebase';
const CLIENT_DATA = 'sovereign-app-instance/1\nhousehold\nu-parent\nchallenge';
const MINUTE = 60 * 1000;

let apple;
test.before(async () => { apple = await createFakeApple({ appId: APP_ID }); });

const issuedAt = () => new Date(Date.now() - MINUTE);
const verify = (made, options = {}) => verifyAttestation({
  attestation: made.attestation, keyId: made.keyId, clientData: CLIENT_DATA, appId: APP_ID,
  issuedAt: issuedAt(), roots: apple.roots, ...options,
});
const refuses = (fn, code) => assert.throws(fn, (error) => error instanceof AppAttestError && error.code === code);

test('a genuine attestation gives the key to store', async () => {
  const made = await apple.attest({ clientData: CLIENT_DATA });
  const result = verify(made);
  assert.equal(result.keyId, made.keyId);
  assert.equal(result.counter, 0);
  assert.equal(result.environment, 'production');
  assert.ok(Buffer.isBuffer(result.receipt) && result.receipt.length > 0);
  assert.ok(result.receiptCreated instanceof Date);
  const key = crypto.createPublicKey({ key: Buffer.from(result.publicKey, 'base64'), format: 'der', type: 'spki' });
  assert.equal(key.asymmetricKeyDetails.namedCurve, 'prime256v1');
});

test("Apple's receipt encoding (indefinite lengths, payload in pieces) reads the same", async () => {
  assert.equal(verify(await apple.attest({ clientData: CLIENT_DATA, wrong: { form: 'ber' } })).counter, 0);
});

test('the attestation is refused when', async (t) => {
  const cases = [
    ['it is not App Attest', { fmt: 'packed' }, 'format'],
    ['its chain ends at an unpinned root', { chain: true }, 'chain'],
    ['the nonce is over other client data', { nonce: true }, 'nonce'],
    ['it is for another app', { appId: 'ABCDE12345.org.example.other' }, 'app_id'],
    ['the counter is not 0', { counter: 1 }, 'counter'],
    ['the environment is unknown', { aaguid: Buffer.from('somethingelse!!!', 'latin1') }, 'environment'],
    ['the credential ID is not the key', { credentialId: true }, 'key'],
    ['keyId is not the hash of the certified key', { keyId: true }, 'key'],
    ['the receipt signer is not a receipt-signing certificate', { receiptSigner: true }, 'receipt_signer'],
    ['the receipt chains to an unpinned root', { receiptRoot: true }, 'receipt_chain'],
    ['the receipt signature is wrong', { receiptSignature: true }, 'receipt_signature'],
    ['the receipt has signed attributes', { signedAttributes: true }, 'receipt'],
    ['the receipt is not an attestation receipt', { receiptType: 'RECEIPT' }, 'receipt'],
    ['the receipt is for another app', { receiptAppId: 'ABCDE12345.org.example.other' }, 'receipt_app_id'],
    ['the receipt is for another key', { receiptKey: true }, 'receipt_key'],
    ['the receipt is for other client data', { receiptClient: true }, 'receipt_client'],
    ['the receipt was made before the challenge', { receiptCreated: new Date(Date.now() - 10 * MINUTE) }, 'receipt_time'],
    ['the receipt was made in the future', { receiptCreated: new Date(Date.now() + 10 * MINUTE) }, 'receipt_time'],
  ];
  for (const [name, wrong, code] of cases) {
    await t.test(name, async () => {
      const made = await apple.attest({ clientData: CLIENT_DATA, wrong });
      refuses(() => verify(made), code);
    });
  }
});

test('the attestation is refused for other inputs', async (t) => {
  const made = await apple.attest({ clientData: CLIENT_DATA });
  await t.test('other client data', () => refuses(() => verify(made, { clientData: `${CLIENT_DATA}x` }), 'nonce'));
  await t.test('another keyId', () => refuses(() => verify(made, { keyId: crypto.randomBytes(32).toString('base64') }), 'key'));
  await t.test('the pinned (real) roots', () => refuses(() => verify(made, { roots: undefined }), 'chain'));
  await t.test('expired certificates', () => refuses(() => verify(made, { now: new Date(Date.now() + 400 * 24 * 60 * MINUTE) }), 'chain'));
  await t.test('an App ID without a team', () => refuses(() => verify(made, { appId: 'org.example.homebase' }), 'malformed'));
  await t.test('no challenge time', () => refuses(() => verify(made, { issuedAt: undefined }), 'malformed'));
  await t.test('a short keyId', () => refuses(() => verify(made, { keyId: 'AAAA' }), 'malformed'));
  await t.test('not base64', () => refuses(() => verify(made, { attestation: 'not base64!' }), 'malformed'));
  await t.test('bytes after the CBOR', () => {
    const padded = Buffer.concat([Buffer.from(made.attestation, 'base64'), Buffer.from([0])]);
    refuses(() => verify(made, { attestation: padded }), 'malformed');
  });
});

test('a malformed receipt is refused, and parsing always ends', async (t) => {
  const nested = Buffer.concat([...Array(40).fill(Buffer.from([0x30, 0x80])), ...Array(40).fill(Buffer.from([0, 0]))]);
  const cases = [
    ['a long length cut short inside an indefinite one', Buffer.from([0x30, 0x80, 0x30, 0x84, 0xff])],
    ['an indefinite length with no end', Buffer.from([0x30, 0x80, 0x05, 0x00])],
    ['a length past the end', Buffer.from([0x30, 0x05, 0x02, 0x01])],
    ['an indefinite primitive', Buffer.from([0x04, 0x80, 0x00, 0x00])],
    ['nesting too deep', nested],
    ['a single byte', Buffer.from([0x30])],
  ];
  for (const [name, receiptBytes] of cases) {
    await t.test(name, async () => {
      const made = await apple.attest({ clientData: CLIENT_DATA, wrong: { receiptBytes } });
      refuses(() => verify(made), 'malformed');
    });
  }
});

test('development is refused unless the household turns it on', async () => {
  const made = await apple.attest({ clientData: CLIENT_DATA, environment: 'development' });
  refuses(() => verify(made), 'environment');
  assert.equal(verify(made, { environments: ['production', 'development'] }).environment, 'development');
});

test('assertions verify against the stored key, and the counter must rise', async () => {
  const made = await apple.attest({ clientData: CLIENT_DATA });
  const stored = verify(made);
  const check = (assertion, clientData, counter, appId = APP_ID) => verifyAssertion({ assertion, clientData, appId, publicKey: stored.publicKey, counter });

  const first = apple.assert(made.device, { clientData: 'sovereign-handoff/1\nhome.example.ts.net\nid-1' });
  assert.deepEqual(check(first, 'sovereign-handoff/1\nhome.example.ts.net\nid-1', 0), { counter: 1 });
  refuses(() => check(first, 'sovereign-handoff/1\nhome.example.ts.net\nid-1', 1), 'counter'); // a replay
  refuses(() => check(first, 'sovereign-handoff/1\nhome.example.ts.net\nid-2', 0), 'signature');
  refuses(() => check(first, 'sovereign-handoff/1\nhome.example.ts.net\nid-1', 0, 'ABCDE12345.org.example.other'), 'app_id');

  const second = apple.assert(made.device, { clientData: 'second' });
  assert.deepEqual(check(second, 'second', 1), { counter: 2 });
  const stale = apple.assert(made.device, { clientData: 'stale', counter: 2 });
  refuses(() => check(stale, 'stale', 2), 'counter');
  const otherApp = apple.assert(made.device, { clientData: 'other', assertedAppId: 'ABCDE12345.org.example.other' });
  refuses(() => check(otherApp, 'other', 2), 'app_id');

  const other = await apple.attest({ clientData: CLIENT_DATA });
  refuses(() => check(apple.assert(other.device, { clientData: 'x' }), 'x', 0), 'signature'); // another device's key
  refuses(() => verifyAssertion({ assertion: first, clientData: 'x', appId: APP_ID, publicKey: stored.publicKey, counter: -1 }), 'malformed');
  refuses(() => verifyAssertion({ assertion: first, clientData: 'x', appId: APP_ID, publicKey: 'AAAA', counter: 0 }), 'malformed');
});

test("the pinned roots are Apple's, by fingerprint", () => {
  assert.deepEqual(APP_ATTEST_ROOTS.attestation.map((r) => r.fingerprint), ['1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32']);
  assert.deepEqual(APP_ATTEST_ROOTS.receipt.map((r) => r.fingerprint), ['63:34:3A:BF:B8:9A:6A:03:EB:B5:7E:9B:3F:5F:A7:BE:7C:4F:5C:75:6F:30:17:B3:A8:C4:88:C3:65:3E:91:79']);
  for (const root of [...APP_ATTEST_ROOTS.attestation, ...APP_ATTEST_ROOTS.receipt]) {
    assert.equal(new crypto.X509Certificate(root.pem).fingerprint256, root.fingerprint);
  }
});

// Real output from the Home Base app (sovereignShell's phase 3 spike 1), checked against the pinned roots at
// the time it was made.
const FIXTURE = process.env.SOVEREIGN_APPATTEST_FIXTURE;
const REAL_APP_ID = process.env.SOVEREIGN_APPATTEST_APP_ID;
test('real device output verifies against the pinned roots', { skip: !(FIXTURE && REAL_APP_ID) && 'set SOVEREIGN_APPATTEST_FIXTURE and SOVEREIGN_APPATTEST_APP_ID' }, () => {
  const fixture = JSON.parse(fs.readFileSync(FIXTURE, 'utf8'));
  const now = new Date(fixture.created);
  const stored = verifyAttestation({
    attestation: fixture.attestation, keyId: fixture.keyId, clientData: fixture.attestationClientData,
    appId: REAL_APP_ID, issuedAt: new Date(now.getTime() - MINUTE), now,
  });
  assert.equal(stored.environment, 'production');
  let { counter } = stored;
  for (const { assertion, clientData } of fixture.assertions) {
    ({ counter } = verifyAssertion({ assertion, clientData, appId: REAL_APP_ID, publicKey: stored.publicKey, counter }));
  }
  assert.equal(counter, fixture.assertions.length);
  refuses(() => verifyAttestation({
    attestation: fixture.attestation, keyId: fixture.keyId, clientData: `${fixture.attestationClientData}x`,
    appId: REAL_APP_ID, issuedAt: new Date(now.getTime() - MINUTE), now,
  }), 'nonce');
});
