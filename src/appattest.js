// App Attest verification: an iPhone app proves a key lives in its Secure Enclave and belongs to one App ID.
// Follows Apple's "Validating apps that connect to your server", plus the receipt checks in
// docs/native-handoff.md (part 1). Shared by the native handoff's app instances and the iPhone approval key.
//
// Never calls Apple. The receipt is checked offline, against a pinned root; Apple's fraud-metric refresh,
// which would exchange it with Apple's server, is not used.
const crypto = require('node:crypto');
const { isoCBOR } = require('@simplewebauthn/server/helpers');
const { attestationRoot, loadRoots } = require('./webauthn');
const PINNED = require('./appattest-roots.json');

const OID = {
  nonce: '1.2.840.113635.100.8.2', // in the credential certificate: SHA-256(authData ‖ clientDataHash)
  receiptSigner: '1.2.840.113635.100.12.15', // Apple's marker on the certificate that signs receipts
  signedData: '1.2.840.113549.1.7.2',
  data: '1.2.840.113549.1.7.1',
  sha256: '2.16.840.1.101.3.4.2.1',
  ecdsaSha256: '1.2.840.10045.4.3.2',
};
const ENVIRONMENTS = {
  'appattest\0\0\0\0\0\0\0': 'production',
  appattestdevelop: 'development',
};
const RECEIPT = { appId: 2, certificate: 3, clientHash: 4, type: 6, created: 12 };
const RECEIPT_SKEW_MS = 60 * 1000;
const MAX_DEPTH = 16;

class AppAttestError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'AppAttestError';
    this.code = code;
  }
}

const fail = (code, message) => { throw new AppAttestError(code, message); };
const sha256 = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts)).digest();

// --- Inputs ----------------------------------------------------------------------------------------------

// Bytes from a Buffer, a Uint8Array or base64 (standard or URL-safe), as the app sends them.
function bytes(value, name) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === 'string' && /^[A-Za-z0-9+/_-]+={0,2}$/.test(value)) return Buffer.from(value, 'base64');
  return fail('malformed', `${name} is not bytes or base64`);
}

function clientDataHash(clientData) {
  if (typeof clientData === 'string') return sha256(Buffer.from(clientData, 'utf8'));
  if (Buffer.isBuffer(clientData) || clientData instanceof Uint8Array) return sha256(Buffer.from(clientData));
  return fail('malformed', 'clientData must be a string or bytes');
}

// CBOR as Apple encodes it: a map, nothing after it, and nothing a re-encoding would change.
function cborMap(buffer, name) {
  let value;
  try {
    value = isoCBOR.decodeFirst(buffer);
  } catch {
    return fail('malformed', `${name} is not CBOR`);
  }
  if (!(value instanceof Map) || Buffer.from(isoCBOR.encode(value)).length !== buffer.length) {
    return fail('malformed', `${name} is not a single CBOR map`);
  }
  return value;
}

// --- ASN.1 (BER, for receipts; DER is a subset) --------------------------------------------------------

// One element at offset i: { tag, constructed, start, contentStart, contentEnd, end, children }. Receipts use
// indefinite lengths and split their payload across a constructed OCTET STRING, so both are read.
function element(buf, i, depth = 0) {
  if (depth > MAX_DEPTH) fail('malformed', 'ASN.1 nests too deeply');
  if (i + 2 > buf.length) fail('malformed', 'ASN.1 ends early');
  const start = i;
  const tag = buf[i++];
  if ((tag & 0x1f) === 0x1f) fail('malformed', 'ASN.1 high tag numbers are not used here');
  const constructed = (tag & 0x20) !== 0;
  let length = buf[i++];
  if (length === 0x80) {
    if (!constructed) fail('malformed', 'ASN.1 indefinite length on a primitive');
    const children = [];
    while (!(buf[i] === 0 && buf[i + 1] === 0)) {
      if (i + 2 > buf.length) fail('malformed', 'ASN.1 indefinite length never ends');
      const child = element(buf, i, depth + 1);
      children.push(child);
      i = child.end;
    }
    return { tag, constructed, start, contentStart: start + 2, contentEnd: i, end: i + 2, children };
  }
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4) fail('malformed', 'ASN.1 length is out of range');
    length = 0;
    for (let k = 0; k < count; k++) length = length * 256 + buf[i++];
  }
  const end = i + length;
  if (end > buf.length) fail('malformed', 'ASN.1 length runs past the end');
  const node = { tag, constructed, start, contentStart: i, contentEnd: end, end };
  if (constructed) node.children = elements(buf, i, end, depth + 1);
  return node;
}

function elements(buf, i, end, depth) {
  const out = [];
  while (i < end) {
    const child = element(buf, i, depth);
    if (child.end > end) fail('malformed', 'ASN.1 element runs past its parent');
    out.push(child);
    i = child.end;
  }
  return out;
}

function parse(buf, name) {
  const root = element(buf, 0);
  if (root.end !== buf.length) fail('malformed', `${name} has bytes after it`);
  return root;
}

const content = (buf, node) => buf.subarray(node.contentStart, node.contentEnd);
const raw = (buf, node) => buf.subarray(node.start, node.end);

function expect(node, tag, what) {
  if (!node || node.tag !== tag) fail('malformed', `${what} is missing`);
  return node;
}

// An OCTET STRING's bytes, joining the pieces of a constructed one.
function octets(buf, node) {
  if (node.tag === 0x04) return Buffer.from(content(buf, node));
  if (node.tag === 0x24) return Buffer.concat(node.children.map((child) => octets(buf, child)));
  return fail('malformed', 'expected an OCTET STRING');
}

function oid(buf, node) {
  const value = content(buf, expect(node, 0x06, 'an object identifier'));
  if (value.length === 0) fail('malformed', 'empty object identifier');
  const arcs = [Math.min(2, Math.floor(value[0] / 40)), value[0] - Math.min(2, Math.floor(value[0] / 40)) * 40];
  let arc = 0;
  for (let k = 1; k < value.length; k++) {
    arc = arc * 128 + (value[k] & 0x7f);
    if (!(value[k] & 0x80)) { arcs.push(arc); arc = 0; }
  }
  return arcs.join('.');
}

function integer(buf, node) {
  const value = content(buf, expect(node, 0x02, 'an integer'));
  if (value.length === 0 || value.length > 6 || value[0] & 0x80) fail('malformed', 'integer out of range');
  return value.reduce((n, byte) => n * 256 + byte, 0);
}

// A certificate's extensions, by OID. tbsCertificate: [0] version, serial, signature, issuer, validity,
// subject, subjectPublicKeyInfo, ..., [3] extensions.
function extensions(der) {
  const tbs = expect(parse(der, 'certificate').children?.[0], 0x30, 'tbsCertificate');
  const wrapper = tbs.children.find((child) => child.tag === 0xa3);
  const out = new Map();
  for (const ext of wrapper ? expect(wrapper.children[0], 0x30, 'extensions').children : []) {
    const id = oid(der, ext.children[0]);
    if (out.has(id)) fail('malformed', `certificate repeats extension ${id}`);
    out.set(id, octets(der, ext.children.at(-1)));
  }
  return out;
}

// --- Attestation -----------------------------------------------------------------------------------------

function loadedRoots(roots) {
  if (!roots) return PINNED_ROOTS;
  return { attestation: loadRoots(roots.attestation), receipt: loadRoots(roots.receipt) };
}

function authenticatorData(data, { attested }) {
  if (data.length < 37) fail('malformed', 'authenticator data is too short');
  const out = { rpIdHash: data.subarray(0, 32), counter: data.readUInt32BE(33) };
  if (attested) {
    if (data.length < 55) fail('malformed', 'authenticator data has no attested credential');
    out.aaguid = data.subarray(37, 53).toString('latin1');
    const length = data.readUInt16BE(53);
    if (data.length < 55 + length) fail('malformed', 'credential ID runs past the authenticator data');
    out.credentialId = data.subarray(55, 55 + length);
  }
  return out;
}

// The credential's public key as an X9.62 uncompressed point (0x04 ‖ x ‖ y), the form keyId hashes.
function uncompressedPoint(cert) {
  const jwk = cert.publicKey.export({ format: 'jwk' });
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') fail('key', 'the credential key is not P-256');
  return Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
}

// The nonce extension holds SEQUENCE { [1] EXPLICIT OCTET STRING (32 bytes) }.
function certificateNonce(der) {
  const value = extensions(der).get(OID.nonce);
  if (!value) return fail('nonce', 'the credential certificate has no nonce');
  const sequence = expect(parse(value, 'nonce extension'), 0x30, 'nonce sequence');
  const tagged = expect(sequence.children[0], 0xa1, 'nonce [1]');
  const nonce = octets(value, expect(tagged.children[0], 0x04, 'nonce'));
  if (sequence.children.length !== 1 || tagged.children.length !== 1 || nonce.length !== 32) {
    fail('nonce', 'the nonce extension has an unexpected shape');
  }
  return nonce;
}

// Verifies an attestation from DCAppAttestService.attestKey(keyId, SHA-256(clientData)) for appId
// ("<TEAMID>.<bundle id>"). Options:
// - environments: the AAGUID environments accepted; ['production'] unless the household opts in to
//   'development' too.
// - issuedAt: when the server issued the challenge in clientData. The receipt must be created after it.
// - now: the time to check certificates and the receipt against.
// - roots: { attestation, receipt } in appattest-roots.json's format; the pinned roots unless given.
// Returns what to store: { keyId, publicKey (SPKI DER, base64), counter: 0, environment, receipt (Buffer),
// receiptCreated (Date) }. Throws AppAttestError otherwise.
function verifyAttestation({ attestation, keyId, clientData, appId, issuedAt, environments = ['production'], now = new Date(), roots } = {}) {
  if (typeof appId !== 'string' || !/^[A-Z0-9]{10}\.[A-Za-z0-9.-]+$/.test(appId)) fail('malformed', 'appId must be <TEAMID>.<bundle id>');
  if (!(issuedAt instanceof Date) || Number.isNaN(issuedAt.getTime())) fail('malformed', 'issuedAt must be a Date');
  const id = bytes(keyId, 'keyId');
  if (id.length !== 32) fail('malformed', 'keyId must be 32 bytes');
  const hash = clientDataHash(clientData);
  const pinned = loadedRoots(roots);

  const object = cborMap(bytes(attestation, 'attestation'), 'attestation');
  if (object.get('fmt') !== 'apple-appattest') fail('format', 'not an App Attest attestation');
  const statement = object.get('attStmt');
  const authData = object.get('authData');
  if (!(statement instanceof Map) || !(authData instanceof Uint8Array)) fail('malformed', 'attestation is missing its statement');
  const x5c = statement.get('x5c');
  const receipt = statement.get('receipt');
  if (!Array.isArray(x5c) || !x5c.every((der) => der instanceof Uint8Array) || !(receipt instanceof Uint8Array)) {
    fail('malformed', 'attestation is missing its certificates or receipt');
  }

  // 1. The chain ends at Apple's App Attestation root.
  if (!attestationRoot(x5c, pinned.attestation, now)) fail('chain', 'the certificates do not chain to the App Attestation root');
  const credentialDer = Buffer.from(x5c[0]);
  const credential = new crypto.X509Certificate(credentialDer);

  // 2–4. The nonce binds authData and clientData to the certificate.
  const data = Buffer.from(authData);
  if (!certificateNonce(credentialDer).equals(sha256(data, hash))) fail('nonce', 'the nonce does not match the client data');

  // 5. keyId is the hash of the certified key.
  const point = uncompressedPoint(credential);
  if (!sha256(point).equals(id)) fail('key', 'keyId is not the certified key');

  // 6–9. The authenticator data names this app, a new key, an allowed environment and the same key.
  const parsed = authenticatorData(data, { attested: true });
  if (!parsed.rpIdHash.equals(sha256(Buffer.from(appId, 'utf8')))) fail('app_id', 'the attestation is for a different app');
  if (parsed.counter !== 0) fail('counter', 'a new key starts at counter 0');
  const environment = ENVIRONMENTS[parsed.aaguid];
  if (!environment || !environments.includes(environment)) fail('environment', `the ${environment || 'unknown'} environment is not accepted`);
  if (!parsed.credentialId.equals(id)) fail('key', 'the credential ID is not keyId');

  const checked = verifyReceipt(Buffer.from(receipt), { appId, credentialDer, hash, issuedAt, now, roots: pinned.receipt });
  return {
    keyId: id.toString('base64'),
    publicKey: credential.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    counter: 0,
    environment,
    receipt: Buffer.from(receipt),
    receiptCreated: checked.created,
  };
}

// --- Receipt ---------------------------------------------------------------------------------------------

// The receipt is a CMS SignedData (RFC 5652) whose content is a SET of SEQUENCE { type INTEGER,
// version INTEGER, value OCTET STRING }. Apple signs it without signed attributes, so the signature covers
// the content itself; a receipt with signed attributes is refused rather than half-checked.
function verifyReceipt(buf, { appId, credentialDer, hash, issuedAt, now, roots }) {
  const info = expect(parse(buf, 'receipt'), 0x30, 'receipt ContentInfo');
  if (oid(buf, info.children[0]) !== OID.signedData) fail('receipt', 'the receipt is not SignedData');
  const signed = expect(expect(info.children[1], 0xa0, 'receipt content').children[0], 0x30, 'SignedData');
  const parts = signed.children;
  const encapsulated = expect(parts[2], 0x30, 'receipt encapsulated content');
  if (oid(buf, encapsulated.children[0]) !== OID.data) fail('receipt', 'the receipt content is not data');
  const payload = octets(buf, expect(encapsulated.children[1], 0xa0, 'receipt payload').children[0]);
  const certificates = expect(parts[3], 0xa0, 'receipt certificates').children.map((child) => Buffer.from(raw(buf, child)));
  const signers = expect(parts.at(-1), 0x31, 'receipt signers').children;
  if (signers.length !== 1) fail('receipt', 'the receipt must have one signer');

  // SignerInfo: version, sid (issuerAndSerialNumber), digestAlgorithm, signatureAlgorithm, signature.
  const signer = signers[0].children;
  if (signer.length !== 5 || signer.some((child) => child.tag === 0xa0 || child.tag === 0xa1)) {
    fail('receipt', 'the receipt signer has attributes');
  }
  if (oid(buf, signer[2].children[0]) !== OID.sha256 || oid(buf, signer[3].children[0]) !== OID.ecdsaSha256) {
    fail('receipt', 'the receipt is not signed with ECDSA and SHA-256');
  }
  const sid = expect(signer[1], 0x30, 'receipt signer identifier');
  const issuer = raw(buf, sid.children[0]);
  const serial = content(buf, expect(sid.children[1], 0x02, 'receipt signer serial'));
  const signerDer = certificates.find((der) => {
    const tbs = parse(der, 'certificate').children[0];
    const fields = tbs.children[0].tag === 0xa0 ? tbs.children.slice(1) : tbs.children;
    return content(der, fields[0]).equals(serial) && raw(der, fields[2]).equals(issuer);
  });
  if (!signerDer) fail('receipt', 'the receipt signer certificate is missing');

  // The signer chains to the pinned receipt root and carries Apple's receipt-signing marker, which no
  // other certificate under that root (a developer's, say) does.
  const chain = [signerDer];
  while (chain.length < 4) {
    const last = new crypto.X509Certificate(chain.at(-1));
    const next = certificates.find((der) => !chain.some((c) => c.equals(der))
      && last.checkIssued(new crypto.X509Certificate(der)) && last.verify(new crypto.X509Certificate(der).publicKey));
    if (!next) break;
    chain.push(next);
  }
  if (!attestationRoot(chain, roots, now)) fail('receipt_chain', 'the receipt does not chain to the receipt root');
  if (!extensions(signerDer).has(OID.receiptSigner)) fail('receipt_signer', 'the receipt signer is not a receipt-signing certificate');
  const signature = octets(buf, expect(signer[4], 0x04, 'receipt signature'));
  if (!crypto.verify('sha256', payload, new crypto.X509Certificate(signerDer).publicKey, signature)) {
    fail('receipt_signature', 'the receipt signature does not verify');
  }

  const fields = new Map();
  for (const entry of expect(parse(payload, 'receipt payload'), 0x31, 'receipt fields').children) {
    const [type, , value] = expect(entry, 0x30, 'receipt field').children;
    const key = integer(payload, type);
    if (fields.has(key)) fail('receipt', `the receipt repeats field ${key}`);
    fields.set(key, octets(payload, value));
  }
  const field = (key) => fields.get(key) || fail('receipt', `the receipt has no field ${key}`);
  if (field(RECEIPT.type).toString('utf8') !== 'ATTEST') fail('receipt', 'not an attestation receipt');
  if (field(RECEIPT.appId).toString('utf8') !== appId) fail('receipt_app_id', 'the receipt is for a different app');
  if (!field(RECEIPT.certificate).equals(credentialDer)) fail('receipt_key', 'the receipt is for a different key');
  if (!field(RECEIPT.clientHash).equals(hash)) fail('receipt_client', 'the receipt is for different client data');
  const created = new Date(field(RECEIPT.created).toString('utf8'));
  if (Number.isNaN(created.getTime())) fail('receipt', 'the receipt creation time is unreadable');
  if (created.getTime() < issuedAt.getTime() - RECEIPT_SKEW_MS || created.getTime() > now.getTime() + RECEIPT_SKEW_MS) {
    fail('receipt_time', 'the receipt was not created after the challenge');
  }
  return { created };
}

// --- Assertion -------------------------------------------------------------------------------------------

// Verifies an assertion from DCAppAttestService.generateAssertion(keyId, SHA-256(clientData)) against a
// stored key: publicKey (as verifyAttestation returned it) and counter (the last one accepted). Returns
// { counter }, the new value to store. The caller stores it atomically: a counter that doesn't rise is a
// replay. Throws AppAttestError otherwise.
function verifyAssertion({ assertion, clientData, appId, publicKey, counter } = {}) {
  if (typeof appId !== 'string' || appId.length === 0) fail('malformed', 'appId is required');
  if (!Number.isSafeInteger(counter) || counter < 0) fail('malformed', 'counter must be a non-negative integer');
  let key;
  try {
    key = crypto.createPublicKey({ key: bytes(publicKey, 'publicKey'), format: 'der', type: 'spki' });
  } catch (error) {
    if (error instanceof AppAttestError) throw error;
    fail('malformed', 'publicKey is not an SPKI key');
  }
  const object = cborMap(bytes(assertion, 'assertion'), 'assertion');
  const signature = object.get('signature');
  const authData = object.get('authenticatorData');
  if (!(signature instanceof Uint8Array) || !(authData instanceof Uint8Array)) fail('malformed', 'assertion is missing its parts');
  const data = Buffer.from(authData);
  const parsed = authenticatorData(data, { attested: false });
  const nonce = sha256(data, clientDataHash(clientData));
  if (!crypto.verify('sha256', nonce, key, Buffer.from(signature))) fail('signature', 'the assertion signature does not verify');
  if (!parsed.rpIdHash.equals(sha256(Buffer.from(appId, 'utf8')))) fail('app_id', 'the assertion is for a different app');
  if (parsed.counter <= counter) fail('counter', 'the counter did not rise');
  return { counter: parsed.counter };
}

const PINNED_ROOTS = { attestation: loadRoots(PINNED.attestation), receipt: loadRoots(PINNED.receipt) };

module.exports = { APP_ATTEST_ROOTS: PINNED, AppAttestError, verifyAssertion, verifyAttestation };
