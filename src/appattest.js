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
const RECEIPT_SKEW_MS = 60 * 1000; // Apple's clock against ours
const RECEIPT_MAX_AGE_MS = 5 * 60 * 1000; // Apple: a receipt is at most five minutes old
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
  if (!Number.isSafeInteger(i) || i < 0 || i + 2 > buf.length) fail('malformed', 'ASN.1 ends early');
  const start = i;
  const tag = buf[i++];
  if (tag === 0) fail('malformed', 'ASN.1 end-of-contents outside an indefinite length');
  if ((tag & 0x1f) === 0x1f) fail('malformed', 'ASN.1 high tag numbers are not used here');
  const constructed = (tag & 0x20) !== 0;
  let length = buf[i++];
  if (length === 0x80) {
    if (!constructed) fail('malformed', 'ASN.1 indefinite length on a primitive');
    const children = [];
    for (;;) {
      if (i + 2 > buf.length) fail('malformed', 'ASN.1 indefinite length never ends');
      if (buf[i] === 0 && buf[i + 1] === 0) break;
      const child = element(buf, i, depth + 1);
      children.push(child);
      i = child.end;
    }
    return { tag, constructed, start, contentStart: start + 2, contentEnd: i, end: i + 2, children };
  }
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4 || i + count > buf.length) fail('malformed', 'ASN.1 length is out of range');
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

// A constructed element's children, checking its tag and how many it has.
function parts(node, tag, what, min, max = min) {
  if (!node || node.tag !== tag || !node.children) fail('malformed', `${what} is missing`);
  if (node.children.length < min || node.children.length > max) fail('malformed', `${what} has ${node.children.length} parts`);
  return node.children;
}

// An OCTET STRING's bytes, joining the pieces of a constructed one.
function octets(buf, node) {
  if (node.tag === 0x04) return Buffer.from(content(buf, node));
  if (node.tag === 0x24) return Buffer.concat(node.children.map((child) => octets(buf, child)));
  return fail('malformed', 'expected an OCTET STRING');
}

// Every subidentifier is base-128, minimal and terminated; the first holds the first two arcs.
function oid(buf, node) {
  const value = content(buf, expect(node, 0x06, 'an object identifier'));
  const ids = [];
  let id = 0;
  let open = false;
  for (const byte of value) {
    if (!open && byte === 0x80) fail('malformed', 'object identifier is not minimal');
    id = id * 128 + (byte & 0x7f);
    if (id > Number.MAX_SAFE_INTEGER) fail('malformed', 'object identifier is out of range');
    open = (byte & 0x80) !== 0;
    if (!open) { ids.push(id); id = 0; }
  }
  if (open || ids.length === 0) fail('malformed', 'object identifier is cut short');
  const first = ids[0] < 40 ? 0 : ids[0] < 80 ? 1 : 2;
  return [first, ids[0] - first * 40, ...ids.slice(1)].join('.');
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

// Anything unreadable is refused as malformed, whatever part of the input it surfaced in.
function guarded(verify) {
  return (options) => {
    try {
      return verify(options);
    } catch (error) {
      if (error instanceof AppAttestError) throw error;
      throw new AppAttestError('malformed', `unreadable input: ${error.message}`);
    }
  };
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
  const sequence = parse(value, 'nonce extension');
  if (sequence.tag !== 0x30 || sequence.children.length !== 1 || sequence.children[0].tag !== 0xa1
    || sequence.children[0].children.length !== 1 || sequence.children[0].children[0].tag !== 0x04) {
    fail('nonce', 'the nonce extension has an unexpected shape');
  }
  const nonce = octets(value, sequence.children[0].children[0]);
  if (nonce.length !== 32) fail('nonce', 'the nonce extension has an unexpected shape');
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
// receiptCreated (Date) }. Throws AppAttestError otherwise (verifyAttestation, below, is this guarded).
function attestationChecks({ attestation, keyId, clientData, appId, issuedAt, environments = ['production'], now = new Date(), roots } = {}) {
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
  const [contentType, wrapped] = parts(parse(buf, 'receipt'), 0x30, 'receipt ContentInfo', 2);
  if (oid(buf, contentType) !== OID.signedData) fail('receipt', 'the receipt is not SignedData');
  // SignedData: version, digestAlgorithms, encapContentInfo, [0] certificates, signerInfos.
  const [, , encapsulated, bag, signerInfos] = parts(parts(wrapped, 0xa0, 'receipt content', 1)[0], 0x30, 'SignedData', 5);
  const [encapsulatedType, encapsulatedContent] = parts(encapsulated, 0x30, 'receipt encapsulated content', 2);
  if (oid(buf, encapsulatedType) !== OID.data) fail('receipt', 'the receipt content is not data');
  const payload = octets(buf, parts(encapsulatedContent, 0xa0, 'receipt payload', 1)[0]);
  const certificates = parts(bag, 0xa0, 'receipt certificates', 1, 8).map((child) => Buffer.from(raw(buf, child)));
  const signers = parts(signerInfos, 0x31, 'receipt signers', 0, 8);
  if (signers.length !== 1) fail('receipt', 'the receipt must have one signer');

  // SignerInfo: version, sid (issuerAndSerialNumber), digestAlgorithm, signatureAlgorithm, signature. Five
  // parts and no more: signed or unsigned attributes would make six or seven.
  const signer = parts(signers[0], 0x30, 'receipt signer', 1, 7);
  if (signer.length !== 5) fail('receipt', 'the receipt signer has attributes');
  const [, sid, digestAlgorithm, signatureAlgorithm, signatureNode] = signer;
  if (oid(buf, parts(digestAlgorithm, 0x30, 'receipt digest algorithm', 1, 2)[0]) !== OID.sha256
    || oid(buf, parts(signatureAlgorithm, 0x30, 'receipt signature algorithm', 1, 2)[0]) !== OID.ecdsaSha256) {
    fail('receipt', 'the receipt is not signed with ECDSA and SHA-256');
  }
  const [issuerNode, serialNode] = parts(sid, 0x30, 'receipt signer identifier', 2);
  const issuer = raw(buf, expect(issuerNode, 0x30, 'receipt signer issuer'));
  const serial = content(buf, expect(serialNode, 0x02, 'receipt signer serial'));
  const signerDer = certificates.find((der) => {
    const tbs = parts(parse(der, 'certificate'), 0x30, 'certificate', 3)[0];
    const fields = parts(tbs, 0x30, 'tbsCertificate', 6, 10);
    const [serialField, , issuerField] = fields[0].tag === 0xa0 ? fields.slice(1) : fields;
    return content(der, serialField).equals(serial) && raw(der, issuerField).equals(issuer);
  });
  if (!signerDer) fail('receipt', 'the receipt signer certificate is missing');

  // The signer chains to the pinned receipt root and carries Apple's receipt-signing marker, which no
  // other certificate under that root (a developer's, say) does.
  const anchored = (cert) => roots.some((root) => cert.fingerprint256 === root.fingerprint
    || (cert.checkIssued(root.cert) && cert.verify(root.cert.publicKey)));
  const chain = [signerDer];
  while (chain.length < 4) {
    const last = new crypto.X509Certificate(chain.at(-1));
    if (anchored(last)) break;
    const next = certificates.find((der) => !chain.some((c) => c.equals(der))
      && last.checkIssued(new crypto.X509Certificate(der)) && last.verify(new crypto.X509Certificate(der).publicKey));
    if (!next) break;
    chain.push(next);
  }
  if (!attestationRoot(chain, roots, now)) fail('receipt_chain', 'the receipt does not chain to the receipt root');
  if (!extensions(signerDer).has(OID.receiptSigner)) fail('receipt_signer', 'the receipt signer is not a receipt-signing certificate');
  const signature = octets(buf, expect(signatureNode, 0x04, 'receipt signature'));
  if (!crypto.verify('sha256', payload, new crypto.X509Certificate(signerDer).publicKey, signature)) {
    fail('receipt_signature', 'the receipt signature does not verify');
  }

  const fields = new Map();
  for (const entry of expect(parse(payload, 'receipt payload'), 0x31, 'receipt fields').children) {
    const [type, version, value] = parts(entry, 0x30, 'receipt field', 3);
    const key = integer(payload, type);
    integer(payload, version);
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
  const at = created.getTime();
  if (at < issuedAt.getTime() - RECEIPT_SKEW_MS || at < now.getTime() - RECEIPT_MAX_AGE_MS || at > now.getTime() + RECEIPT_SKEW_MS) {
    fail('receipt_time', 'the receipt was not created after the challenge, in the last five minutes');
  }
  return { created };
}

// --- Assertion -------------------------------------------------------------------------------------------

// Verifies an assertion from DCAppAttestService.generateAssertion(keyId, SHA-256(clientData)) against a
// stored key: publicKey (as verifyAttestation returned it) and counter (the last one accepted). Returns
// { counter }, the new value to store. The caller stores it atomically: a counter that doesn't rise is a
// replay. Throws AppAttestError otherwise (verifyAssertion, below, is this guarded).
function assertionChecks({ assertion, clientData, appId, publicKey, counter } = {}) {
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

const verifyAttestation = guarded(attestationChecks);
const verifyAssertion = guarded(assertionChecks);
const PINNED_ROOTS = { attestation: loadRoots(PINNED.attestation), receipt: loadRoots(PINNED.receipt) };

module.exports = { APP_ATTEST_ROOTS: PINNED, AppAttestError, verifyAssertion, verifyAttestation };
