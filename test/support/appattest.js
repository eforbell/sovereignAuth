// A fake Apple for the App Attest tests: its own attestation and receipt roots (pinned only by the tests that
// pin them), a device that attests keys and asserts with them, and knobs to get each part wrong. Real device
// output can't be published here, because it names the household's App ID; test/appattest.test.js runs it
// from a local file instead.
const crypto = require('node:crypto');
const x509 = require('@peculiar/x509');
const { isoCBOR } = require('@simplewebauthn/server/helpers');

x509.cryptoProvider.set(crypto.webcrypto);

const ECDSA = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
const DAY = 24 * 60 * 60 * 1000;
const OID = {
  nonce: '1.2.840.113635.100.8.2',
  receiptSigner: '1.2.840.113635.100.12.15',
  signedData: '1.2.840.113549.1.7.2',
  data: '1.2.840.113549.1.7.1',
  sha256: '2.16.840.1.101.3.4.2.1',
  ecdsaSha256: '1.2.840.10045.4.3.2',
  contentType: '1.2.840.113549.1.9.3',
};
const AAGUID = { production: Buffer.from('appattest\0\0\0\0\0\0\0', 'latin1'), development: Buffer.from('appattestdevelop', 'latin1') };

const sha256 = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts.map((p) => Buffer.from(p)))).digest();
const u32 = (value) => { const out = Buffer.alloc(4); out.writeUInt32BE(value); return out; };

// --- DER (and BER, for Apple's receipt form) -----------------------------------------------------------

function length(n) {
  if (n < 128) return Buffer.from([n]);
  const out = [];
  for (let x = n; x > 0; x = Math.floor(x / 256)) out.unshift(x & 255);
  return Buffer.from([0x80 | out.length, ...out]);
}
const tlv = (tag, ...parts) => { const body = Buffer.concat(parts.map((p) => Buffer.from(p))); return Buffer.concat([Buffer.from([tag]), length(body.length), body]); };
const open = (tag, ...parts) => Buffer.concat([Buffer.from([tag, 0x80]), ...parts.map((p) => Buffer.from(p)), Buffer.from([0, 0])]);
const int = (n) => tlv(0x02, Buffer.from([n]));
function oid(text) {
  const arcs = text.split('.').map(Number);
  const out = [40 * arcs[0] + arcs[1]];
  for (const arc of arcs.slice(2)) {
    const group = [arc & 0x7f];
    for (let x = Math.floor(arc / 128); x > 0; x = Math.floor(x / 128)) group.unshift((x & 0x7f) | 0x80);
    out.push(...group);
  }
  return tlv(0x06, Buffer.from(out));
}

// The children of a DER element's content, as [start, end] ranges.
function children(buf, start = 0) {
  let i = start + 1;
  let n = buf[i++];
  if (n & 0x80) { const count = n & 0x7f; n = 0; for (let k = 0; k < count; k++) n = n * 256 + buf[i++]; }
  const out = [];
  for (let at = i; at < i + n;) {
    let j = at + 1;
    let m = buf[j++];
    if (m & 0x80) { const count = m & 0x7f; m = 0; for (let k = 0; k < count; k++) m = m * 256 + buf[j++]; }
    out.push([at, j + m]);
    at = j + m;
  }
  return out;
}

// issuerAndSerialNumber for a certificate: SEQUENCE { issuer Name, serialNumber INTEGER }.
function issuerAndSerial(der) {
  const [tbs] = children(der);
  const fields = children(der, tbs[0]);
  const [serial, , issuer] = der[fields[0][0]] === 0xa0 ? fields.slice(1) : fields;
  return tlv(0x30, der.subarray(...issuer), der.subarray(...serial));
}

// --- Certificates ----------------------------------------------------------------------------------------

async function certificate({ name, issuer = null, ca = true, keys = null, extensions = [], from = -DAY, to = 365 * DAY }) {
  keys ||= await crypto.webcrypto.subtle.generateKey(ECDSA, true, ['sign', 'verify']);
  const fields = {
    serialNumber: crypto.randomBytes(8).toString('hex').replace(/^[89a-f]/, '1'),
    subject: `CN=${name}`,
    notBefore: new Date(Date.now() + from),
    notAfter: new Date(Date.now() + to),
    signingAlgorithm: ECDSA,
    extensions: [new x509.BasicConstraintsExtension(ca, undefined, true), ...extensions.map(([id, value]) => new x509.Extension(id, false, value))],
  };
  const cert = issuer
    ? await x509.X509CertificateGenerator.create({ ...fields, issuer: issuer.cert.subject, publicKey: keys.publicKey, signingKey: issuer.keys.privateKey })
    : await x509.X509CertificateGenerator.createSelfSigned({ ...fields, name: fields.subject, keys });
  const der = Buffer.from(cert.rawData);
  return {
    cert,
    keys,
    der,
    key: crypto.KeyObject.from(keys.privateKey),
    pin: () => ({ name, fingerprint: new crypto.X509Certificate(der).fingerprint256, pem: cert.toString('pem') }),
  };
}

// --- The receipt -----------------------------------------------------------------------------------------

// A receipt as Apple makes one: CMS SignedData over a SET of { type, version, value } fields, signed with no
// signed attributes. form 'ber' copies Apple's encoding: indefinite lengths and a payload split into pieces.
function receipt({ fields, signer, chain, form = 'der', signedAttributes = false, badSignature = false }) {
  const payload = tlv(0x31, ...Object.entries(fields)
    .filter(([, value]) => value !== undefined)
    .map(([type, value]) => tlv(0x30, int(Number(type)), int(1), tlv(0x04, value))));
  let signature = crypto.sign('sha256', payload, signer.key);
  if (badSignature) signature = crypto.sign('sha256', Buffer.concat([payload, Buffer.from([0])]), signer.key);
  const algorithm = (id) => tlv(0x30, oid(id), Buffer.from([0x05, 0x00]));
  const attributes = signedAttributes ? [tlv(0xa0, tlv(0x30, oid(OID.contentType), tlv(0x31, oid(OID.data))))] : [];
  const signerInfo = tlv(0x30, int(1), issuerAndSerial(signer.der), algorithm(OID.sha256), ...attributes, tlv(0x30, oid(OID.ecdsaSha256)), tlv(0x04, signature));
  const certificates = chain.map((c) => c.der);
  if (form === 'ber') {
    const pieces = [payload.subarray(0, 40), payload.subarray(40)].map((piece) => tlv(0x04, piece));
    return open(0x30, oid(OID.signedData), open(0xa0, open(0x30,
      int(1), tlv(0x31, algorithm(OID.sha256)),
      open(0x30, oid(OID.data), open(0xa0, open(0x24, ...pieces))),
      open(0xa0, ...certificates),
      tlv(0x31, signerInfo))));
  }
  return tlv(0x30, oid(OID.signedData), tlv(0xa0, tlv(0x30,
    int(1), tlv(0x31, algorithm(OID.sha256)),
    tlv(0x30, oid(OID.data), tlv(0xa0, tlv(0x04, payload))),
    tlv(0xa0, ...certificates),
    tlv(0x31, signerInfo))));
}

// --- Apple ---------------------------------------------------------------------------------------------

async function createFakeApple({ appId }) {
  const root = await certificate({ name: 'Fake App Attestation Root' });
  const intermediate = await certificate({ name: 'Fake App Attestation CA', issuer: root });
  const otherRoot = await certificate({ name: 'Unpinned Root' });
  const otherIntermediate = await certificate({ name: 'Unpinned CA', issuer: otherRoot });
  const receiptRoot = await certificate({ name: 'Fake Root CA - G3' });
  const receiptIntermediate = await certificate({ name: 'Fake Application Integration CA', issuer: receiptRoot });
  const receiptSigner = await certificate({ name: 'Fake Receipt Signing', issuer: receiptIntermediate, ca: false, extensions: [[OID.receiptSigner, Buffer.from([0x05, 0x00])]] });
  const developerSigner = await certificate({ name: 'A developer, not Apple', issuer: receiptIntermediate, ca: false });

  // A device key attested for clientData. `wrong` names the part to get wrong.
  async function attest({ clientData, environment = 'production', created = new Date(), wrong = {} }) {
    const keys = await crypto.webcrypto.subtle.generateKey(ECDSA, true, ['sign', 'verify']);
    const jwk = await crypto.webcrypto.subtle.exportKey('jwk', keys.publicKey);
    const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
    const keyId = wrong.keyId ? crypto.randomBytes(32) : sha256(point); // wrong.keyId: credential ID and keyId agree, but not with the key
    const cose = isoCBOR.encode(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
    const credentialId = wrong.credentialId ? crypto.randomBytes(32) : keyId;
    const authData = Buffer.concat([
      sha256(wrong.appId || appId), Buffer.from([0x40]), u32(wrong.counter || 0),
      wrong.aaguid || AAGUID[environment], Buffer.from([0, 32]), credentialId, cose,
    ]);
    const hash = sha256(clientData);
    const nonce = sha256(authData, wrong.nonce ? sha256('other client data') : hash);
    const issuer = wrong.chain ? otherIntermediate : intermediate;
    const leaf = await certificate({ name: 'Fake credential', issuer, ca: false, keys, extensions: [[OID.nonce, tlv(0x30, tlv(0xa1, tlv(0x04, nonce)))]] });
    let signer = wrong.receiptSigner ? developerSigner : receiptSigner;
    let chain = [signer, receiptIntermediate, receiptRoot];
    if (wrong.receiptRoot) {
      signer = await certificate({ name: 'Self-made signer', issuer: otherRoot, ca: false, extensions: [[OID.receiptSigner, Buffer.from([0x05, 0x00])]] });
      chain = [signer, otherRoot];
    }
    const fields = {
      2: Buffer.from(wrong.receiptAppId || appId),
      3: wrong.receiptKey ? (await certificate({ name: 'Another credential', issuer: intermediate, ca: false })).der : leaf.der,
      4: wrong.receiptClient ? sha256('other client data') : hash,
      5: crypto.randomBytes(16),
      6: Buffer.from(wrong.receiptType || 'ATTEST'),
      12: Buffer.from((wrong.receiptCreated || created).toISOString()),
      21: Buffer.from(new Date(created.getTime() + 90 * DAY).toISOString()),
    };
    const receiptDer = receipt({
      fields,
      signer,
      chain,
      form: wrong.form || 'der',
      signedAttributes: Boolean(wrong.signedAttributes),
      badSignature: Boolean(wrong.receiptSignature),
    });
    const object = isoCBOR.encode(new Map([
      ['fmt', wrong.fmt || 'apple-appattest'],
      ['attStmt', new Map([['x5c', [leaf.der, issuer.der]], ['receipt', receiptDer]])],
      ['authData', authData],
    ]));
    return {
      attestation: Buffer.from(object).toString('base64'),
      keyId: keyId.toString('base64'),
      device: { key: crypto.KeyObject.from(keys.privateKey), counter: 0 },
    };
  }

  // An assertion over clientData; the device's counter rises unless `counter` says otherwise.
  function assert(device, { clientData, counter = device.counter + 1, assertedAppId = appId }) {
    device.counter = counter;
    const authData = Buffer.concat([sha256(assertedAppId), Buffer.from([0x40]), u32(counter)]);
    const signature = crypto.sign('sha256', sha256(authData, sha256(clientData)), device.key);
    return Buffer.from(isoCBOR.encode(new Map([['signature', signature], ['authenticatorData', authData]]))).toString('base64');
  }

  return {
    roots: { attestation: [root.pin()], receipt: [receiptRoot.pin()] },
    attest,
    assert,
  };
}

module.exports = { createFakeApple };
