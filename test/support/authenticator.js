// A software authenticator and certificate factory for the WebAuthn tests. The authenticator makes the
// responses a browser passes on, with whatever flags, attestation and clientData a test needs; the factory
// makes attestation chains to roots that are not pinned anywhere.
const crypto = require('node:crypto');
const x509 = require('@peculiar/x509');
const { isoBase64URL, isoCBOR } = require('@simplewebauthn/server/helpers');

x509.cryptoProvider.set(crypto.webcrypto);

const ECDSA = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
const FLAGS = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40 };
const AAGUID_OID = '1.3.6.1.4.1.45724.1.1.4';
const DAY = 24 * 60 * 60 * 1000;

const b64 = (bytes) => isoBase64URL.fromBuffer(new Uint8Array(bytes));
const sha256 = (data) => crypto.createHash('sha256').update(data).digest();
const u32 = (value) => { const out = Buffer.alloc(4); out.writeUInt32BE(value); return out; };

function cosePublicKey(publicKey) {
  const jwk = publicKey.export({ format: 'jwk' });
  return Buffer.from(isoCBOR.encode(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]])));
}

function createAuthenticator({ aaguid = crypto.randomBytes(16), backupEligible = false, backedUp = false } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const rawId = crypto.randomBytes(16);
  const id = b64(rawId);
  let counter = 0;

  function flags({ userVerified = true, attested = false, eligible = backupEligible, backed = backedUp }) {
    return FLAGS.UP | (userVerified ? FLAGS.UV : 0) | (eligible ? FLAGS.BE : 0) | (backed ? FLAGS.BS : 0) | (attested ? FLAGS.AT : 0);
  }

  function clientData(type, options, { origin, extra = {} }) {
    return Buffer.from(JSON.stringify({ type, challenge: options.challenge, origin, crossOrigin: false, ...extra }));
  }

  // fmt 'packed' self-attests unless attestation gives { x5c, key }; other formats get an x5c and nothing else.
  function register(options, { origin, rpID = options.rp.id, fmt = 'none', attestation = null, extra, flagOptions = {} } = {}) {
    const clientDataJSON = clientData('webauthn.create', options, { origin, extra });
    const authData = Buffer.concat([
      sha256(rpID), Buffer.from([flags({ ...flagOptions, attested: true })]), u32(0),
      aaguid, Buffer.from([0, rawId.length]), rawId, cosePublicKey(publicKey),
    ]);
    let attStmt = new Map();
    if (fmt === 'packed') {
      const sig = crypto.sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), attestation?.key || privateKey);
      attStmt = new Map([['alg', -7], ['sig', sig]]);
      if (attestation) attStmt.set('x5c', attestation.x5c);
    } else if (fmt !== 'none') {
      attStmt = new Map([['alg', -7], ['sig', Buffer.alloc(64)], ['x5c', attestation?.x5c || []]]);
    }
    const attestationObject = isoCBOR.encode(new Map([['fmt', fmt], ['attStmt', attStmt], ['authData', authData]]));
    return {
      id,
      rawId: id,
      type: 'public-key',
      response: { clientDataJSON: b64(clientDataJSON), attestationObject: b64(attestationObject), transports: ['usb'] },
      clientExtensionResults: {},
      authenticatorAttachment: 'cross-platform',
    };
  }

  function authenticate(options, { origin, rpID = options.rpId, userHandle, extra, flagOptions = {}, signCount } = {}) {
    counter = signCount ?? counter + 1;
    const clientDataJSON = clientData('webauthn.get', options, { origin, extra });
    const authenticatorData = Buffer.concat([sha256(rpID), Buffer.from([flags(flagOptions)]), u32(counter)]);
    const signature = crypto.sign('sha256', Buffer.concat([authenticatorData, sha256(clientDataJSON)]), privateKey);
    const response = { clientDataJSON: b64(clientDataJSON), authenticatorData: b64(authenticatorData), signature: b64(signature) };
    if (userHandle !== undefined) response.userHandle = userHandle;
    return { id, rawId: id, type: 'public-key', response, clientExtensionResults: {} };
  }

  return { id, aaguid, register, authenticate };
}

// A certificate authority: a self-signed root, or an intermediate when issuer is given.
async function createCertificate({ name, issuer = null, ca = true, aaguid = null, crl = null, from = -DAY, to = 365 * DAY } = {}) {
  const keys = await crypto.webcrypto.subtle.generateKey(ECDSA, true, ['sign', 'verify']);
  const subject = ca ? `CN=${name}` : `C=US, O=Test Vendor, OU=Authenticator Attestation, CN=${name}`;
  const extensions = [
    new x509.BasicConstraintsExtension(ca, undefined, true),
    await x509.SubjectKeyIdentifierExtension.create(keys.publicKey),
  ];
  if (issuer) extensions.push(await x509.AuthorityKeyIdentifierExtension.create(issuer.cert));
  if (aaguid) extensions.push(new x509.Extension(AAGUID_OID, false, Buffer.concat([Buffer.from([0x04, 0x10]), aaguid])));
  if (crl) extensions.push(new x509.CRLDistributionPointsExtension([crl]));
  const fields = {
    serialNumber: crypto.randomBytes(8).toString('hex').replace(/^[89a-f]/, '1'),
    subject,
    notBefore: new Date(Date.now() + from),
    notAfter: new Date(Date.now() + to),
    signingAlgorithm: ECDSA,
    extensions,
  };
  const cert = issuer
    ? await x509.X509CertificateGenerator.create({ ...fields, issuer: issuer.cert.subject, publicKey: keys.publicKey, signingKey: issuer.keys.privateKey })
    : await x509.X509CertificateGenerator.createSelfSigned({ ...fields, name: subject, keys });
  return {
    cert,
    keys,
    der: Buffer.from(cert.rawData),
    key: crypto.KeyObject.from(keys.privateKey),
    pin: () => ({ name, fingerprint: new crypto.X509Certificate(Buffer.from(cert.rawData)).fingerprint256, pem: cert.toString('pem') }),
  };
}

module.exports = { createAuthenticator, createCertificate };
