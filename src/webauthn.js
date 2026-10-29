// WebAuthn ceremonies for the suite (D11, D15, D17), around @simplewebauthn/server, with storage left to the
// caller. Every challenge is stored with the hostname that issued it, the member, the purpose, the audience and
// the action, and finishing checks all of them against what the request says, once. Ceremonies require user
// verification and never ask for PRF: they prove presence, nothing is derived from them.
//
// Credential kinds come from what the authenticator proves, never from what the member chose (bugBase #147):
// - synced: backup-eligible or backed up, so the key can leave the device;
// - device-bound: single-device, with no attestation we can verify;
// - hardware: single-device, with a packed attestation whose chain we verified to a pinned vendor root.
//
// We check attestation chains ourselves, before simplewebauthn sees the response: it skips chain checks when
// no roots are loaded into its process-wide settings, and for formats it ships roots for it fetches CRLs named
// in the client's own certificates. So only 'none' and 'packed' are accepted, and a packed chain must reach a
// pinned root here first; one that doesn't is refused, not downgraded.

const crypto = require('node:crypto');
const {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} = require('@simplewebauthn/server');
const { decodeAttestationObject, isoBase64URL } = require('@simplewebauthn/server/helpers');
const PINNED = require('./attestation-roots.json');

const CHALLENGE_SECONDS = 300;
const MAX_CHAIN = 4;
const ALGORITHMS = [-8, -7, -257];
const KINDS = ['synced', 'device-bound', 'hardware']; // weakest first
const PURPOSE = /^[a-z][a-z0-9-]{0,63}$/;
const HOSTNAME = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;

const certDate = (text) => new Date(text.replace(/ +/g, ' '));
const current = (cert, at) => certDate(cert.validFrom) <= at && at <= certDate(cert.validTo);
const signedBy = (cert, issuer) => cert.checkIssued(issuer) && cert.verify(issuer.publicKey);
const knownKind = (kind) => (KINDS.includes(kind) ? kind : 'synced');
const weaker = (a, b) => KINDS[Math.min(KINDS.indexOf(knownKind(a)), KINDS.indexOf(knownKind(b)))];

// Folds an assertion's update into the stored credential. The kind only falls, the counter only rises and
// the flags only widen, so two finishes stored in either order end the same way. Run it on the record as
// read in the transaction that writes it.
function mergeCredentialUpdate(stored, update) {
  return {
    ...stored,
    kind: weaker(stored.kind, update.kind),
    counter: Math.max(Number(stored.counter) || 0, Number(update.counter) || 0),
    deviceType: stored.deviceType === 'singleDevice' && update.deviceType === 'singleDevice' ? 'singleDevice' : 'multiDevice',
    backedUp: stored.backedUp !== false || update.backedUp !== false,
  };
}

// Roots as the attestation-roots.json format lists them; each PEM must match its recorded fingerprint.
function loadRoots(list = PINNED.roots) {
  return list.map(({ name, fingerprint, pem }) => {
    const cert = new crypto.X509Certificate(pem);
    if (cert.fingerprint256 !== fingerprint || !cert.ca) throw new Error(`attestation root ${name} does not match its fingerprint`);
    return { name, fingerprint, cert };
  });
}

// The pinned root an attestation chain (x5c: leaf first, DER) leads to, or null. Every certificate must be
// current; the leaf must not be a CA and each certificate after it must be one, signed in turn, and the last
// must be a pinned root or signed by one. A self-signed certificate along the way ends nothing.
function attestationRoot(x5c, roots, at) {
  if (!Array.isArray(x5c) || x5c.length === 0 || x5c.length > MAX_CHAIN) return null;
  let chain;
  try {
    chain = x5c.map((der) => new crypto.X509Certificate(Buffer.from(der)));
  } catch {
    return null;
  }
  if (chain[0].ca || !chain.every((cert) => current(cert, at))) return null;
  for (let i = 1; i < chain.length; i++) {
    if (!chain[i].ca || !signedBy(chain[i - 1], chain[i])) return null;
  }
  const last = chain.at(-1);
  return roots.find((root) => current(root.cert, at)
    && (last.fingerprint256 === root.fingerprint || signedBy(last, root.cert))) || null;
}

// The kind an authenticator's flags and a verified root support.
function credentialKind({ deviceType, backedUp, root }) {
  if (deviceType !== 'singleDevice' || backedUp !== false) return 'synced';
  return root ? 'hardware' : 'device-bound';
}

// Same order for every caller, so an action compares by value.
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value ?? null);
}

function parseClientData(encoded) {
  try {
    const clientData = JSON.parse(isoBase64URL.toUTF8String(encoded));
    return clientData && typeof clientData.challenge === 'string' ? clientData : null;
  } catch {
    return null;
  }
}

// The default store: in memory, so a restart forgets ceremonies in progress. Any store works that provides
// put(record) and take(challenge), where take returns the record at most once, ever.
function createMemoryChallengeStore({ maxEntries = 1000, now = Date.now } = {}) {
  const records = new Map();
  return {
    put(record) {
      for (const [challenge, entry] of records) {
        if (entry.expires < now() || records.size >= maxEntries) records.delete(challenge);
        else break;
      }
      records.set(record.challenge, record);
    },
    take(challenge) {
      const record = records.get(challenge) || null;
      records.delete(challenge);
      return record;
    },
  };
}

// createWebAuthn({ rpID, rpName, roots, store, now }):
// - rpID: the tailnet domain (D17), the same for every hostname in it;
// - roots: attestation roots in the attestation-roots.json format; the pinned list unless given. With none,
//   nothing is hardware and every attested registration is refused.
function createWebAuthn({ rpID, rpName = 'The Sovereign Home', roots = PINNED.roots, store = createMemoryChallengeStore(), now = Date.now } = {}) {
  if (typeof rpID !== 'string' || !HOSTNAME.test(rpID)) throw new Error('createWebAuthn needs the tailnet domain as rpID, in lower case');
  if (!store || typeof store.put !== 'function' || typeof store.take !== 'function') throw new Error('a challenge store needs put(record) and take(challenge)');
  const anchors = loadRoots(roots);

  function context({ hostname, member, purpose, audience = hostname, action = null }) {
    if (typeof hostname !== 'string' || !HOSTNAME.test(hostname) || !hostname.endsWith(`.${rpID}`)) throw new Error(`${hostname} is not a hostname in ${rpID}`);
    if (!member?.userId) throw new Error('a ceremony is for a member');
    if (typeof purpose !== 'string' || !PURPOSE.test(purpose)) throw new Error('a ceremony needs a purpose, like step-up or enroll');
    if (typeof audience !== 'string' || !audience) throw new Error('a ceremony\'s audience is a hostname or an app ID');
    return { hostname, userId: member.userId, purpose, audience, action: canonical(action) };
  }

  // Takes the record for this response's challenge and checks it against the request. The record is gone
  // whatever happens next, so a challenge gets one attempt.
  async function claim(ceremony, request, bound = {}) {
    const refuse = (reason) => ({ refusal: { ok: false, reason } });
    const expected = { ...context(request), ...bound };
    const clientData = parseClientData(request.response?.response?.clientDataJSON);
    if (!clientData) return refuse('malformed');
    const record = await store.take(clientData.challenge);
    if (!record) return refuse('unknown_challenge');
    if (!(now() <= record.expires)) return refuse('expired');
    if (record.ceremony !== ceremony) return refuse('wrong_ceremony');
    for (const field of ['hostname', 'userId', 'purpose', 'audience', 'action', ...Object.keys(bound)]) {
      if (record[field] !== expected[field]) return refuse(field === 'userId' ? 'wrong_member' : `wrong_${field}`);
    }
    // A ceremony in a frame, or run for another origin, is never ours (D17).
    if (clientData.crossOrigin !== undefined && clientData.crossOrigin !== false) return refuse('cross_origin');
    if (clientData.topOrigin !== undefined) return refuse('cross_origin');
    return { record };
  }

  const result = (record, fields) => ({ ok: true, purpose: record.purpose, audience: record.audience, action: JSON.parse(record.action), ...fields });

  // attestation: 'direct' only when enrolling a hardware key (SID-005); otherwise 'none'.
  async function registrationOptions({ attestation = 'none', excludeCredentials = [], ...request }) {
    const record = context(request);
    if (attestation !== 'none' && attestation !== 'direct') throw new Error('attestation is none or direct');
    const { member } = request;
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: Buffer.from(member.userId, 'utf8'),
      userName: member.login || member.userId,
      userDisplayName: member.name || member.login || member.userId,
      attestationType: attestation,
      excludeCredentials: excludeCredentials.map(({ id, transports }) => ({ id, transports })),
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      supportedAlgorithmIDs: ALGORITHMS,
      timeout: CHALLENGE_SECONDS * 1000,
    });
    await store.put({ challenge: options.challenge, ceremony: 'registration', ...record, attestation, expires: now() + CHALLENGE_SECONDS * 1000 });
    return options;
  }

  // Returns { ok, credential } with the credential to store, or { ok: false, reason }.
  async function verifyRegistration(request) {
    const { record, refusal } = await claim('registration', request);
    if (refusal) return refusal;
    let fmt;
    let x5c;
    try {
      const attestation = decodeAttestationObject(isoBase64URL.toBuffer(request.response.response.attestationObject));
      fmt = attestation.get('fmt');
      x5c = attestation.get('attStmt')?.get('x5c');
    } catch {
      return { ok: false, reason: 'malformed' };
    }
    if (fmt !== 'none' && fmt !== 'packed') return { ok: false, reason: 'unsupported_attestation' };
    const root = x5c === undefined ? null : attestationRoot(x5c, anchors, new Date(now()));
    if (x5c !== undefined && !root) return { ok: false, reason: 'untrusted_attestation' };
    let info;
    try {
      const verification = await verifyRegistrationResponse({
        response: request.response,
        expectedChallenge: record.challenge,
        expectedOrigin: `https://${record.hostname}`,
        expectedRPID: rpID,
        requireUserVerification: true,
        supportedAlgorithmIDs: ALGORITHMS,
      });
      if (!verification.verified) throw new Error('not verified');
      info = verification.registrationInfo;
    } catch (error) {
      return { ok: false, reason: 'not_verified', detail: error.message };
    }
    const flags = { deviceType: info.credentialDeviceType, backedUp: info.credentialBackedUp };
    const kind = credentialKind({ ...flags, root });
    return result(record, {
      credential: {
        id: info.credential.id,
        publicKey: isoBase64URL.fromBuffer(info.credential.publicKey),
        counter: info.credential.counter,
        transports: info.credential.transports || [],
        aaguid: info.aaguid,
        kind,
        // Which root it verified against, so that removing the root demotes it (SID-005).
        root: kind === 'hardware' ? root.fingerprint : null,
        ...flags,
      },
    });
  }

  // The kind a stored credential has now: never more than it registered as, synced once its flags say so,
  // and no longer hardware once the root it verified against is gone. The stored flags count as well as new
  // ones, so a key that once said it was backed up stays synced.
  function currentKind(credential, flags = credential) {
    const stored = knownKind(credential?.kind);
    const root = stored === 'hardware' ? anchors.find((anchor) => anchor.fingerprint === credential.root) : null;
    return [credential || {}, flags || {}].reduce((kind, seen) => weaker(kind, credentialKind({ deviceType: seen.deviceType, backedUp: seen.backedUp, root })), stored);
  }

  const requiredKind = (kind) => {
    if (kind !== 'any' && kind !== 'hardware') throw new Error('kind is any or hardware');
    return kind;
  };

  // credentials: the member's stored credentials. kind: 'hardware' when the policy needs it (D12).
  async function authenticationOptions({ credentials = [], kind = 'any', ...request }) {
    const record = context(request);
    requiredKind(kind);
    const usable = credentials.filter((credential) => kind === 'any' || currentKind(credential) === 'hardware');
    if (usable.length === 0) throw new Error(`the member has no ${kind === 'any' ? '' : 'hardware '}credential to use`);
    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: usable.map(({ id, transports }) => ({ id, transports })),
      userVerification: 'required',
      timeout: CHALLENGE_SECONDS * 1000,
    });
    await store.put({ challenge: options.challenge, ceremony: 'authentication', ...record, kind, expires: now() + CHALLENGE_SECONDS * 1000 });
    return options;
  }

  // kind is the policy's, as when the challenge was issued. Returns { ok, credentialId, kind, update }, or
  // { ok: false, reason }. A verified assertion always carries update ({ kind, counter, deviceType,
  // backedUp }), even when refused for its kind: the caller stores mergeCredentialUpdate(stored, update), so
  // a counter only moves forward and a kind that fell stays down, whichever finish is stored first.
  async function verifyAuthentication({ credentials = [], kind = 'any', ...request }) {
    const { record, refusal } = await claim('authentication', request, { kind: requiredKind(kind) });
    if (refusal) return refusal;
    const { response } = request;
    const credential = credentials.find((candidate) => candidate.id === response.id);
    if (!credential) return { ok: false, reason: 'unknown_credential' };
    const userHandle = response.response?.userHandle;
    if (userHandle !== undefined && userHandle !== null && userHandle !== isoBase64URL.fromUTF8String(record.userId)) return { ok: false, reason: 'wrong_member' };
    let info;
    try {
      const verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: record.challenge,
        expectedOrigin: `https://${record.hostname}`,
        expectedRPID: rpID,
        credential: {
          id: credential.id,
          publicKey: isoBase64URL.toBuffer(credential.publicKey),
          counter: credential.counter || 0,
          transports: credential.transports || [],
        },
        requireUserVerification: true,
      });
      if (!verification.verified) throw new Error('not verified');
      info = verification.authenticationInfo;
    } catch (error) {
      return { ok: false, reason: 'not_verified', detail: error.message };
    }
    const flags = { deviceType: info.credentialDeviceType, backedUp: info.credentialBackedUp };
    const update = { kind: currentKind(credential, flags), counter: info.newCounter, ...flags };
    if (record.kind === 'hardware' && update.kind !== 'hardware') return { ok: false, reason: 'insufficient_kind', credentialId: credential.id, update };
    return result(record, { credentialId: credential.id, kind: update.kind, update });
  }

  return { registrationOptions, verifyRegistration, authenticationOptions, verifyAuthentication, currentKind };
}

module.exports = { ATTESTATION_ROOTS: PINNED.roots, attestationRoot, createMemoryChallengeStore, createWebAuthn, credentialKind, loadRoots, mergeCredentialUpdate };
