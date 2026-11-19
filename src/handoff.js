// The native handoff (wire contract, section 13): a passkey check or every-time action asked for by a page in
// the household's native app, whose web view can't run the ceremony. The page begins a record, the app
// attests it with App Attest, a Safari sheet runs the ceremony against it, and the page redeems the result.
//
// This module keeps the records and makes every check on them. Home Base keeps the rest: which purposes a
// hostname may begin, the ceremony itself (createWebAuthn, with the handoff id in the challenge's binding),
// minting the cookie or token, and the app instances' keys.
//
// A record moves pending -> attested -> done -> taken, and each move is one conditional write in the store,
// so racing calls can't both win and a taken record never comes back.

const crypto = require('node:crypto');
const { AppAttestError, verifyAssertion } = require('./appattest');

const MAX_AGE_SECONDS = 300;
const COOKIE_PREFIX = '__Host-sv_handoff_';
const TAG_LENGTH = 16;
const ID = /^[A-Za-z0-9_-]{43}$/;
const KEY_ID = /^[A-Za-z0-9+/]{43}=$/;
const DIGEST = /^[A-Za-z0-9_-]{43}$/;
const HOSTNAME = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;
const SCHEME = /^[a-z][a-z0-9+.-]{2,31}$/;
const APP_ID = /^[A-Z0-9]{10}\.[A-Za-z0-9.-]+$/;
const MAX_ASSERTION_LENGTH = 4096;
const MAX_CLIENT_DATA_LENGTH = 4096;

const random = () => crypto.randomBytes(32).toString('base64url');
// Strict base64: the alphabet, and the one canonical spelling of the bytes.
const canonical = (text, pattern, encoding) => typeof text === 'string' && pattern.test(text) && Buffer.from(text, encoding).toString(encoding) === text;

function sameText(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

// What the app's App Attest assertion for a handoff signs (the client data whose SHA-256 it passes).
function handoffClientData(hostname, id) {
  if (typeof hostname !== 'string' || !HOSTNAME.test(hostname)) throw new Error('a handoff\'s hostname is in lower case');
  if (!canonical(id, ID, 'base64url')) throw new Error('a handoff id is 32 bytes in base64url');
  return Buffer.from(`sovereign-handoff/1\n${hostname}\n${id}`, 'utf8');
}

// What the app attests when it registers an app instance (Part 1).
function appInstanceClientData({ household, userId, challenge }) {
  for (const [name, value] of Object.entries({ household, userId, challenge })) {
    if (typeof value !== 'string' || !value || /[\r\n]/.test(value)) throw new Error(`${name} is text with no line breaks`);
  }
  return Buffer.from(`sovereign-app-instance/1\n${household}\n${userId}\n${challenge}`, 'utf8');
}

// The wire reason for an App Attest refusal, at registration or at attest.
function appInstanceReason(error) {
  if (!(error instanceof AppAttestError)) return 'malformed';
  switch (error.code) {
    case 'malformed':
    case 'format':
      return 'malformed';
    case 'app_id':
    case 'receipt_app_id':
      return 'wrong_app';
    case 'environment':
      return 'wrong_environment';
    case 'signature':
      return 'bad_signature';
    default:
      return 'untrusted_attestation';
  }
}

const cookieName = (id) => `${COOKIE_PREFIX}${id.slice(0, TAG_LENGTH)}`;
const setCookie = (id, value, maxAge) => `${cookieName(id)}=${value}; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age=${maxAge}`;

// The one cookie for this handoff: more than one with its name is refused, as section 7 refuses them.
function handoffCookie(headers, id) {
  const name = cookieName(id);
  const raw = headers?.cookie;
  const text = Array.isArray(raw) ? raw.join('; ') : typeof raw === 'string' ? raw : '';
  const values = [];
  for (const pair of text.split(';')) {
    const at = pair.indexOf('=');
    if (at >= 0 && pair.slice(0, at).trim() === name) values.push(pair.slice(at + 1).trim());
  }
  if (values.length > 1) return { value: null, reason: 'duplicate_cookie' };
  return values.length ? { value: values[0], reason: null } : { value: null, reason: 'no_cookie' };
}

const copy = (record) => (record ? structuredClone(record) : null);

// The default store: in memory, so a restart forgets handoffs in progress (they last five minutes). Any
// store works that provides, each as one atomic step:
// - put(record);
// - get(id): the record, or null;
// - update(id, expected, change): applies change only if the record exists and every field in expected
//   still has that value, and says whether it did. It never creates a record;
// - take(id): returns the record at most once, ever. Whoever takes it, it is gone.
function createMemoryHandoffStore({ maxEntries = 1000, now = Date.now } = {}) {
  const records = new Map();
  return {
    put(record) {
      for (const [id, entry] of records) {
        if (now() - entry.created > MAX_AGE_SECONDS * 1000 || records.size >= maxEntries) records.delete(id);
        else break;
      }
      records.set(record.id, copy(record));
    },
    get(id) {
      return copy(records.get(id));
    },
    update(id, expected, change) {
      const record = records.get(id);
      if (!record || !Object.entries(expected).every(([field, value]) => record[field] === value)) return false;
      Object.assign(record, copy(change));
      return true;
    },
    take(id) {
      const record = records.get(id) || null;
      records.delete(id);
      return record;
    },
  };
}

// The challenge an assertion answers, from its clientDataJSON, or null.
function assertionChallenge(assertion) {
  const encoded = assertion?.response?.clientDataJSON;
  if (typeof encoded !== 'string' || encoded.length > MAX_CLIENT_DATA_LENGTH) return null;
  try {
    const clientData = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    return typeof clientData?.challenge === 'string' && clientData.challenge ? clientData.challenge : null;
  } catch {
    return null;
  }
}

// createHandoff({ appId, scheme, store, instances, now }):
// - appId: the household's app, "<TEAMID>.<bundle id>" (Home Base's nativeApp setting);
// - scheme: the app's callback scheme, which finish returns to;
// - instances: the app instances' keys, with get(keyId) -> { userId, publicKey, counter } or null, and
//   advance(keyId, from, to) -> true only if the stored counter was still from and is now to.
//
// Every step takes the member the request resolves to and the hostname it came in on, and answers
// { ok: true, ... } or { ok: false, status, body, reason } for the caller to send.
function createHandoff({ appId, scheme, store = createMemoryHandoffStore(), instances, now = Date.now } = {}) {
  if (typeof appId !== 'string' || !APP_ID.test(appId)) throw new Error('createHandoff needs the household\'s app as <TEAMID>.<bundle id>');
  if (typeof scheme !== 'string' || !SCHEME.test(scheme)) throw new Error('createHandoff needs the app\'s callback scheme');
  for (const method of ['put', 'get', 'update', 'take']) {
    if (typeof store?.[method] !== 'function') throw new Error('a handoff store needs put, get, update and take');
  }
  if (typeof instances?.get !== 'function' || typeof instances?.advance !== 'function') throw new Error('createHandoff needs the app instances\' get and advance');
  const returnUrl = `${scheme}://sovereign-auth/done`;

  const refuse = (reason, { error = 'handoff_refused', clearCookie } = {}) => ({
    ok: false,
    status: reason === 'malformed' ? 400 : 403,
    body: { error, reason },
    reason,
    ...(clearCookie ? { clearCookie } : {}),
  });
  const refuseInstance = (reason) => refuse(reason, { error: 'app_instance_refused' });

  // The checks every step makes, in this order, on a record it read or took.
  function holds(record, { member, hostname }) {
    if (!record) return 'unknown_handoff';
    const age = now() - record.created;
    if (!(age >= 0 && age <= MAX_AGE_SECONDS * 1000)) return 'expired';
    if (!member?.userId || record.userId !== member.userId) return 'wrong_member';
    if (record.hostname !== hostname) return 'wrong_hostname';
    return null;
  }

  // A refusal for a conditional write that lost: whatever the record says now.
  async function lost(id, request, state) {
    const record = await store.get(id);
    return refuse(holds(record, request) || `not_${state}`);
  }

  const idOf = (body) => (canonical(body?.id, ID, 'base64url') ? body.id : null);

  // 1-2. From the page, after Home Base has made the same checks its options route makes. purpose is
  // 'check' or 'action'; kind is 'any' or 'hardware'; action is { target, digest } for an action and null
  // for a check. data is the caller's own, returned with the record at each later step.
  async function begin({ member, hostname, purpose, policy, kind, action = null, data = null }) {
    if (!member?.userId) throw new Error('a handoff begins for a member');
    if (typeof hostname !== 'string' || !HOSTNAME.test(hostname)) throw new Error('a handoff begins on a hostname, in lower case');
    if (purpose !== 'check' && purpose !== 'action') throw new Error('a handoff is for a check or an action');
    if (typeof policy !== 'string' || !policy) throw new Error('a handoff names its policy');
    if (kind !== 'any' && kind !== 'hardware') throw new Error('kind is any or hardware');
    if (purpose === 'check' && action !== null) throw new Error('a check has no action');
    if (purpose === 'action' && (typeof action?.target !== 'string' || /[\r\n]/.test(action.target) || typeof action?.digest !== 'string' || !DIGEST.test(action.digest))) {
      throw new Error('an action is { target, digest }');
    }
    const record = {
      id: random(),
      correlation: random(),
      userId: member.userId,
      hostname,
      purpose,
      policy,
      kind,
      action: action && { target: action.target, digest: action.digest },
      data,
      created: now(),
      state: 'pending',
      keyId: null,
      challenge: null,
      result: null,
    };
    await store.put(record);
    return { ok: true, id: record.id, body: { id: record.id }, setCookie: setCookie(record.id, record.correlation, MAX_AGE_SECONDS) };
  }

  // 3a. From the app: an App Attest assertion over the handoff, by a key registered to this member.
  async function attest({ member, hostname, body }) {
    const id = idOf(body);
    const { keyId, assertion } = body || {};
    if (!id || !canonical(keyId, KEY_ID, 'base64') || typeof assertion !== 'string' || !assertion || assertion.length > MAX_ASSERTION_LENGTH) return refuse('malformed');
    const request = { member, hostname };
    const record = await store.get(id);
    const wrong = holds(record, request);
    if (wrong) return refuse(wrong);
    if (record.state !== 'pending') return refuse('not_pending');

    const instance = await instances.get(keyId);
    if (!instance) return refuseInstance('unknown_key');
    if (instance.userId !== member.userId) return refuseInstance('wrong_member');
    let counter;
    try {
      ({ counter } = verifyAssertion({ assertion, clientData: handoffClientData(hostname, id), appId, publicKey: instance.publicKey, counter: instance.counter }));
    } catch (error) {
      if (error instanceof AppAttestError && error.code === 'counter') return refuseInstance('counter_not_increasing');
      return refuseInstance(appInstanceReason(error));
    }
    // Another assertion by this key got there first.
    if ((await instances.advance(keyId, instance.counter, counter)) !== true) return refuseInstance('counter_not_increasing');

    if (!(await store.update(id, { state: 'pending' }, { state: 'attested', keyId }))) return lost(id, request, 'pending');
    return { ok: true, body: {} };
  }

  // 3b. From the sheet, before its tap: issue(record) runs Home Base's options for the ceremony and returns
  // them; their challenge becomes the record's one live challenge. Home Base binds the handoff id into the
  // challenge as well, and builds the summary the sheet shows from the record.
  async function options({ member, hostname, body, issue }) {
    if (typeof issue !== 'function') throw new Error('options needs issue(record)');
    const id = idOf(body);
    if (!id) return refuse('malformed');
    const request = { member, hostname };
    const record = await store.get(id);
    const wrong = holds(record, request);
    if (wrong) return refuse(wrong);
    if (record.state !== 'attested') return refuse('not_attested');
    const issued = await issue(record);
    if (typeof issued?.challenge !== 'string' || !issued.challenge) throw new Error('issue(record) returns the ceremony\'s options, with its challenge');
    if (!(await store.update(id, { state: 'attested' }, { challenge: issued.challenge }))) return lost(id, request, 'attested');
    return { ok: true, record: { ...record, challenge: issued.challenge }, options: issued };
  }

  // 3b. From the sheet, after its tap: verify(record, assertion) runs Home Base's finish for the ceremony and
  // mints the result, returning { ok: true, result } (the assurance cookie's token, or the action token) or
  // a refusal to send as it is. No cookie is set in the sheet: the result waits on the record.
  async function finish({ member, hostname, body, verify }) {
    if (typeof verify !== 'function') throw new Error('finish needs verify(record, assertion)');
    const id = idOf(body);
    const challenge = assertionChallenge(body?.assertion);
    if (!id || !challenge) return refuse('malformed');
    const request = { member, hostname };
    const record = await store.get(id);
    const wrong = holds(record, request);
    if (wrong) return refuse(wrong);
    if (record.state !== 'attested') return refuse('not_attested');
    if (record.challenge === null || !sameText(record.challenge, challenge)) return refuse('stale_challenge');
    const verified = await verify(record, body.assertion);
    if (!verified?.ok) return verified;
    if (verified.result === undefined || verified.result === null) throw new Error('verify returns { ok: true, result }');
    if (!(await store.update(id, { state: 'attested', challenge }, { state: 'done', result: verified.result }))) {
      const current = await store.get(id);
      if (current?.state === 'attested') return refuse('stale_challenge');
      return lost(id, request, 'attested');
    }
    return { ok: true, body: { return: returnUrl } };
  }

  // 4-5. From the page, once the sheet has closed. The record is taken first, so it is used up whatever
  // happens next. On success the caller delivers result: as the assurance cookie for a check, as { token }
  // for an action. Every answer clears the handoff's cookie.
  async function redeem({ member, hostname, headers = {}, body }) {
    const id = idOf(body);
    if (!id) return refuse('malformed');
    const clearCookie = setCookie(id, '', 0);
    const record = await store.take(id);
    const wrong = holds(record, { member, hostname });
    if (wrong) return refuse(wrong, { clearCookie });
    if (record.state !== 'done') return refuse('not_done', { clearCookie });
    const cookie = handoffCookie(headers, id);
    if (!cookie.value) return refuse(cookie.reason, { clearCookie });
    if (!sameText(cookie.value, record.correlation)) return refuse('wrong_correlation', { clearCookie });
    return { ok: true, purpose: record.purpose, policy: record.policy, action: record.action, data: record.data, result: record.result, clearCookie };
  }

  return { begin, attest, options, finish, redeem, returnUrl };
}

module.exports = { HANDOFF_COOKIE_PREFIX: COOKIE_PREFIX, appInstanceClientData, appInstanceReason, createHandoff, createMemoryHandoffStore, handoffClientData, handoffCookie };
