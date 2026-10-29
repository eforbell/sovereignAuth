// Who is asking (wire contract, sections 2 and 3). In tailnet mode the member comes from the identity
// headers nginx sets, looked up in the directory snapshot by stable user ID; the login alone never
// identifies anyone (D1), and anything that doesn't line up exactly means no member.

const MODES = new Set(['local', 'tailnet']);
const TAGGED_LOGIN = 'tagged-devices';

// SOVEREIGN_AUTH_MODE: 'local' or 'tailnet'. Anything else, including nothing, is a configuration error:
// an app must not guess which kind of sign-in protects it.
function authMode(value) {
  const mode = String(value ?? '').trim();
  if (!MODES.has(mode)) throw new Error(`SOVEREIGN_AUTH_MODE must be local or tailnet, not ${value === undefined ? 'unset' : `'${value}'`}`);
  return mode;
}

// The identity headers are trustworthy only because nothing but nginx can connect to the app's socket
// (SID-002), so tailnet mode needs the app to be listening there.
function requireSocketListen(listen) {
  const value = String(listen ?? '').trim();
  if (!value.startsWith('unix:/')) throw new Error('tailnet mode needs SOVEREIGN_LISTEN=unix:<socket path>: identity headers are trusted only on the app\'s socket');
  return value;
}

function single(headers, name) {
  const value = headers?.[name];
  return typeof value === 'string' && value !== '' ? value : null;
}

// resolveMember(snapshot, headers, { appId }) returns { member } or { member: null, reason }.
function resolveMember(snapshot, headers, { appId }) {
  const userId = single(headers, 'x-sovereign-user-id');
  const login = single(headers, 'x-sovereign-login');
  if (!userId || !login) return { member: null, reason: 'no_identity' };
  if (login === TAGGED_LOGIN) return { member: null, reason: 'tagged' };
  const member = snapshot.byUserId.get(userId);
  if (!member) return { member: null, reason: 'unknown_user' };
  if (member.login !== login) return { member: null, reason: 'login_mismatch' };
  if (member.status !== 'active') return { member: null, reason: 'disabled' };
  if (!member.apps.includes(appId)) return { member: null, reason: 'no_access' };
  return { member };
}

// createIdentity({ appId, mode, listen, reader }).identify(headers) returns { member, reason, snapshot }:
// a member only in tailnet mode, with a good snapshot, and when every check passes. In local mode it
// always answers 'local_mode', and the app uses its own sign-in.
function createIdentity({ appId, mode, listen, reader }) {
  if (typeof appId !== 'string' || !appId) throw new Error('createIdentity needs the app\'s ID');
  const checkedMode = authMode(mode);
  if (checkedMode === 'tailnet') {
    requireSocketListen(listen);
    if (!reader || typeof reader.current !== 'function') throw new Error('tailnet mode needs a snapshot reader');
  }

  function identify(headers) {
    if (checkedMode === 'local') return { member: null, reason: 'local_mode', snapshot: null };
    const state = reader.current();
    if (!state.ok) return { member: null, reason: 'no_snapshot', snapshotReason: state.reason, snapshot: null };
    return { ...resolveMember(state.snapshot, headers, { appId }), snapshot: state.snapshot };
  }

  return { identify, mode: checkedMode, appId };
}

module.exports = { authMode, createIdentity, requireSocketListen, resolveMember };
