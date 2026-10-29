// OAuth and other external callbacks (wire contract, section 10; D22): the one route allowed to act on URL
// parameters, and only in three steps. Start (a guarded POST) stores a single-use state record bound to the
// member, this hostname and a __Host- correlation cookie. Landing (the provider's redirect, a GET) changes
// nothing and needs no cookie: it renders a page that strips code and state from the address bar and sends
// them once. Completion (a same-origin JSON POST from that page, behind the mutation guard) takes the record,
// checks everything, and only then hands the app the code to exchange.

const crypto = require('node:crypto');

const COOKIE_NAME = '__Host-sv_oauth';
const MAX_AGE_SECONDS = 600;
const MAX_CODE_LENGTH = 4096;
const STATE = /^[A-Za-z0-9_-]{43}$/;

const random = () => crypto.randomBytes(32).toString('base64url');
// PKCE S256 (RFC 7636): the challenge is base64url(SHA-256(verifier)).
const pkceChallenge = (verifier) => crypto.createHash('sha256').update(verifier, 'ascii').digest('base64url');

function sameText(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

// The default store: in memory, so a restart forgets flows in progress (they last ten minutes anyway).
// Any store works that provides put(record) and take(state), where take returns the record at most once,
// ever: whoever takes it, it is gone.
function createMemoryStateStore({ maxEntries = 1000, now = Date.now } = {}) {
  const records = new Map();
  return {
    put(record) {
      for (const [state, entry] of records) {
        if (now() - entry.created > MAX_AGE_SECONDS * 1000 || records.size >= maxEntries) records.delete(state);
        else break;
      }
      records.set(record.state, record);
    },
    take(state) {
      const record = records.get(state) || null;
      records.delete(state);
      return record;
    },
  };
}

function oauthCookie(headers) {
  const raw = headers?.cookie;
  const text = Array.isArray(raw) ? raw.join('; ') : typeof raw === 'string' ? raw : '';
  const values = [];
  for (const pair of text.split(';')) {
    const at = pair.indexOf('=');
    if (at >= 0 && pair.slice(0, at).trim() === COOKIE_NAME) values.push(pair.slice(at + 1).trim());
  }
  if (values.length > 1) return { value: null, reason: 'duplicate_cookie' };
  return values.length ? { value: values[0], reason: null } : { value: null, reason: 'no_cookie' };
}

const setCookie = (value, maxAge) => `${COOKIE_NAME}=${value}; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age=${maxAge}`;
const CLEAR_COOKIE = setCookie('', 0);

// A same-origin path for the page to post to: no scheme, no host, nothing a browser could read as another
// origin.
function checkRelativePath(value, what) {
  if (typeof value !== 'string' || !value || /[:\\\s]/.test(value) || value.startsWith('//')) throw new Error(`${what} must be a path on this hostname`);
  return value;
}

// The landing page's script, with its two settings passed as JSON that can't close the script element.
const scriptJson = (value) => JSON.stringify(value).replace(/</g, '\\u003c');

function landingScript({ completionPath, donePath }) {
  return `(() => {
  const say = (text) => { document.getElementById('status').textContent = text; };
  const params = new URLSearchParams(location.search);
  const code = params.get('code');
  const state = params.get('state');
  const error = params.get('error');
  history.replaceState(null, '', location.pathname);
  if (!code || !state) { say(error ? 'The provider did not link the account (' + error + ').' : 'Nothing to finish here.'); return; }
  fetch(${scriptJson(completionPath)}, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ code, state }),
  }).then((response) => response.json().catch(() => ({})).then((body) => {
    if (response.ok) location.replace(${scriptJson(donePath)});
    else say('Linking did not finish (' + (body.reason || response.status) + '). Start again from the app.');
  })).catch(() => say('Linking did not finish. Start again from the app.'));
})();`;
}

// createOAuthFlow({ hostname, landingPath, completionPath, donePath, store, now }):
// - hostname: this app's service hostname (lower case), which the record and the Referer must name;
// - landingPath: the provider's redirect target as the browser sees it (with any mount prefix);
// - completionPath, donePath: where the landing page posts, and where it goes after; relative to it or
//   absolute paths on this hostname.
function createOAuthFlow({ hostname, landingPath, completionPath, donePath = '.', store = createMemoryStateStore(), now = Date.now } = {}) {
  if (typeof hostname !== 'string' || !/^[a-z0-9.-]+$/.test(hostname)) throw new Error('createOAuthFlow needs this app\'s hostname, in lower case');
  if (typeof landingPath !== 'string' || !landingPath.startsWith('/') || landingPath.startsWith('//') || /[?#\s]/.test(landingPath)) throw new Error('landingPath is the callback\'s absolute path as the browser sees it');
  checkRelativePath(completionPath, 'completionPath');
  checkRelativePath(donePath, 'donePath');
  if (!store || typeof store.put !== 'function' || typeof store.take !== 'function') throw new Error('an OAuth state store needs put(record) and take(state)');
  const landingUrl = `https://${hostname}${landingPath}`;

  // Step 1, from the app's guarded POST. The app sends the browser to the provider with state (and the
  // PKCE challenge, unless the provider has no PKCE) and sets the cookie. data is the app's own, returned
  // at completion (which provider, say).
  async function start(member, { pkce = true, data = null } = {}) {
    if (!member?.userId) throw new Error('an OAuth flow starts for a member');
    const record = { state: random(), userId: member.userId, hostname, correlation: random(), codeVerifier: pkce ? random() : null, created: now(), data };
    await store.put(record);
    return {
      state: record.state,
      codeChallenge: pkce ? pkceChallenge(record.codeVerifier) : null,
      codeChallengeMethod: pkce ? 'S256' : null,
      setCookie: setCookie(record.correlation, MAX_AGE_SECONDS),
    };
  }

  // Step 2, the provider's redirect: the same page for every request, no cookie read, nothing stored.
  // Referrer-Policy same-origin lets the completion route see that this page sent it, and nothing
  // leaves for other sites.
  function landing({ nonce } = {}) {
    if (nonce !== undefined && !/^[A-Za-z0-9+/=_-]+$/.test(nonce)) throw new Error('a CSP nonce is base64');
    const body = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Linking…</title></head>
<body><p id="status">Finishing the link…</p>
<script${nonce ? ` nonce="${nonce}"` : ''}>${landingScript({ completionPath, donePath })}</script></body></html>
`;
    return {
      status: 200,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'referrer-policy': 'same-origin',
      },
      body,
    };
  }

  // Step 3, behind the mutation guard. The record is taken before anything else is checked, so a code and
  // state can be tried once, by anyone, and then never again.
  async function complete({ member, headers = {}, body }) {
    const refuse = (status, reason) => ({ ok: false, status, body: { error: 'oauth_refused', reason }, reason, clearCookie: CLEAR_COOKIE });
    const code = body?.code;
    const state = body?.state;
    if (typeof code !== 'string' || !code || code.length > MAX_CODE_LENGTH || typeof state !== 'string' || !STATE.test(state)) return refuse(400, 'malformed');
    const record = await store.take(state);
    if (!record) return refuse(403, 'unknown_state');
    const age = now() - record.created;
    if (!(age >= 0 && age <= MAX_AGE_SECONDS * 1000)) return refuse(403, 'expired');
    if (!member?.userId || record.userId !== member.userId) return refuse(403, 'wrong_member');
    if (record.hostname !== hostname) return refuse(403, 'wrong_hostname');
    const cookie = oauthCookie(headers);
    if (!cookie.value) return refuse(403, cookie.reason);
    if (!sameText(cookie.value, record.correlation)) return refuse(403, 'wrong_correlation');
    if (headers.referer !== landingUrl) return refuse(403, 'not_from_landing');
    return { ok: true, code, codeVerifier: record.codeVerifier, data: record.data, clearCookie: CLEAR_COOKIE };
  }

  return { start, landing, complete, landingUrl };
}

module.exports = { OAUTH_COOKIE_NAME: COOKIE_NAME, createMemoryStateStore, createOAuthFlow, pkceChallenge };
