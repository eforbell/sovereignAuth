// Assurance (wire contract, sections 7 to 9; D12). An app names the protected action by its policy key, and
// the library decides from the policy matrix whether this request meets it: a member for 'tailnet', a
// fresh enough assurance cookie for 'session' and 'recent', and a redeemed action token bound to this exact
// request for 'every-time'. Anything short of that is answered before the app's handler runs.

const crypto = require('node:crypto');
const POLICY = require('./policy.json');
const { verifyToken } = require('./tokens');
const { createRedeemer } = require('./redeem');

const COOKIE_NAME = '__Host-sv_assurance';
const ACTION_HEADER = 'x-sovereign-action-token';
const KINDS = new Set(['synced', 'device-bound', 'hardware']);
const MAX_ACTION_LIFETIME_SECONDS = 60;

function policyFor(key) {
  const policy = Object.hasOwn(POLICY.policies, key) ? POLICY.policies[key] : null;
  if (!policy) throw new Error(`no assurance policy named ${key}`);
  return policy;
}

const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest();

// The request digest an action token is bound to (section 9). body is the raw bytes the app received.
function requestDigest({ method, url, body, target }) {
  checkTarget(target);
  let bytes = body ?? Buffer.alloc(0);
  if (typeof bytes === 'string') bytes = Buffer.from(bytes, 'utf8');
  if (!Buffer.isBuffer(bytes)) throw new Error('the request digest needs the raw body bytes, not a parsed body');
  const text = ['sovereign-action/1', String(method).toUpperCase(), String(url), sha256(bytes).toString('base64url'), target].join('\n');
  return sha256(Buffer.from(text, 'utf8')).toString('base64url');
}

function hasBody(headers = {}) {
  return headers['transfer-encoding'] !== undefined || Number(headers['content-length'] || 0) > 0;
}

function checkTarget(target) {
  if (typeof target !== 'string' || /[\r\n]/.test(target)) throw new Error('an action target is a string with no line breaks');
}

// Only a cookie named exactly __Host-sv_assurance counts. A sibling hostname can plant a same-named cookie
// without the prefix (D20), but not one with it; two with the prefixed name is not a question to guess at.
function assuranceCookie(headers) {
  const raw = headers?.cookie;
  const text = Array.isArray(raw) ? raw.join('; ') : typeof raw === 'string' ? raw : '';
  const values = [];
  for (const pair of text.split(';')) {
    const at = pair.indexOf('=');
    if (at < 0) continue;
    if (pair.slice(0, at).trim() === COOKIE_NAME) values.push(pair.slice(at + 1).trim());
  }
  if (values.length > 1) return { token: null, reason: 'duplicate_cookie' };
  return values.length ? { token: values[0], reason: null } : { token: null, reason: 'no_cookie' };
}

// What every token says about who and where, checked the same way for cookies and action tokens.
function claimsHold(payload, { typ, snapshot, member, hostname, policy }) {
  if (payload.typ !== typ) return 'wrong_type';
  if (payload.household !== snapshot.household) return 'wrong_household';
  if (payload.aud !== hostname) return 'wrong_audience';
  if (payload.sub !== member.userId) return 'wrong_member';
  if (payload.epoch !== member.epoch) return 'stale_epoch';
  if (payload.global_epoch !== snapshot.globalEpoch) return 'stale_global_epoch';
  if (!KINDS.has(payload.kind)) return 'wrong_kind';
  if (policy.kind === 'hardware' && payload.kind !== 'hardware') return 'wrong_kind';
  return null;
}

// createAssurance({ appId, hostname, identity, redeem, isAdministrator, now, log }).check(policyKey,
// { method, url, headers, body }, { target }) resolves to { allowed: true, member, level } or
// { allowed: false, status, body, reason }. hostname is this app's service hostname, which cookies and
// tokens must name exactly. isAdministrator(member) is required for policies that need an administrator
// (only Home Base has them: the flag is Home Base's, D10).
function createAssurance({ appId, hostname, identity, redeem, isAdministrator, now = Date.now, log = () => {} } = {}) {
  if (typeof appId !== 'string' || !appId) throw new Error('createAssurance needs the app\'s ID');
  if (typeof hostname !== 'string' || !/^[a-z0-9.-]+$/.test(hostname)) throw new Error('createAssurance needs this app\'s hostname, in lower case');
  if (!identity || identity.mode !== 'tailnet' || identity.appId !== appId) throw new Error('assurance needs this app\'s tailnet identity (createIdentity in tailnet mode)');
  const redeemToken = redeem || createRedeemer({ appId });

  const refuse = (status, body, reason) => ({ allowed: false, status, body, reason });

  function stepUp(key, policy, reason, extra = {}) {
    return refuse(401, { error: 'step_up_required', policy: key, level: policy.level, kind: policy.kind, ...extra }, reason);
  }

  function checkCookie(key, policy, headers, { snapshot, member }) {
    const { token, reason } = assuranceCookie(headers);
    if (!token) return stepUp(key, policy, reason);
    const verified = verifyToken(token, { keys: snapshot.keys, now });
    if (!verified.ok) return stepUp(key, policy, verified.reason);
    const claims = verified.payload;
    const wrong = claimsHold(claims, { typ: 'assurance', snapshot, member, hostname, policy });
    if (wrong) return stepUp(key, policy, wrong);
    const window = policy.level === 'recent' ? POLICY.recent_seconds : policy.window_seconds;
    const seconds = Math.floor(now() / 1000);
    if (!Number.isSafeInteger(claims.auth_time) || claims.auth_time > claims.iat) return stepUp(key, policy, 'malformed');
    if (seconds - claims.auth_time > window) return stepUp(key, policy, 'too_old');
    return null;
  }

  async function checkActionToken(key, policy, request, target, { snapshot, member }) {
    // Without the raw bytes the digest would cover an empty body, and the token would not bind what is sent.
    if (request.body === undefined && hasBody(request.headers)) throw new Error('every-time actions need the raw request body');
    const digest = requestDigest({ method: request.method, url: request.url, body: request.body, target });
    const challenge = (reason) => stepUp(key, policy, reason, { target, digest });
    const header = request.headers?.[ACTION_HEADER];
    if (header === undefined) return challenge('no_token');
    if (typeof header !== 'string') return challenge('malformed');
    const verified = verifyToken(header, { keys: snapshot.keys, now });
    if (!verified.ok) return challenge(verified.reason);
    const claims = verified.payload;
    const wrong = claimsHold(claims, { typ: 'action', snapshot, member, hostname, policy });
    if (wrong) return challenge(wrong);
    if (claims.app !== appId) return challenge('wrong_app');
    if (claims.act !== key) return challenge('wrong_action');
    if (claims.tgt !== target) return challenge('wrong_target');
    if (claims.dig !== digest) return challenge('wrong_digest');
    if (claims.exp - claims.iat > MAX_ACTION_LIFETIME_SECONDS) return challenge('malformed');
    if (typeof claims.jti !== 'string' || !claims.jti) return challenge('malformed');
    // Checked here, then redeemed: Home Base consumes the jti and rechecks the member as it stands now.
    const result = await redeemToken({ token: header, policy: key, target, digest });
    if (!result.redeemed) return refuse(403, { error: 'step_up_refused', policy: key, reason: result.reason }, `redemption_${result.reason}`);
    return null;
  }

  async function check(key, request, { target = '' } = {}) {
    const policy = policyFor(key);
    if (policy.level === 'every-time') checkTarget(target);
    if (policy.administrator && typeof isAdministrator !== 'function') throw new Error(`policy ${key} needs an administrator, so createAssurance needs isAdministrator`);
    const { member, reason, snapshot } = identity.identify(request.headers || {});
    let decision;
    if (!member) {
      decision = refuse(403, { error: 'not_a_member', reason }, reason);
    } else if (policy.administrator && !isAdministrator(member)) {
      decision = refuse(403, { error: 'not_authorized', policy: key }, 'not_administrator');
    } else if (policy.level === 'session' || policy.level === 'recent') {
      decision = checkCookie(key, policy, request.headers, { snapshot, member });
    } else if (policy.level === 'every-time') {
      decision = await checkActionToken(key, policy, request, target, { snapshot, member });
    } else {
      decision = null;
    }
    if (!decision) return { allowed: true, member, level: policy.level };
    const path = String(request.url || '/').split('?')[0];
    log(`[sovereign-auth] ${key} not met for ${request.method} ${path}: ${decision.reason}`);
    return decision;
  }

  return { check, appId, hostname };
}

// Writes a refusal from check() with Node's http.
function sendAssuranceRefusal(res, decision) {
  const body = JSON.stringify(decision.body);
  res.writeHead(decision.status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
}

// Express: assuranceExpress(assurance, policyKey, { target(req) }) as route middleware. Every-time actions
// need the raw body: keep it with express.json({ verify: (req, res, buf) => { req.rawBody = buf; } }).
function assuranceExpress(assurance, key, { target } = {}) {
  policyFor(key);
  return async function sovereignAssurance(req, res, next) {
    try {
      const resolvedTarget = target ? await target(req) : '';
      const body = req.rawBody ?? (Buffer.isBuffer(req.body) ? req.body : undefined);
      const decision = await assurance.check(key, { method: req.method, url: req.originalUrl || req.url, headers: req.headers, body }, { target: resolvedTarget });
      if (decision.allowed) {
        req.sovereignMember = decision.member;
        return next();
      }
      return sendAssuranceRefusal(res, decision);
    } catch (error) {
      return next(error);
    }
  };
}

module.exports = { ACTION_HEADER, COOKIE_NAME, POLICY, assuranceCookie, assuranceExpress, createAssurance, policyFor, requestDigest, sendAssuranceRefusal };
