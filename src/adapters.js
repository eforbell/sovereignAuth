// Framework adapters for the request guard. Both take the guard's decision as is; they only decide what
// happens to a refused request. Modes:
// - 'enforce' answers 403 with the refusal body (wire contract, section 4.4) and stops the request;
// - 'report' logs what enforce would refuse and lets the request through, to see what a rollout would
//   break before it does;
// - 'off' lets everything through silently, so callers keep one code path behind a flag.

const MODES = new Set(['off', 'report', 'enforce']);

function requireMode(mode) {
  if (!MODES.has(mode)) throw new Error(`request guard mode must be off, report or enforce, not ${mode}`);
  return mode;
}

// The log line names the method, the path without its query (a query can carry an OAuth code), the reason
// and the two headers that decided it. Never the identity headers or cookies.
function describeRefusal(decision, req, mode) {
  const path = String(req.url || '/').split('?')[0];
  const origin = req.headers?.origin ?? '-';
  const site = req.headers?.['sec-fetch-site'] ?? '-';
  const verb = mode === 'report' ? 'would refuse' : 'refused';
  return `[sovereign-auth] ${verb} ${req.method} ${path}: ${decision.reason} (origin ${origin}, sec-fetch-site ${site})`;
}

function refusalBody(decision) {
  return { error: 'request_refused', reason: decision.reason, message: decision.message };
}

function sendRefusal(res, decision) {
  const body = JSON.stringify(refusalBody(decision));
  res.writeHead(decision.status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
  });
  res.end(body);
}

function decide(guard, req, { mode, log }) {
  if (mode === 'off') return null;
  const decision = guard.check({ method: req.method, headers: req.headers });
  if (decision.allowed) return null;
  log(describeRefusal(decision, req, mode));
  return mode === 'enforce' ? decision : null;
}

// Node's http: guardHttp(guard, options)(req, res) returns true when the handler may go on; on false the
// response has been sent.
function guardHttp(guard, { mode = 'enforce', log = console.warn } = {}) {
  requireMode(mode);
  return function guardRequest(req, res) {
    const refusal = decide(guard, req, { mode, log });
    if (!refusal) return true;
    sendRefusal(res, refusal);
    return false;
  };
}

// Express (or anything with (req, res, next) middleware).
function guardExpress(guard, { mode = 'enforce', log = console.warn } = {}) {
  requireMode(mode);
  return function sovereignRequestGuard(req, res, next) {
    const refusal = decide(guard, req, { mode, log });
    if (!refusal) return next();
    sendRefusal(res, refusal);
  };
}

module.exports = { guardExpress, guardHttp, refusalBody };
