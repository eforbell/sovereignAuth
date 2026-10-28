// Request guards (wire contract, section 4). Every service hostname in a tailnet is the same browser site
// (D20: ts.net is a public suffix), so SameSite cookies give no isolation between apps. These guards are
// what does: a mutation must come from this hostname's own pages, and on a strict hostname (sensitive apps,
// Home Base admin) nothing but its own pages and top-level navigations reaches the app at all.
//
// The core works on plain request data, { method, headers } with lower-case header names (Node's
// req.headers), so every framework adapter and the conformance vectors share one decision.

const SAFE_METHODS = new Set(['GET', 'HEAD']);
const FETCH_SITES = new Set(['same-origin', 'same-site', 'cross-site', 'none']);
const DEFAULT_CONTENT_TYPES = ['application/json'];

const MESSAGES = {
  fetch_metadata_missing: 'This address accepts requests only from browsers that send fetch metadata.',
  fetch_metadata_malformed: 'The request carries malformed fetch metadata.',
  not_same_origin: 'This address accepts only its own pages and top-level navigations.',
  origin_missing: 'Changes need an Origin header.',
  origin_mismatch: 'Changes are accepted only from this address\'s own pages.',
  fetch_site: 'Changes are accepted only from this address\'s own pages.',
  content_type: 'Changes are accepted only as application/json.',
};

// An exact origin: scheme, host and port, nothing else. 'https://example.ts.net/' and
// 'https://EXAMPLE.ts.net' both normalize to 'https://example.ts.net'; a path, query or credentials is a
// configuration mistake, not an origin.
function normalizeOrigin(value) {
  let url;
  try {
    url = new URL(String(value));
  } catch {
    throw new Error(`not an origin: ${value}`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new Error(`not an http(s) origin: ${value}`);
  if (url.username || url.password || url.search || url.hash || (url.pathname && url.pathname !== '/')) {
    throw new Error(`an origin has no path, query or credentials: ${value}`);
  }
  return url.origin;
}

function header(headers, name) {
  const value = headers?.[name];
  if (Array.isArray(value)) return value.join(', ');
  return value === undefined || value === null ? undefined : String(value);
}

function refused(reason) {
  return { allowed: false, status: 403, reason, message: MESSAGES[reason] };
}

// Resource isolation (D20), for strict hostnames: a request reaches the app only if the browser says it
// came from this origin, or it is a top-level document navigation (a link, a bookmark, a typed address).
// Anything else from a sibling hostname (fetch, image, script, iframe, form post) is refused before the app
// sees it, and so is a request with no fetch metadata: supported browsers always send it.
function checkIsolation(method, headers) {
  const site = header(headers, 'sec-fetch-site');
  if (site === undefined) return refused('fetch_metadata_missing');
  if (!FETCH_SITES.has(site)) return refused('fetch_metadata_malformed');
  if (site === 'same-origin') return null;
  const navigation = method === 'GET'
    && header(headers, 'sec-fetch-mode') === 'navigate'
    && header(headers, 'sec-fetch-dest') === 'document';
  return navigation ? null : refused('not_same_origin');
}

// The mutation guard, for every method but GET and HEAD on every hostname. The tailnet identity is ambient,
// like a cookie, so the Origin must be exactly this hostname's (same-site is not enough, D20). Requiring
// JSON keeps cross-site forms out even where fetch metadata is absent, because a form can't send it and a
// JSON request from elsewhere needs a preflight the app never grants.
function checkMutation(method, headers, { origins, contentTypes }) {
  const origin = header(headers, 'origin');
  if (origin === undefined || origin === '') return refused('origin_missing');
  if (!origins.has(origin)) return refused('origin_mismatch');
  const site = header(headers, 'sec-fetch-site');
  if (site !== undefined && site !== 'same-origin') return refused('fetch_site');
  const contentType = (header(headers, 'content-type') || '').split(';')[0].trim().toLowerCase();
  if (!contentTypes.has(contentType)) return refused('content_type');
  return null;
}

// createRequestGuard({ origin, isolate, contentTypes }):
// - origin: this hostname's origin, or a list of them (for example while a host moves to its service
//   hostname). Requests are compared to it exactly.
// - isolate: apply resource isolation (on by default for sensitive apps and Home Base admin; a low-friction
//   app turns it off and keeps only the mutation guard).
// - contentTypes: the media types a mutation may carry. Widening it (a file upload) keeps the Origin check
//   but loses the content type's protection in browsers without fetch metadata.
function createRequestGuard({ origin, isolate = true, contentTypes = DEFAULT_CONTENT_TYPES } = {}) {
  const list = [].concat(origin ?? []);
  if (!list.length) throw new Error('createRequestGuard needs this hostname\'s origin');
  const origins = new Set(list.map(normalizeOrigin));
  const types = new Set([].concat(contentTypes).map((type) => String(type).trim().toLowerCase()));
  if (!types.size) throw new Error('createRequestGuard needs at least one content type');

  function check({ method = 'GET', headers = {} } = {}) {
    const verb = String(method).toUpperCase();
    const decision = (isolate ? checkIsolation(verb, headers) : null)
      || (SAFE_METHODS.has(verb) ? null : checkMutation(verb, headers, { origins, contentTypes: types }));
    return decision || { allowed: true };
  }

  return { check, origins: [...origins], isolate: Boolean(isolate) };
}

module.exports = { createRequestGuard, normalizeOrigin };
