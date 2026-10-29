# sovereignAuth

Suite identity for The Sovereign Home: the shared library that lets apps managed by [Home Base](https://github.com/eforbell/homeBase) trust a household member's tailnet identity, and ask for a passkey when an action needs one.

Work in progress (Home Base Feature-10, story SID-003). The [wire contract](docs/wire-contract.md) says what is implemented and what is still only agreed.

## Install

Apps take it as a git dependency pinned to a commit, so hosts need no GitHub credentials and no registry:

```json
"dependencies": {
  "sovereign-auth": "github:eforbell/sovereignAuth#<commit>"
}
```

Plain CommonJS for Node 22 and later, with no build step, no install scripts and no dependencies of its own.

## Request guards

The guards come first because every service hostname in a tailnet is the same browser site, so cookies' SameSite gives no isolation between apps (contract, section 4).

```js
const { createRequestGuard, guardHttp, guardExpress } = require('sovereign-auth');

// A sensitive app or Home Base admin: isolation and the mutation guard.
const guard = createRequestGuard({ origin: 'https://smith-pulse.example-tailnet.ts.net' });

// A low-friction app on the shared hostname: the mutation guard only.
const shared = createRequestGuard({ origin: 'https://smith-home.example-tailnet.ts.net', isolate: false });

// Express
app.use(guardExpress(guard, { mode: 'enforce' }));

// Node's http
const guardRequest = guardHttp(guard, { mode: 'report' });
http.createServer((req, res) => {
  if (!guardRequest(req, res)) return;
  // …
});
```

`mode` is `enforce` (answer 403 and stop), `report` (log what enforce would refuse, then go on) or `off`. The core, `guard.check({ method, headers })`, returns `{ allowed: true }` or `{ allowed: false, status: 403, reason, message }` for any other framework.

With isolation on, the adapters also add `Vary: Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest` to every response, so the browser never hands a cached response to a request the guard would refuse. An app that sets `Vary` itself appends to it; an adapter for another framework must add it too (contract, section 4.1).

## Who is asking

In tailnet mode the member comes from the identity headers nginx sets, looked up in the directory snapshot Home Base publishes (contract, sections 2, 3 and 5).

```js
const { createIdentity, createSnapshotReader } = require('sovereign-auth');

const identity = createIdentity({
  appId: 'family-pulse',
  mode: process.env.SOVEREIGN_AUTH_MODE,          // 'local' or 'tailnet'; anything else throws
  listen: process.env.SOVEREIGN_LISTEN,           // tailnet mode requires unix:<socket>
  reader: createSnapshotReader({ homeBaseUid: Number(process.env.SOVEREIGN_HOMEBASE_UID) }),
});

const { member, reason } = identity.identify(req.headers);
// member: { memberId, userId, login, name, role, status, epoch, apps } or null, with a reason such as
// 'no_identity', 'unknown_user', 'login_mismatch', 'disabled', 'no_access' or 'no_snapshot'.
```

The reader trusts the snapshot only while the file and its directory belong to the Home Base user and nothing on the path is a symlink or writable by anyone else; it refuses a snapshot older than 120 seconds or older than one it has already seen.

`readOwnedFile(file, { uid })` applies the same ownership rules to any small file, for configuration a trusted user writes (Home Base reads root's with `uid: 0`).

## Assurance

For actions that need more than a member: a passkey session, a recent ceremony, or a fresh hardware-key tap bound to this exact request (contract, sections 6 to 9). The app names the action by its key in the policy matrix (`src/policy.json`); the level, credential kind and window come from there.

```js
const { createAssurance, assuranceExpress, sendAssuranceRefusal } = require('sovereign-auth');

const assurance = createAssurance({
  appId: 'family-pulse',
  hostname: 'smith-pulse.example-tailnet.ts.net',  // cookies and tokens must name it exactly
  identity,                                         // createIdentity in tailnet mode
});

// Express: a passkey ceremony in the last five minutes before an export.
app.post('/api/export', assuranceExpress(assurance, 'export-data'), handler);

// Node's http
const decision = await assurance.check('open-documents', { method: req.method, url: req.url, headers: req.headers });
if (!decision.allowed) return sendAssuranceRefusal(res, decision);  // 401 step_up_required, or 403
```

Every-time actions (Home Base's privileged plans) also pass the `target` the request will act on, and the raw body, which the action token's digest covers; the token is then redeemed with Home Base over `/run/sovereign-identity/<app>.sock` before the handler runs. The library verifies tokens; Home Base issues them (SID-005).

## Linking external accounts (OAuth)

The one place an app acts on URL parameters, in three steps (contract, section 10): a guarded `POST` starts the flow, the provider's redirect lands on a page that changes nothing, and that page posts `code` and `state` back once.

```js
const { createOAuthFlow } = require('sovereign-auth');

const oauth = createOAuthFlow({
  hostname: 'smith-helm.example-tailnet.ts.net',
  landingPath: '/oauth/callback',   // the redirect URI's path, as the browser sees it
  completionPath: 'complete',       // relative to the landing page
  donePath: '../settings',
});

app.post('/api/link', async (req, res) => {                       // behind the mutation guard
  const { state, codeChallenge, setCookie } = await oauth.start(req.sovereignMember, { data: { provider: 'schwab' } });
  res.setHeader('set-cookie', setCookie);
  res.json({ url: providerAuthorizeUrl({ state, codeChallenge }) });
});
app.get('/oauth/callback', (req, res) => {
  const page = oauth.landing();
  res.status(page.status).set(page.headers).send(page.body);
});
app.post('/oauth/complete', async (req, res) => {                 // behind the mutation guard
  const result = await oauth.complete({ member: req.sovereignMember, headers: req.headers, body: req.body });
  res.setHeader('set-cookie', result.clearCookie);
  if (!result.ok) return res.status(result.status).json(result.body);
  await exchangeCode(result.code, result.codeVerifier);
  res.json({ linked: true });
});
```

## Tests and conformance vectors

```bash
npm test
```

`vectors/` holds language-neutral JSON cases. Every implementation, including the planned Python port, must pass them unchanged.

## License

MIT
