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

## Tests and conformance vectors

```bash
npm test
```

`vectors/` holds language-neutral JSON cases. Every implementation, including the planned Python port, must pass them unchanged.

## License

MIT
