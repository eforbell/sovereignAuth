# Wire contract, version 1

What Home Base, nginx and every app agree on when a household member uses an app over the tailnet. The Node library in this repo implements the app's side; a port to another language implements the same contract and passes the same [conformance vectors](../vectors/).

Decisions referred to as D1–D23 are in Home Base's Feature-10 PRD (`planning/features/feature-10-prd.json`).

| Section | Status |
| --- | --- |
| 2. App modes | **Implemented** (`authMode`, `createIdentity`) |
| 3. Identity headers | Sent by Home Base's ingress since SID-001; **resolved** by `createIdentity` / `resolveMember`, vectors in `vectors/snapshot.json` |
| 4. Request guards | **Implemented** (`createRequestGuard`, `guardHttp`, `guardExpress`), vectors in `vectors/request-guards.json` |
| 5. Directory snapshot | **Implemented** (`createSnapshotReader`, `writeSnapshot`), vectors in `vectors/snapshot.json`; Home Base publishes a preview behind a setting in SID-003 and the real directory from SID-004 |
| 6–9. Tokens, assurance cookie, step-up, action tokens | **Verified** by the app (`verifyToken`, `createAssurance`, `createRedeemer`), policy matrix in `src/policy.json`, vectors in `vectors/assurance.json`; issued and redeemed by Home Base from SID-005 |
| 10. OAuth callbacks | **Implemented** (`createOAuthFlow`), vectors in `vectors/oauth.json` |
| 11. Passkey ceremonies and credential kinds | **Implemented** (`createWebAuthn`), pinned roots in `src/attestation-roots.json`; run by Home Base's passkey service from SID-005 |

Everything marked "contract only" may still change before its implementation lands; the version number changes once a host runs it.

## 1. The path a request takes

```
member's browser ─▶ Tailscale Serve ─▶ nginx (root-only socket for that service hostname)
                                         │  auth_request ─▶ Home Base identity endpoint (whois)
                                         ▼
                                       app's own socket (/run/sovereign-apps/<app id>/app.sock)
```

Each sensitive app and Home Base admin has its own service hostname (`<instance>-<key>.<tailnet>.ts.net`); the low-friction apps share `<instance>-home`. All of them are one browser site, because `ts.net` is a public suffix (D20).

## 2. App modes

An app runs in exactly one mode, from `SOVEREIGN_AUTH_MODE`:

- **`local`**: the app's own sign-in, as before Feature-10. Identity headers are ignored.
- **`tailnet`**: the member comes from the identity headers and the directory snapshot. The app must be listening on its socket (`SOVEREIGN_LISTEN=unix:…`), because only nginx can connect to that socket, which is what makes the headers trustworthy. An app in tailnet mode that is not listening on its socket refuses to start.

Any other value, including an empty one, refuses to start. There is no mixed or per-route mode.

## 3. Identity headers

nginx sets these on every request it proxies, overwriting anything the client sent:

| Header | Value |
| --- | --- |
| `X-Sovereign-User-Id` | The tailnet's stable user ID (D1) |
| `X-Sovereign-Login` | The tailnet login, for example `parent@example.com` |
| `X-Sovereign-Name` | The display name; display only |

An absent or empty header means no identity: the lookup failed, the device is tagged, or the user isn't admitted. In tailnet mode the member is resolved like this, and anything else means no member:

1. Find the snapshot member whose `user_id` equals `X-Sovereign-User-Id`. The login alone never identifies anyone.
2. That member's `login` must equal `X-Sovereign-Login` exactly.
3. The member's `status` must be `active`, and `apps` must include this app's ID.
4. `tagged-devices` is never a member, whatever the snapshot says.

## 4. Request guards

Two guards, checked before the app's handler and before any authorization or step-up prompt. They read only the method and headers. The reason codes below are the refusal reasons, checked in this order.

### 4.1 Resource isolation (strict hostnames)

On by default for sensitive apps and Home Base admin; off for the shared low-friction hostname. A request passes only if:

- `Sec-Fetch-Site` is `same-origin`; or
- it is a top-level document navigation: method `GET`, `Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document`, from any site (a link, a bookmark, a typed address).

| Reason | When |
| --- | --- |
| `fetch_metadata_missing` | No `Sec-Fetch-Site` header. Supported browsers always send it: Safari 16.4+ (including the iOS web wrapper), Chrome and Edge 80+, Firefox 90+. Scripts and health checks use the app's socket, not nginx |
| `fetch_metadata_malformed` | `Sec-Fetch-Site` is not exactly one of `same-origin`, `same-site`, `cross-site`, `none` (lower case, one value) |
| `not_same_origin` | Anything else: a sibling hostname's fetch, image, script, stylesheet, iframe or form post, a preflight, a `HEAD`, a framed page |

Framing is also refused by nginx, which sends `Content-Security-Policy: frame-ancestors 'none'` on every response from a strict hostname.

Every response from a strict hostname, allowed or refused, in `enforce` and in `report` mode, carries `Vary: Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest`, added to any `Vary` already set. Without it a browser can serve a response it cached for the app's own page to a sibling hostname's script, image or fetch, and the request never reaches the guard ([Fetch Metadata, "Vary"](https://www.w3.org/TR/fetch-metadata/#vary)). The adapters add it before the handler runs; an app that sets `Vary` itself appends to it and never replaces it, and a custom adapter must do the same.

### 4.2 Mutation guard (every hostname)

Every method except `GET` and `HEAD`:

| Reason | When |
| --- | --- |
| `origin_missing` | No `Origin` header, or an empty one |
| `origin_mismatch` | `Origin` is not exactly this hostname's origin (`https://<hostname>`): same-site is not enough, and `null`, another port, `http`, a trailing slash or other letter case all fail |
| `fetch_site` | `Sec-Fetch-Site` is present and is not `same-origin` |
| `content_type` | The media type (before any `;`, case-insensitive) is not `application/json`. An app may allow more types on a route that takes uploads; the Origin check still applies |

A form can't send `application/json`, and a JSON request from another origin needs a CORS preflight that the app never grants. So the content type keeps forms out even in a browser that sends no fetch metadata.

### 4.3 Reads change nothing

A sibling hostname's top-level navigation reaches the app with the member's identity, so:

- `GET` and `HEAD` handlers have no side effects. Exports, downloads that are logged as actions, and anything else that acts are `POST`.
- A page reached by navigation never acts on load from its URL parameters. The only exception is an OAuth callback (section 10).

### 4.4 Refusal

```
HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8
Cache-Control: no-store
Vary: Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest    (strict hostnames)

{"error": "request_refused", "reason": "<reason code>", "message": "<human-readable text>"}
```

The message is for people and may change; clients branch on `reason`.

## 5. Directory snapshot (D18)

Home Base publishes the household directory as a file that apps can read but not write. Integrity comes from file ownership, not signatures.

- **Location:** `/var/lib/sovereign-home/identity/snapshot.json`. The directory is owned by the Home Base user, mode 0755; its parents are root's and writable by no one else. The file is owned by the Home Base user, mode 0644, and replaced atomically (written beside it, synced, renamed).
- **Freshness:** rewritten on every change and every 30 seconds.

The reader refuses the snapshot, so the app has no members, when:

- the directory or file is a symlink (the file is opened by descriptor with no-follow, and the checks below are on that descriptor);
- either is not owned by the Home Base user, or is writable by group or others; the file is not a regular file or has more than one link;
- it doesn't parse, or isn't format 1;
- `written_at` is more than 120 seconds old;
- its `generation` is lower than the highest this process has seen.

The reader re-reads at most every 5 seconds. A refused snapshot is not cached as good: every request until a good one appears has no member.

```json
{
  "format": 1,
  "household": "smith",
  "generation": 4182,
  "written_at": "2026-10-28T19:00:00.000Z",
  "global_epoch": 3,
  "keys": [
    { "kid": "k2", "public_key": "<base64url of the raw 32-byte Ed25519 key>" }
  ],
  "members": [
    {
      "user_id": "1234567890",
      "member_id": "m_4f2a",
      "login": "parent@example.com",
      "name": "Parent",
      "role": "parent",
      "status": "active",
      "epoch": 7,
      "apps": ["family-dinner", "family-pulse", "home-source"]
    }
  ]
}
```

The reader is configured with the Home Base user's uid (never 0); an app learns it from `SOVEREIGN_HOMEBASE_UID`, which Home Base renders into the app's environment when it enters tailnet mode.

- `household`: the instance name, the same in every token.
- `generation`: an integer that only grows, across Home Base restarts.
- `global_epoch`: bumped by recovery and admin reset; every token with an older one stops working.
- `keys`: the public keys that verify tokens. During a key rotation the previous key stays listed for one session window.
- `members[].role`: `parent` or `kid`. `status`: `active` or `disabled`. `epoch`: bumped when a member's credential is revoked, the member is disabled, or their access changes. `apps`: the app IDs the member may use, written out in full (Home Base expands "all").
- The administrator flag is not in the snapshot: it is Home Base's own (D10). Credentials are never in it.

## 6. Tokens

Assurance cookies and action tokens share one format:

```
v1.<payload>.<signature>
```

- `<payload>` is the base64url (no padding) of a UTF-8 JSON object.
- `<signature>` is the base64url (no padding) of an Ed25519 signature over the ASCII bytes of `v1.<payload>`.
- Both parts must be the one canonical base64url spelling of their bytes: no padding, nothing outside the alphabet, no spare bits set. A token longer than 4096 characters is refused.
- There is no algorithm field and nothing to negotiate: version 1 is Ed25519, and the verifying key is the snapshot key whose `kid` the payload names. An unknown `kid` fails.
- Times are integer seconds since the Unix epoch, and `kid`, `iat` and `exp` are required in every token. A token is refused from the second `exp` names onwards, or when `iat` is more than 30 seconds in the future.
- Unknown payload fields are ignored; missing required ones fail.

## 7. Assurance cookie

Set by Home Base's passkey service under `/_sovereign/auth/` on the hostname where the ceremony ran (SID-005):

```
Set-Cookie: __Host-sv_assurance=<token>; Secure; HttpOnly; Path=/; SameSite=Strict
```

No `Domain`. The `__Host-` prefix matters here: a sibling hostname is same-site and could otherwise plant a cookie (D20). The app reads only a cookie named exactly `__Host-sv_assurance`. Any other name, including `sv_assurance` without the prefix, is ignored, and more than one cookie with that name fails.

| Field | Meaning | Checked against |
| --- | --- | --- |
| `typ` | `"assurance"` | |
| `kid` | Signing key | Snapshot `keys` |
| `household` | Instance | Snapshot `household` |
| `aud` | The hostname the ceremony ran on | This app's hostname, exactly |
| `sub` | The member's stable user ID | The resolved member's `user_id` |
| `sid`, `cred` | Session ID and the credential used | Recorded only |
| `kind` | `synced`, `device-bound` or `hardware` (D15) | The policy's kind |
| `epoch` | The member's epoch | The member's current `epoch` |
| `global_epoch` | | Snapshot `global_epoch` |
| `auth_time` | When the ceremony ran | The policy's window |
| `iat`, `exp` | | Section 6 |

Revoking a credential, disabling a member or changing their access bumps their epoch, so their cookies stop working at the app's next snapshot read (about 5 seconds).

## 8. Assurance policy and step-up

The assurance policy matrix (D12) gives every protected action a level and a credential kind. Apps name an action by its policy key; the library looks up the rest, so no app decides its own level. The matrix is `src/policy.json`:

| Policy key | Level | Kind | Administrator |
| --- | --- | --- | --- |
| `use-app` | `tailnet` | any | |
| `open-documents` | `session`, 30 days | any | |
| `open-operator` | `session`, 24 hours | any | |
| `open-admin` | `session`, 8 hours | any | yes |
| `link-account`, `export-data`, `change-role`, `manage-own-credential` | `recent` | any | |
| `manage-admin-credential`, `grant-administrator`, `privileged-plan` | `every-time` | hardware | yes |

"Administrator" is Home Base's own flag (D10), so only Home Base can use those keys; it tells the library who holds the flag.

| Level | Satisfied by |
| --- | --- |
| `tailnet` | A member (section 3); no cookie |
| `session` | A valid assurance cookie whose `auth_time` is within the policy's window |
| `recent` | A valid assurance cookie whose `auth_time` is at most 5 minutes old |
| `every-time` | A redeemed action token bound to this exact request (section 9) |

Kind `any` accepts every credential kind; `hardware` accepts only `kind: "hardware"`.

A cookie's `auth_time` may not be later than its `iat`.

When there is no member (section 3), the app answers `403 {"error": "not_a_member", "reason": "<why>"}`; when the policy needs an administrator and the member isn't one, `403 {"error": "not_authorized", "policy": "<policy key>"}`. When the member hasn't met the level, the app answers before its handler runs:

```
HTTP/1.1 401 Unauthorized
Content-Type: application/json; charset=utf-8
Cache-Control: no-store
Vary: Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest    (strict hostnames)

{"error": "step_up_required", "policy": "<policy key>", "level": "recent", "kind": "any"}
```

For `every-time` the body also has `target` and `digest` (section 9). The shared helper (`/_sovereign/auth/stepup.js`, SID-005) turns this into a confirm tap, the ceremony, and one retry of the identical request.

## 9. Action tokens and redemption (D19)

An every-time action is bound to one request. Before answering 401, the app resolves what the request will act on into a `target`: a UTF-8 string with no line breaks, for example the named backup that "latest" means right now. It may be empty. The request digest is then:

```
digest = base64url(SHA-256(
  "sovereign-action/1\n" + METHOD + "\n" + path-with-query + "\n" + base64url(SHA-256(raw body bytes)) + "\n" + target
))
```

After the ceremony, the helper retries the identical request with the token in `X-Sovereign-Action-Token`. The token's payload:

| Field | Checked against |
| --- | --- |
| `typ` | `"action"` |
| `kid`, `household`, `aud`, `sub`, `kind`, `epoch`, `global_epoch` | As for the assurance cookie |
| `app` | This app's ID |
| `act` | The policy key |
| `tgt` | The target the app resolves now |
| `dig` | The digest of this request |
| `jti` | Single use (Home Base) |
| `iat`, `exp` | `exp` at most 60 seconds after `iat` |

The app checks all of that, then redeems the token before acting. A token that fails any of these checks gets the same 401 again, with the target and digest as they stand now; the helper retries only once, so a second failure ends there.

The digest covers the raw body bytes as received. An app that only has a parsed body must keep the raw bytes for every-time routes (in Express, `express.json({ verify })`); the library refuses to compute a digest from a parsed body, or with no body when the request has one. It sends HTTP/1.1 over `/run/sovereign-identity/<app id>.sock` (owner the Home Base user, group the app's user, 0660), so the socket the request arrives on tells Home Base which app is asking:

```
POST /v1/redeem
Content-Type: application/json

{"token": "<token>", "policy": "<policy key>", "target": "<target>", "digest": "<digest>"}
```

Home Base checks that the token was issued for this app, consumes `jti` atomically, and rechecks the member's current authorization: active, has access to the app, epochs current, and administrator where the policy needs it. It answers `200 {"redeemed": true}`, or an error: `409 {"error": "replayed"}`, `403 {"error": "not_authorized"}`, `400 {"error": "invalid"}`. Anything else, including no answer within 3 seconds or a Home Base restart, counts as a refusal (fail closed). After a refusal the app answers, without acting:

```
HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8
Cache-Control: no-store

{"error": "step_up_refused", "policy": "<policy key>", "reason": "replayed" | "not_authorized" | "invalid" | "unavailable"}
```

## 10. OAuth and other external callbacks (D22)

The only route allowed to act on URL parameters, and only through this sequence:

1. **Start**: the member asks the app, with a mutation-guarded `POST`, to link an account. The app stores a state record `{state, user_id, hostname, correlation, PKCE verifier, created}`. `state` and `correlation` are each 32 random bytes in base64url. The app sets `__Host-sv_oauth=<correlation>; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age=600`, then sends the browser to the provider with `state` and a PKCE challenge wherever the provider supports it.
2. **Landing**: the provider redirects to the app's callback route. That `GET` needs no cookie and changes nothing, and answers with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. It renders a page that reads `code` and `state`, removes them from the address bar (`history.replaceState`), and sends them once. A reload finds nothing to send; an `error` parameter is shown, not sent.
3. **Completion**: a same-origin JSON `POST` of `{code, state}` to the app's completion route, which passes the mutation guard. The `SameSite=Strict` cookie was withheld on the provider's cross-site redirect, but is sent on this same-origin request. The route takes the state record first, so it is used up whatever happens next, then refuses unless it existed, is at most 10 minutes old, and matches the current member, this hostname and the cookie. Only then does the app exchange the code, with the record's PKCE verifier. Every answer clears the cookie.

The boundary is the origin. The mutation guard keeps every other origin, sibling hostnames included, from posting to the completion route. Pages on the app's own origin are trusted: any of them can fetch or frame the landing page and read what it reads, and set a `Referer` of their choosing, so the route does not try to tell them apart. On the shared low-friction hostname that origin is every low-friction app (D14).

A refusal is `400` (a body that isn't `{code, state}` of the right shape) or `403`:

```
{"error": "oauth_refused", "reason": "malformed" | "unknown_state" | "expired" | "wrong_member" | "wrong_hostname" | "no_cookie" | "duplicate_cookie" | "wrong_correlation"}
```

The state store is the app's: anything with `put(record)` and a `take(state)` that returns a record at most once. The library's default keeps records in memory.

An app that can't follow this stays in local mode.

## 11. Passkey ceremonies and credential kinds (D15, D17)

Home Base's passkey service runs the ceremonies (SID-005); apps only read the `kind` they produce, from the assurance cookie. The rules:

- **RP ID** is the tailnet domain, for every hostname in it. The origin is `https://<the hostname the ceremony runs on>`, exactly.
- **User verification** is required. **No PRF**, or any other extension that derives something: a ceremony proves presence and nothing more.
- **Challenges** last 5 minutes and are stored with the hostname that issued them, the member, the purpose (`enroll`, `step-up`, …), the audience (a hostname or an app ID), the action context and, for a step-up, the kind it needs. Finishing takes the record first, so a challenge gets one attempt, then refuses unless every one of those matches the finishing request and the ceremony type (registration or authentication) is the one it was issued for.
- **clientData** must have `crossOrigin` absent or `false` and no `topOrigin`: a ceremony in a frame is never accepted.
- **A step-up** names the member's own credentials; a credential not among them, or a user handle that isn't the member's stable user ID, is refused. When the policy needs `hardware`, a credential that isn't hardware now is refused even after its assertion verified.

**Kinds** come from what the authenticator proves. What the member asked for when enrolling plays no part:

| Kind | When |
| --- | --- |
| `synced` | The flags say backup-eligible or backed up: the key can leave the device |
| `device-bound` | Single-device, with no attestation that verified |
| `hardware` | Single-device, and a `packed` attestation whose chain verifies to a pinned root |

Attestation is `none` except when enrolling a hardware key, which asks for `direct`. Only the `none` and `packed` formats are accepted. A `packed` statement with a certificate chain must reach a pinned root, or the registration is refused rather than downgraded. The chain is checked before anything else looks at the certificates. Every certificate must be within its validity period. The leaf must not be a CA, and every certificate after it must be one, each signed by the next. The last must be a pinned root, or be signed by one. There are at most four certificates, and a self-signed certificate the client sends never ends the chain. The credential records the root it verified against.

A stored credential's kind never rises. It falls to `synced` once the flags say so, in any assertion, and `hardware` falls to `device-bound` when its root is no longer pinned, so a sovereignAuth release that removes a root demotes every credential that relied on it. Every verified assertion, including one refused for its kind, returns the credential's new kind, counter and flags. The service merges them into the stored credential, keeping the weaker kind, the higher counter and the wider flags, with the read locked until the write (or a compare-and-swap that retries), so concurrent finishes can't undo a demotion in either order. With no roots loaded, nothing is hardware.

Refusal reasons: `malformed`, `unknown_challenge`, `expired`, `wrong_ceremony`, `wrong_hostname`, `wrong_member`, `wrong_purpose`, `wrong_audience`, `wrong_action`, `wrong_kind` (the finishing request needs a different kind than the challenge was issued for), `cross_origin`, `unsupported_attestation`, `untrusted_attestation`, `unknown_credential`, `insufficient_kind`, `not_verified`.

## 12. Conformance vectors

`vectors/*.json` are language-neutral. Each file describes how to build the thing under test and lists cases with their expected outcome. A port must pass every file unchanged; a new case is added here first, then to every implementation.
