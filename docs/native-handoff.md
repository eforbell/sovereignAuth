# Design: passkey checks for pages inside a native app (handoff)

Status: **proposed**, 2026-11-18. Nothing is implemented. Once it lands, it becomes section 13 of the [wire contract](wire-contract.md).

## The problem

A household's native app shows the suite's pages in its own web view (`WKWebView` on iOS). That web view can't run passkey ceremonies for the suite. Section 11 sets the RP ID to the tailnet domain. An iOS app may use passkeys in its web view only for domains it claims as associated domains, and Apple fetches the claim file from that domain. Nothing serves the bare tailnet domain, so no app can claim it.

This was measured on a phone (iOS 26.7, TestFlight):
- `navigator.credentials.get` in the web view fails with `NotAllowedError`.
- The same ceremony works in `ASWebAuthenticationSession` and `SFSafariViewController`, with synced passkeys and with hardware keys.

The ceremony has to run in a Safari context, but its result is needed in the web view:
- the assurance cookie (section 7) for a check;
- the action token (section 9) for an every-time action.

Today, a parent's check in Family Pulse can't finish inside the app at all.

**The constraint that shapes the design.** Today a ceremony's result stays in the Safari context that ran it. An app can open a Safari view or a sheet, but it can't read the cookie set inside one. Moving the result into the web view must not let *any* app on the phone do the same.
- A native client can send any headers it likes.
- The tailnet identity belongs to the device, so it's shared by every app on it.

Only the household's genuine app may receive a result. That is proven with **App Attest**.

## What doesn't change

- **Apps.** Every app's pages already go through Home Base's helper, `/_sovereign/auth/stepup.js`. The handoff lives in that helper and in Home Base's passkey service. No app code changes, and nothing changes in the app-side library: apps still read the same cookie and the same action token.
- **Browsers.** Without the native bridge, the helper runs the ceremony in the page exactly as today.
- **Section 4.3 (reads change nothing).** Every step that acts is a JSON `POST` that passes the mutation guard. Nothing acts on a URL parameter.
- **Section 11 (ceremonies).** The ceremony itself is unchanged:
  - it runs top-level on the same hostname, with the same RP ID and origin;
  - `crossOrigin` is absent;
  - challenges follow the same rules, and kinds are derived the same way.

## Part 1: app instances (App Attest)

An **app instance** is one installation of the household's app on one phone, registered to one member. It grants no authority of its own. It is not a credential, doesn't count toward any assurance level, and can't approve anything. It only lets that installation take part in a handoff.

### The household's app

Home Base gets one setting: `nativeApp: { appId: "<TEAMID>.<bundle id>", scheme: "<scheme>" }`.
- It belongs to the install config and is never in code.
- `scheme` must match `^[a-z][a-z0-9+.-]{2,31}$`.
- Without this setting, there are no app instances and no handoff, and the helper keeps its in-page ceremony.

### Registering

The app does this once, on first use, over the tailnet:

1. **`POST /_sovereign/auth/app/challenge`** on Home Base's hostname. Home Base issues a challenge (32 random bytes) bound to the caller's member and to this hostname, with a 5-minute lifetime.
2. **The app attests a new key.** It calls `DCAppAttestService.generateKey`, then `attestKey(keyId, clientDataHash)`, where:
   ```
   clientDataHash = SHA-256("sovereign-app-instance/1\n" + household + "\n" + user_id + "\n" + challenge)
   ```
3. **`POST /_sovereign/auth/app/register {keyId, attestation, challenge}`.** Home Base takes the challenge first, so it gets one attempt. It refuses unless the challenge matches this member and hostname and is within its 5 minutes. It then verifies the attestation as Apple's validation guide sets out:
   - the certificate chain ends at the **pinned Apple App Attestation Root CA** (pinned in sovereignAuth, like section 11's roots);
   - the nonce extension equals `SHA-256(authData ‖ clientDataHash)`;
   - `rpIdHash` equals `SHA-256(appId)`;
   - the counter is 0;
   - the AAGUID is the **production** environment. Development is refused unless the household turns it on; this is the iPhone hardware-key note's open decision 5. TestFlight and App Store builds are production.
   - the credential ID equals `keyId`, which equals `SHA-256` of the public key.
4. **Home Base stores** `{keyId, publicKey, counter: 0, user_id, created, label}`. The label is a device name the app sends, shown to people only. It audits the registration.

Registering needs only the tailnet identity:
- A malicious app can't produce an attestation for the household's App ID.
- A genuine copy of the app on another person's phone can't present this member's tailnet identity.

**The Members card lists each member's app instances.** Revoking one deletes its key, and so does removing or disabling the member. The app re-registers if Home Base says its key is unknown, for example after a reinstall or a new phone; App Attest keys don't survive either.

### Asserting

To prove a request comes from a registered instance, the app sends `{keyId, assertion}`. The assertion comes from `generateAssertion(keyId, clientDataHash)`, over a client-data hash that each step defines. Home Base:
- finds the key, which must belong to the member the request resolves to;
- verifies the signature over `SHA-256(authenticatorData ‖ clientDataHash)` with the stored public key;
- checks that `rpIdHash` equals `SHA-256(appId)`;
- checks that the counter is **greater** than the stored one, then stores the new counter. The read is locked until the write, as section 11 does for passkey counters.

Refusals:

```
{"error": "app_instance_refused", "reason": "malformed" | "unknown_challenge" | "expired" | "wrong_member" | "wrong_hostname" | "untrusted_attestation" | "wrong_app" | "wrong_environment" | "unknown_key" | "bad_signature" | "counter_not_increasing"}
```

## Part 2: the handoff

Names used below:
- `H` is the hostname the page is on: Home Base's own, or a sensitive app's.
- The **web view** is the app's.
- The **app** is its native code.
- The **sheet** is `ASWebAuthenticationSession`: Safari's context, on the same phone, over the same tailnet connection, so the same member.

```
web view (page on H)        app (native)                Home Base on H                    sheet (Safari)
────────────────────        ────────────                ──────────────                    ──────────────
1 401 step_up_required
2 POST handoff/begin ─────────────────────────────────▶ record {pending}
                                                        Set-Cookie __Host-sv_handoff_<tag>
  ◀──────────────────────────────────────────────────── {id}
3 sovereign.handoff(id) ──▶ POST handoff/attest ──────▶ App Attest assertion over id
                             {id, keyId, assertion}     record {attested}
                           opens sheet on handoff/sheet#<id> ──────────────────────────▶ POST handoff/options
                                                        ◀──────────────────────────────── (summary + challenge)
                                                                                          tap, passkey
                                                        ◀── POST handoff/finish ─────────
                                                        record {done, result}
                                                        ── {return} ────────────────────▶ navigates to <scheme>:, closes
4 ◀── promise resolves ────
5 POST handoff/redeem {id} ───────────────────────────▶ take record; cookie, member, hostname
  ◀──────────────────────────────────────────────────── check: Set-Cookie __Host-sv_assurance
                                                        action: {token}
6 retry the identical request (section 8 or 9, as today)
```

### 1–2. Begin (web view)

The helper gets `401 step_up_required` for a request.

**When the bridge is present** (`window.sovereign.handoff` exists), the helper still shows its confirm tap first. It then posts `POST /_sovereign/auth/handoff/begin` with what the ceremony is for: `{purpose: "check"}`, or `{purpose: "action", action: {policy, target, digest}}`.

The service applies **exactly the checks** that `check/options` or an action's options apply today:
- the member, the lifecycle state, the policy, the kind;
- whether this hostname may run that purpose (an app's hostname: checks only).

It then stores a record:

| Field | |
| --- | --- |
| `id` | 32 random bytes, base64url |
| `correlation` | 32 random bytes, base64url |
| `user_id`, `hostname` | From the identity headers and this request |
| `purpose`, `policy`, `kind`, `action` | As validated |
| `created` | Records last **5 minutes** |
| `state`, `result`, `keyId` | `pending`, nothing, nothing |

It answers with:

```
Set-Cookie: __Host-sv_handoff_<tag>=<correlation>; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age=300
{"id": "<id>"}
```

- **Each handoff has its own cookie.** `<tag>` is the first 16 characters of the `id`, so two step-ups in flight at once don't overwrite each other's correlation.
- **The cookie follows section 7's `__Host-` rules:** an exact name, and more than one cookie with that name fails.
- **The helper runs one handoff at a time per page.** Other `step_up_required` answers wait for it. For a check, the one handoff's cookie then satisfies them all.

### 3a. Attest (app)

The page calls `sovereign.handoff(id)`. The bridge's own checks are under "The bridge" below. The app then makes a native `POST /_sovereign/auth/handoff/attest {id, keyId, assertion}` to `H`, where:

```
clientDataHash = SHA-256("sovereign-handoff/1\n" + H + "\n" + id)
```

Being Home Base's own client, the app sends the headers that pass the guards (section 4): `Origin: https://H`, `Sec-Fetch-Site: same-origin`, JSON.

The service refuses unless all of these hold:
- the record is `pending` and still within its 5 minutes;
- the caller resolves to the record's `user_id`;
- the request came in on the record's `hostname`;
- the assertion verifies for a key registered to that member (Part 1).

It then records `keyId` and marks the record **`attested`**. **Only an attested record can reach the ceremony.**

This is the step that closes the gap. A malicious app can begin a record, but it can't attest one: it has no key for the household's App ID. And it can't get the genuine app to attest its record, because:
- the app attests only `id`s its own web view hands it, from a household page in a main frame;
- the app never attests in response to a URL scheme, a universal link or a notification.

### 3b. The ceremony (sheet)

1. **The app opens the sheet** on `https://H/_sovereign/auth/handoff/sheet#<id>`, with an **ephemeral** browser session. The sheet needs no cookies, and being ephemeral skips iOS's "wants to use … to sign in" alert (spike 2). The `id` travels in the URL fragment, so it never reaches a server log or a `Referer`.
2. **The sheet page** is `GET /_sovereign/auth/handoff/sheet`. It changes nothing and sends `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. It reads the `id` from the fragment.
3. **`POST handoff/options {id}`, before any tap,** as the existing helper fetches options before its tap. The service refuses unless all of these hold:
   - the record is **`attested`** and still within its 5 minutes;
   - the caller resolves to the record's `user_id`;
   - the request came in on the record's `hostname`.

   It then issues a section 11 challenge, bound to the purpose, audience, action and kind, plus the handoff `id`. It answers with the challenge and a **summary** of what will be confirmed, written from the record: for example, "Unlock administration on Home Base" or "Confirm restore backup *nightly-2026-11-18* in Home Base". The sheet shows that summary, then asks for the tap that iOS needs before a passkey prompt.
4. **`POST handoff/finish {id, assertion}`**, after the tap. The service verifies the assertion exactly as `check/finish` or an action finish does, and checks the challenge's handoff `id` against the record. On success it stores the result on the record and marks it `done`:
   - for a check, the assurance token it would have set;
   - for an action, the action token.

   **It sets no cookie in the sheet**, because the result belongs to the web view. It answers `{"return": "<scheme>://sovereign-auth/done"}`.
5. **The sheet navigates there.** `ASWebAuthenticationSession` catches its own callback scheme and closes. **The callback carries nothing**: no id, no ticket, no token. If it went astray, it would reveal nothing.

### 4–6. Redeem (web view)

When the sheet closes, the bridge's promise resolves; if the member cancels, it rejects. The helper then posts `POST handoff/redeem {id}` from the web view, which sends the `__Host-sv_handoff_<tag>` cookie.

The service **takes the record first**, so it is used up whatever happens next. It then refuses unless all of these hold:
- the record existed and is `done`;
- it is still within its 5 minutes;
- the cookie for this `id` equals `correlation`;
- the caller resolves to `user_id`;
- the request came in on `hostname`.

Then it delivers the result:
- **check:** `Set-Cookie: __Host-sv_assurance=…` (section 7), now in the web view's cookie jar;
- **action:** `{"token": "<action token>"}`, which the helper sends in `X-Sovereign-Action-Token` as today. Single use (`jti`), redemption and the 60-second lifetime all apply unchanged.

Every answer clears that handoff's cookie. The helper then retries the identical request once, as today. Refusals:

```
{"error": "handoff_refused", "reason": "malformed" | "unknown_handoff" | "expired" | "not_attested" | "not_done" | "wrong_member" | "wrong_hostname" | "no_cookie" | "duplicate_cookie" | "wrong_correlation"}
```

plus the `app_instance_refused` reasons at `attest`.

## The bridge (native app side)

The app gives household pages one function:

```js
window.sovereign = { version: 1, handoff(id) /* → Promise<void> */ };
```

- **Where it exists.** It's injected only into **main frames** on **household hosts**: Home Base and the apps `/api/home` lists. Frames and other sites never see it.
- **What the app checks before attesting:**
  - the calling frame is a main frame;
  - its origin is `https://` plus a household host;
  - `id` is 43 base64url characters.

  The app attests to that same origin, `H`, never to another host.
- **One handoff at a time.** A second call while one is open is refused.
- **If App Attest is unsupported, or the app has no registered instance and can't register one,** the bridge rejects with `unavailable`. The helper then says the check can't be done in the app on this device, rather than falling back silently.

## Why this is safe

| Threat | What stops it |
|---|---|
| **A malicious app on the phone runs its own handoff** | It can begin a record, but the ceremony needs an `attested` record, and only a key App Attest issued for the household's App ID can attest. |
| A malicious app gets the genuine app to attest its record | The app attests only `id`s from its own web view's household main frames, never from a URL scheme, a link or a notification. |
| A malicious app redeems the genuine app's record | Redeeming needs the web view's `__Host-` correlation cookie, which only the web view's cookie jar holds. |
| Another app intercepts the callback | The callback carries nothing. `ASWebAuthenticationSession` also takes it directly, without iOS's usual routing between apps. |
| A sibling hostname begins, attests or redeems | The mutation guard (section 4.2) and strict isolation (4.1). |
| Someone else's handoff gets confirmed | `options`, `finish` and `redeem` all need the record's member and hostname. The sheet shows a summary taken from the record, never from the URL. |
| A stale or reused handoff, challenge or assertion | The record lasts 5 minutes and is taken on redeem. The challenge gets one attempt (section 11). The App Attest counter must rise. |
| A replayed action token | Unchanged: `jti`, the digest and redemption (section 9). |

**What App Attest doesn't cover**, as the iPhone hardware-key note says:
- It proves a genuine, unmodified copy of the household's app on a genuine device, not that the app's code is right.
- It's no defense if the phone's OS is compromised.

As in section 10, **pages on the same origin are trusted.** A page on `H` could already run the in-page ceremony in a browser, so the handoff gives it nothing new.

## Home Base's own pages

Home Base's admin pages (unlock and enrollment) call the passkey API directly, not through `stepup.js`.
- **In scope:** unlocking administration, which is a check on Home Base's hostname. Its page branches on the bridge the same way the helper does.
- **Not in this design:** enrolling a passkey and activation (setup or recovery). They stay in a browser.

## Relation to the iPhone approval key

Home Base `planning/research/iphone-hardware-key.md` plans an App Attest–enrolled approval key, an `attested-device` credential with administrator authority. The two share:
- the App Attest verification in sovereignAuth: attestation, assertion, the pinned root, counters, vectors. That's its slice 1, and slice 1 below.
- the household's App ID setting.

They stay **separate registrations.** An app instance grants nothing on its own. An approval key is a credential, enrolled under an every-time hardware check (or the passphrase authority in setup and recovery) and paired with a Face ID key. A phone can hold both, but registering an app instance never creates an approval key.

## Slices

Each is one PR touching few files.

1. **sovereignAuth: App Attest verification.** Attestation and assertion checks, the pinned Apple root, and vectors from real device fixtures (spike 1). Shared with the iPhone approval key.
2. **sovereignAuth: the handoff contract.** This section in the wire contract, and `createHandoff` (the record store and its checks). Vectors in `vectors/handoff.json`. The passkey service is Node-only, so there's no Python port.
3. **Home Base: app instances.** The `nativeApp` setting, the `app/challenge` and `app/register` routes, and the Members card list with revoke.
4. **Home Base: handoff routes.** `begin`, `attest`, `options`, `finish` and `redeem`, plus the sheet page, on Home Base's hostname and on sensitive apps' hostnames.
5. **Home Base: the bridge branch** in `stepup.js` and in the admin unlock page.
6. **sovereignShell:**
   - registering the app instance;
   - `window.sovereign` version 1;
   - the `attest` call and the sheet;
   - the App Attest entitlement (production) and the scheme, in operator config.

## Spikes before slice 1

1. **App Attest on a TestFlight build:** attest, then assert several times. Verify in Node against the pinned root and Apple's validation-guide example, and capture fixtures for the vectors. The App ID needs the App Attest capability. (This is also spike 1 in the hardware-key note.)
2. **Ephemeral sheet:** run a ceremony in an ephemeral `ASWebAuthenticationSession` with iCloud Keychain, 1Password and a YubiKey (NFC and USB-C). Fallback: a shared session, which shows iOS's sign-in alert each time.
3. **The sheet's identity:** confirm the sheet's requests carry the same tailnet identity as the web view's. Spike c suggests they do.
4. **Closing the sheet:** confirm that navigating to the custom scheme from the sheet page's script, after a `fetch`, closes the sheet. If iOS needs a tap for that, the sheet shows a "Return to the app" button.

## Questions for the operator

1. **The App Attest environment:** production only, which covers TestFlight and the App Store, with development as an opt-in household setting. Recommended. This also answers the hardware-key note's decision 5.
2. **The ephemeral sheet** (no "wants to use … to sign in" alert), if spike 2 passes. Recommended.
3. **Scope:** checks and every-time actions now; enrolling a passkey from the app later. Recommended.
