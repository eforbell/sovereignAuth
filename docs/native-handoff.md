# Design: passkey checks for pages inside a native app (handoff)

Status: **accepted**, 2026-11-18; Parts 1 and 2 are built and verified on a phone. Part 3 (enrolling a passkey) is proposed, 2026-11-19. The contract is now section 13 of the [wire contract](wire-contract.md), which wins where the two differ. It adds the refusals `not_pending` (attesting a record twice) and `stale_challenge` (finishing on a challenge that isn't the live one), and the store's `update` takes the fields it expects, not just the state.

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
   - the credential ID equals `keyId`, which equals `SHA-256` of the credential certificate's public key, as an X9.62 uncompressed point, compared as decoded bytes.
   - **the receipt** in the attestation verifies as Apple's guide requires:
     - its signature and chain reach Apple's receipt root (Apple Root CA G3), which is a separate pin from the attestation root;
     - its signing certificate carries Apple's receipt-signing marker (`1.2.840.113635.100.12.15`), because G3 also issues certificates to developers;
     - its App ID equals `appId`;
     - its attested certificate is the credential certificate;
     - its client hash equals `clientDataHash`;
     - its creation time is within the challenge's 5 minutes.

     A real receipt is CMS SignedData in BER, with indefinite lengths and its payload split across a constructed OCTET STRING, and has no signed attributes; one with signed attributes is refused.
4. **Home Base stores** `{keyId, publicKey, counter: 0, receipt, user_id, created, label}`. The label is a device name the app sends, shown to people only. It audits the registration.

Apple also offers an online fraud-metric refresh that exchanges the stored receipt with Apple's server. **Home Base doesn't use it.** It would be the only call from Home Base to Apple, and it adds no check this flow relies on.

Registering needs only the tailnet identity:
- A malicious app can't produce an attestation for the household's App ID.
- A genuine copy of the app elsewhere gains nothing by registering. Even if its traffic were relayed through the member's phone so that it registered as that member, using the registration would still take that member's passkey, in a sheet on the relaying phone (see "Why this is safe").

### Household trust (pinned certificate authorities)

The app attests a handoff `id` only when that `id` came from a real household page. That holds only if nobody can show the app a fake one. The phone's own trust store isn't enough for that:
- A person can install and trust their own root certificate, for example to intercept their own phone's traffic.
- With such a root, a genuine copy of the app could be served a forged page on `H` that hands its bridge another client's `id`.

So for **household hosts only**, the app trusts a pinned set of certificate authorities and nothing else:

- **The pin set:** `trustAnchors`, in the app's operator config. It defaults to the authorities that issue Tailscale's HTTPS certificates: Let's Encrypt's ISRG Root X1 and ISRG Root X2, pinned by the SHA-256 of their public keys.
- **Native requests** (`/api/home`, `app/*`, `handoff/attest`) evaluate the server's chain against those anchors only. User-installed and other system roots don't count.
- **The web view** applies the same evaluation in its server-trust challenge handler, for every load from a household host. A household page that fails it doesn't load.
- **The bridge** exists only in a main frame whose own load passed it (spike 5).
- **A failure** shows "Can't verify your household's certificate". It never falls back to the system's trust. If the certificate authority changes, the operator updates `trustAnchors` and ships a build.
- **Other sites** keep the system's trust; they open in Safari anyway.

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

### Record transitions are atomic

A record moves `pending → attested → done → taken`, and every change is a **conditional, atomic** write in the store:
- `attest` commits only if the record is still `pending` and unexpired;
- `options` commits only if it is still `attested`;
- `finish` commits only if the record is still `attested` and unexpired, and `challenge` is still the record's current challenge;
- `redeem` takes the record, so it's gone at once whatever happens next. A taken record never comes back, whatever an operation that started earlier writes afterwards.

`options` replaces the record's `challenge`. A record has one live challenge, so two sheets or two `options` calls can't produce two finishes. The store needs `put`, `get`, a conditional `update(id, expectedState, change)` and `take(id)`. The library's default keeps records in memory; Home Base keeps them in its own store, with the same guarantees.

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
| `state`, `result`, `keyId`, `challenge` | `pending`, nothing, nothing, nothing |

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
| A relayed or intercepted copy of the genuine app is fed another client's `id` | Household trust: household hosts load only over chains to the pinned authorities, so a root the device owner installed can't stand in a forged page. Relaying traffic without breaking TLS reaches only real Home Base pages, which give the app records whose cookie lives in that app's own web view. |
| `finish` and `redeem` race | Atomic record transitions: a taken record never returns. |
| A genuine copy of the app on another phone registers as this member through a relay | It gains nothing usable. Any result it could get needs this member's passkey in a sheet on the relaying phone, which is the same exposure a browser on that phone has today. Registrations are audited and listed on the Members card for revoking. |
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
- **Enrolling a passkey** while Home Base is active: Part 3.
- **Not in this design:** activation, and enrolling in setup or recovery. They stay in a browser.

## Part 3: enrolling a passkey in the app

Proposed 2026-11-19 (the app's phase 4). The operator chose:
- **every enrollment that runs while Home Base is active**, from the Passkeys panel in the app, not just the first one;
- for a member with no passkey, **the administrator's grant keeps its code**, but nobody types it: the app scans it from the Members card, or takes it pasted. (Why the code stays is under "The grant keeps its code".)

### What enrolling needs today

Enrollment runs on Home Base's hostname only. `enroll/options` decides who may enroll, and `enroll/finish` stores the credential. In active Home Base there are three ways to do it:

| Who | Authority | Where it comes from |
|---|---|---|
| A member with no usable passkey | `grant` | The administrator's 15-minute grant, presented as its code. It's used up when the registration verifies. |
| A member adding another passkey | `recent-check` | A check in the last 5 minutes (`manage-own-credential`), read from the assurance cookie, at options and again at finish. |
| The administrator | `every-time` | A hardware action token for `manage-admin-credential`, target `enroll:<member>`. It's used up when the ceremony starts, and the challenge is bound to the epochs it saw. |

In the app's web view, the ceremony itself is the problem, as with checks. The authority is not: the cookie, the action token and the code are all in the web view, where the page runs.

### The enroll handoff

Enrolling is a third handoff purpose, `enroll`, on Home Base's hostname only. It's the same record, cookie, attest step and sheet as Part 2. These things differ:

1. **Begin decides the authority.** `POST handoff/begin {purpose: "enroll", label, hardware, grant?}` makes the decision `enroll/options` makes today, from the web view's cookies and headers. If the member needs a check first, it answers `401 step_up_required` the same way. The page satisfies that through the handoff as a check, then begins again. An administrator's action token is used up here, as `enroll/options` uses it up today.

   The record keeps:
   - the authority (`grant`, `recent-check` or `every-time`), the label and `hardware`;
   - the standing it was decided on: the epochs, and whether the member had a usable passkey;
   - for `grant`, **which grant**: the hash of the code, which begin checks against the live grant without using it up;
   - for `recent-check`, **the check's deadline**: its time plus 5 minutes.
2. **The sheet registers.** `handoff/options` issues registration options: the existing enroll challenge, bound to the label, `hardware` and standing as today, with the handoff `id` beside them. The sheet calls `navigator.credentials.create`. Its summary says what is being added, from the record: "Add a passkey named *iPhone* to your Home Base account", or "Add an administrator passkey named *YubiKey 5C*". With `hardware`, it says hardware attestation is asked for. Nothing more: today a `hardware` registration that proves less is stored as the kind it proves, and the panel shows that kind afterwards.
3. **Finish claims the record, then stores the credential.** See "Finish claims the record" below for the claim. It then re-reads the member's standing and refuses if any of these hold:
   - the epochs moved, or the member is disabled or no longer active;
   - the app instance that attested the record is gone, or no longer the member's;
   - for `grant`: the member now has a usable passkey, or the grant on file isn't the one begin saw (reissued, used, or past its 15 minutes);
   - for `recent-check`: the check's deadline has passed;
   - for `every-time`: the member is no longer the administrator.

   Then it verifies the registration as `enroll/finish` does. For `grant`, using up that exact grant and storing the credential are **one write**, conditional on the grant's hash, so a grant reissued in between stops it. The record's result is just `{kind, label}`.
4. **Redeem only reports.** `handoff/redeem` takes the record and answers `{enrolled: {kind, label}}`. No cookie or token is involved; the page refreshes its list. The credential is already stored, so a redeem that never comes loses nothing.

The wire field for the sheet's answer stays `assertion` in `handoff/finish`. For `enroll` it carries the registration response. The library reads the challenge from `clientDataJSON` either way.

### Finish claims the record (all purposes)

Today `finish` calls `verify` and only then commits `attested → done`. While `verify` runs, an `options` call can replace the challenge. For a check that is harmless: the losing finish's result is never stored, so it's never delivered. For `enroll`, `verify` itself stores a credential. Two finishes could then store two credentials under one authority, which matters most for an administrator's single every-time token.

So `finish` first moves the record **`attested → finishing`**, conditional on the live challenge, and only then calls `verify`:
- `options` refuses a `finishing` record (`not_attested`), so no second challenge exists;
- `verify` succeeds and the record moves `finishing → done`; or it refuses, and the record stays `finishing` until it expires. The ceremony's challenge already gets one attempt, so nothing is lost; the member starts again.

This changes the record transitions above for every purpose: `pending → attested → finishing → done → taken`.

### The grant keeps its code

The first design (2026-11-19) let the member's attested app use the grant with no code. Review found that this can be relayed:
1. A malicious app on the member's phone tunnels the attacker's own copy of the household's genuine app through the phone's tailnet connection. Household trust still holds, because TLS runs end to end to Home Base.
2. Registering an app instance needs only the tailnet identity, so the attacker's copy registers as the member. App Attest passes, because that copy is genuine.
3. Inside the grant's 15 minutes, the attacker attests an enroll record and registers their own passkey on the member's account.

Part 2 resists the same relay because a check still needs the member's own passkey. A first passkey has nothing of the member's to ask for. Only a step between the two people breaks the relay, and the code is that step.

So the code stays, and the typing goes:
- **The Members card** shows the code as a QR code beside the text. It holds `sovereign-grant/1`, Home Base's hostname and the code, on three lines.
- **The app's "Add a passkey"** scans it, or takes it pasted. The app checks the hostname is its household's. It then opens the Passkeys panel in the web view with the code in the URL fragment (`#grant=<code>`), which never reaches a server log. The panel takes it from the fragment and clears the fragment at once.
- **The code is never a link.** A URL scheme or a universal link could be claimed by another app, which would then hold the code and could relay again. The app scans the code itself.
- **In person** it's one scan. **At a distance** the administrator sends the code and the member pastes it, as today, without the typing.

`begin` checks the code against the live grant, so a wrong code fails before the sheet. It's still used up only when the registration verifies.

### Telling the member

`GET /api/home` adds `passkeyInvite: {expiresAt}` for a member with no usable passkey and a live grant. The launcher shows "Add a passkey" while it lasts, with Scan and Paste. Without an invite, the Passkeys panel is still in the app for adding more passkeys. The app's native part is the scanner and the card. The panel runs the handoff through the bridge the app already has.

### Why this is safe

Everything in Part 2's "Why this is safe" holds. In addition:
- **Begin can't be skipped.** The authority is decided there, from the web view, and a sheet without an attested record gets nothing.
- **Finish checks the authority again,** from the member's standing at that moment, and the attesting instance with it. A reissued or used grant, a revoked passkey (which moves the epochs), a removed app instance, an expired check, or a demotion all stop the registration.
- **One record, one credential.** Finish claims the record before anything is stored.
- **The challenge binds what was shown.** The label and `hardware` that the sheet summarizes are the ones in the challenge, so the sheet can't register something else.
- **A first passkey needs the code,** passed between the administrator and the member, as in a browser.

### Not in Part 3

- **Activation, and enrolling in setup or recovery.** They rest on the passphrase session, and they're rare operator steps. They stay in a browser.
- **One sheet for the administrator.** Adding an administrator passkey is two sheets: the hardware check that buys the action token, then the registration. That's the same two ceremonies Safari runs today.

### Slices for Part 3

1. **sovereignAuth:**
   - `enroll` as a handoff purpose in `createHandoff`;
   - the `finishing` claim;
   - section 13 and the vectors.
2. **Home Base, the routes:**
   - the enroll handoff in `handoff-routes.js`, with the checks above;
   - the conditional grant-and-credential write in the directory;
   - the sheet's registration branch.
3. **Home Base, the pages:**
   - the Passkeys panel enrolls through the bridge in the app, taking `#grant=`;
   - the Members card's QR code (a small vendored encoder, served as a static file);
   - `passkeyInvite` in `/api/home`.
4. **sovereignShell:** the launcher's "Add a passkey" card, with the scanner (VisionKit) and Paste.

**Check on the phone at the end:** creating a passkey in the ephemeral sheet with iCloud Keychain, 1Password and a YubiKey (`hardware`, with attestation). Phase 3 measured only assertions there. If a provider can't create in the sheet, that path falls back to Safari, as now.

## Relation to the iPhone approval key

Home Base `planning/research/iphone-hardware-key.md` plans an App Attest–enrolled approval key, an `attested-device` credential with administrator authority. The two share:
- the App Attest verification in sovereignAuth: attestation, assertion, the pinned root, counters, vectors. That's its slice 1, and slice 1 below.
- the household's App ID setting.

They stay **separate registrations.** An app instance grants nothing on its own. An approval key is a credential, enrolled under an every-time hardware check (or the passphrase authority in setup and recovery) and paired with a Face ID key. A phone can hold both, but registering an app instance never creates an approval key.

## Slices

Each is one PR touching few files.

1. **sovereignAuth: App Attest verification.** Attestation, receipt and assertion checks, and the pinned Apple roots (attestation and receipt). The public tests use a fake Apple; real device output (spike 1) runs from a local file, because it names the App ID. Shared with the iPhone approval key.
2. **sovereignAuth: the handoff contract.** This section in the wire contract, and `createHandoff` (the record store and its checks). Vectors in `vectors/handoff.json`. The passkey service is Node-only, so there's no Python port.
3. **Home Base: app instances.** The `nativeApp` setting, the `app/challenge` and `app/register` routes, and the Members card list with revoke.
4. **Home Base: handoff routes.** `begin`, `attest`, `options`, `finish` and `redeem`, plus the sheet page, on Home Base's hostname and on sensitive apps' hostnames.
5. **Home Base: the bridge branch** in `stepup.js` and in the admin unlock page.
6. **sovereignShell:**
   - household trust: pinned authorities for native requests and the web view;
   - registering the app instance;
   - `window.sovereign` version 1;
   - the `attest` call and the sheet;
   - the App Attest entitlement (production) and the scheme, in operator config.

## Spikes before slice 1

1. **App Attest on a TestFlight build:** attest, then assert several times. Verify in Node against the pinned root and Apple's validation-guide example, and capture fixtures for the vectors. The App ID needs the App Attest capability. (This is also spike 1 in the hardware-key note.)
2. **Ephemeral sheet:** run a ceremony in an ephemeral `ASWebAuthenticationSession` with iCloud Keychain, 1Password and a YubiKey (NFC and USB-C). Fallback: a shared session, which shows iOS's sign-in alert each time.
3. **The sheet's identity:** confirm the sheet's requests carry the same tailnet identity as the web view's. Spike c suggests they do.
4. **Closing the sheet:** confirm that navigating to the custom scheme from the sheet page's script, after a `fetch`, closes the sheet. If iOS needs a tap for that, the sheet shows a "Return to the app" button.
5. **Pinning the web view:** confirm the web view's server-trust handler sees every load from a household host, subresources included, so a refused chain blocks the page. If it doesn't, find out whether ATS `NSPinnedDomains` applies to `WKWebView`.

## Questions for the operator

1. **The App Attest environment:** production only, which covers TestFlight and the App Store, with development as an opt-in household setting. Recommended. This also answers the hardware-key note's decision 5.
2. **The ephemeral sheet** (no "wants to use … to sign in" alert), if spike 2 passes. Recommended.
3. **Scope:** checks and every-time actions now; enrolling a passkey from the app later. Recommended.
