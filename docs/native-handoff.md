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

## What doesn't change

- **Apps.** Every app's pages already go through Home Base's helper, `/_sovereign/auth/stepup.js`. The handoff lives in that helper and in Home Base's passkey service. No app code changes, and nothing changes in the app-side library: apps still read the same cookie and the same action token.
- **Browsers.** Without the native bridge, the helper runs the ceremony in the page exactly as today.
- **Section 4.3 (reads change nothing).** Every step that acts is a same-origin JSON `POST` that passes the mutation guard. Nothing acts on a URL parameter.
- **Section 11 (ceremonies).** The ceremony itself is unchanged:
  - it runs top-level on the same hostname, with the same RP ID and origin;
  - `crossOrigin` is absent;
  - challenges follow the same rules, and kinds are derived the same way.

## The flow

Names used below:
- `H` is the hostname the page is on: Home Base's own, or a sensitive app's.
- The **web view** is the app's.
- The **sheet** is `ASWebAuthenticationSession`: Safari's context, on the same phone, over the same tailnet connection, so the same member.

```
web view (page on H)              Home Base passkey service on H            sheet (Safari context)
────────────────────              ──────────────────────────────            ──────────────────────
1 401 step_up_required
2 POST handoff/begin ───────────▶ record {pending}, Set-Cookie __Host-sv_handoff
                     ◀─────────── { url: https://H/_sovereign/auth/handoff/sheet#<id> }
3 sovereign.handoff(url) ─── app opens the sheet ────────────────────────────▶ GET sheet (changes nothing)
                                                                              tap to confirm
                                   ◀── POST handoff/options {id} ────────────
                                   ── challenge bound to the record ────────▶ navigator.credentials.get
                                   ◀── POST handoff/finish {id, assertion} ──
                                   record {done, result}
                                   ── { return: "<scheme>:" } ──────────────▶ navigates to <scheme>:…, sheet closes
4 ◀── promise resolves ──────────────────────────────────────────────────────
5 POST handoff/redeem {id} ──────▶ take record, check cookie and member
                     ◀─────────── check: Set-Cookie __Host-sv_assurance
                                  action: { token }
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
| `state`, `result` | `pending`, nothing |

It answers with:

```
Set-Cookie: __Host-sv_handoff_<tag>=<correlation>; Secure; HttpOnly; Path=/; SameSite=Strict; Max-Age=300
{"url": "https://H/_sovereign/auth/handoff/sheet#<id>"}
```

- **The `id` travels in the URL fragment**, so it never reaches a server log or a `Referer`.
- **Each handoff has its own cookie.** `<tag>` is the first 16 characters of the `id`, so two step-ups in flight at once don't overwrite each other's correlation. (A single shared cookie would let a second `begin` replace the first's, and both would then fail.)
- **The cookie follows section 7's `__Host-` rules:** an exact name, and more than one cookie with that name fails.
- **The helper runs one handoff at a time per page.** Other `step_up_required` answers wait for it. For a check, the one handoff's cookie then satisfies them all.

### 3. The ceremony (sheet)

1. **The app opens the sheet** on that URL. The app's own checks are under "The bridge" below.
2. **The sheet page** is `GET /_sovereign/auth/handoff/sheet`. It changes nothing and sends `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. It reads the `id` from the fragment.
3. **`POST handoff/options {id}`, before any tap,** as the existing helper fetches options before its tap. The service finds the record and refuses unless all of these hold:
   - the record is `pending` and still within its 5 minutes;
   - the caller's identity headers resolve to the record's `user_id`;
   - the request came in on the record's `hostname`.

   It then issues a section 11 challenge, bound to the purpose, audience, action and kind, plus the handoff `id`. It answers with the challenge and a **summary** of what will be confirmed, written from the record: for example, "Unlock administration on Home Base" or "Confirm restore backup *nightly-2026-11-18* in Home Base". The sheet shows that summary, then asks for the tap that iOS needs before a passkey prompt.
4. **`POST handoff/finish {id, assertion}`**, after the tap. The service verifies the assertion exactly as `check/finish` or an action finish does, and checks the challenge's handoff `id` against the record. On success it stores the result on the record and marks it `done`:
   - for a check, the assurance token it would have set;
   - for an action, the action token.

   **It sets no cookie in the sheet**, because the result belongs to the web view. It answers `{"return": "<scheme>:"}`.
5. **The sheet navigates to `<scheme>://sovereign-auth/done`.** `ASWebAuthenticationSession` catches its own callback scheme and closes. **The callback carries nothing**: no id, no ticket, no token. If it went astray, it would reveal nothing.

`<scheme>` is the household's app scheme, a Home Base setting such as `homebase-example`. It must match `^[a-z][a-z0-9+.-]{2,31}$`, and it is never taken from a request. If it's unset, `handoff/begin` answers `404`, and the helper falls back to the in-page ceremony.

### 4–6. Redeem (web view)

When the sheet closes, the bridge's promise resolves; if the member cancels, it rejects. The helper then posts `POST handoff/redeem {id}` from the web view, which sends the `__Host-sv_handoff` cookie.

The service **takes the record first**, so it is used up whatever happens next. It then refuses unless all of these hold:
- the record existed and is `done`;
- it is still within its 5 minutes;
- the `__Host-sv_handoff_<tag>` cookie for this `id` equals `correlation`;
- the caller's identity resolves to `user_id`;
- the request came in on `hostname`.

Then it delivers the result:
- **check:** `Set-Cookie: __Host-sv_assurance=…` (section 7), now in the web view's cookie jar;
- **action:** `{"token": "<action token>"}`, which the helper sends in `X-Sovereign-Action-Token` as today. Single use (`jti`), redemption and the 60-second lifetime all apply unchanged.

Every answer clears that handoff's cookie. The helper then retries the identical request once, as today. Refusals:

```
{"error": "handoff_refused", "reason": "malformed" | "unknown_handoff" | "expired" | "not_done" | "wrong_member" | "wrong_hostname" | "no_cookie" | "duplicate_cookie" | "wrong_correlation"}
```

## The bridge (native app side)

The app gives household pages one function:

```js
window.sovereign = { version: 1, handoff(url) /* → Promise<void> */ };
```

- **Where it exists.** It's injected only into **main frames** on **household hosts**: Home Base and the apps `/api/home` lists. Frames and other sites never see it.
- **What the app checks before opening the sheet:**
  - the calling frame is a main frame;
  - its origin is `https://` plus a household host;
  - `url` has that same origin, and its path is exactly `/_sovereign/auth/handoff/sheet`.

  Anything else is refused without opening a sheet.
- **One sheet at a time.**
- **The sheet uses the ephemeral browser session.** It needs no cookies: identity comes from the tailnet, and the correlation cookie lives in the web view. Being ephemeral also skips iOS's "wants to use … to sign in" alert. (Spike 1.)
- **Callback scheme:** the app's own scheme, from its operator config (the same value Home Base holds).

## Why this is safe

| Threat | What stops it |
|---|---|
| Another app on the phone intercepts the callback | The callback carries nothing. `ASWebAuthenticationSession` also takes it directly, without iOS's usual routing between apps. |
| Someone else redeems a finished record | Redeeming needs the web view's `__Host-` correlation cookie, the same member and the same hostname. |
| A sibling hostname begins or redeems | The mutation guard (section 4.2) and strict isolation (4.1): every step is a same-origin JSON `POST`. |
| Someone else's handoff gets confirmed | The sheet's `options` and `finish` need the record's member, and the sheet shows a summary of what it confirms, taken from the record, never from the URL. |
| A stale or reused handoff or challenge | The record lasts 5 minutes and is taken on redeem. The challenge gets one attempt (section 11). |
| A page outside the household drives the sheet | The bridge exists only in household main frames, and only opens the sheet on the calling page's own origin. |
| A replayed action token | Unchanged: `jti`, the digest and redemption (section 9). |

As in section 10, **pages on the same origin are trusted.** A page on `H` could begin a handoff and redeem it, but it could already run the in-page ceremony in a browser. Handoff gives it nothing new.

### Open: which client gets the result (blocks implementation)

Found in review. **Nothing in the flow above proves that the client redeeming the result is the household's real app.**

A malicious app installed on the member's phone could do this:
1. Call `handoff/begin` from its own HTTP client. A native client sets any headers it likes, and the tailnet identity is the device's, shared by every app on it.
2. Keep the correlation cookie it receives.
3. Open its own `ASWebAuthenticationSession` on the real sheet.
4. If the member approves the prompt, redeem the result into its own client.

Every check passes. Apple delivers a session's callback to the session that started it, which protects the real app's session from interception, but it does the same for the attacker's.

**This is a regression against today.** Today a ceremony's result stays in the Safari context that ran it. An app can open a Safari view or a sheet, but it can't read the cookie set inside one. A malicious app can't run the ceremony in its own web view either, because it can't claim the tailnet domain. The handoff is exactly what makes the result transferable.

**What the attack still needs:** the member has to approve a passkey prompt they didn't start, in an unexpected app. A shared, non-ephemeral session would name the calling app in iOS's "wants to use … to sign in" alert, which helps a little. Even so, an approval phished this way would hand over an administrator session (8 hours) or a hardware-backed action token.

Two ways to close it:

- **A. Bind the handoff to the genuine app with App Attest.**
  - The app registers an App Attest key with Home Base for this member. Apple's attestation proves the key belongs to the household's App ID (team plus bundle ID, from Home Base's install config). Registration needs only the tailnet identity: a malicious app can't produce an attestation for that App ID.
  - `begin` and `redeem` each carry an App Attest assertion over the handoff `id`, so a client without that key can't start a handoff or collect a result.
  - This shares sovereignAuth's App Attest verification with the planned iPhone approval key (Home Base `planning/research/iphone-hardware-key.md`, slice 1), so the same registered key can later become that approver.
  - The cost: App Attest works only in production-signed builds (TestFlight or App Store) unless development is allowed, which is that note's open decision 5.
- **B. Don't transfer results.**
  - The app opens any page that needs a passkey in a Safari view, where the ceremony and the session both stay.
  - The bridge shrinks to "open this page in a Safari view".
  - It's safe and small, but the member continues in a Safari view rather than the app's own view.

Recommendation: **B now**, since it's what the app already does by hand, then **A** together with the iPhone approval key.

## Home Base's own pages

Home Base's admin pages (unlock and enrollment) call the passkey API directly, not through `stepup.js`.
- **In scope:** unlocking administration, which is a check on Home Base's hostname. Its page branches on the bridge the same way the helper does.
- **Not in this design:** enrolling a passkey and activation (setup or recovery). They stay in a browser or a Safari view, and the app opens them there.

## Slices

Each is one PR touching few files.

1. **sovereignAuth:** this section in the wire contract, and `createHandoff`, the record store and every check above, as `createOAuthFlow` does for section 10. Conformance vectors in `vectors/handoff.json`. The passkey service is Node-only, so there's no Python port.
2. **Home Base:**
   - the `handoff/begin`, `options`, `finish` and `redeem` routes, plus the sheet page, on Home Base's hostname and on sensitive apps' hostnames (added to their route list);
   - the `nativeAppScheme` setting.
3. **Home Base:** the bridge branch in `stepup.js` and in the admin unlock page.
4. **sovereignShell:** `window.sovereign` version 1 (`handoff`) in the shell's web view, and the scheme in operator config.

## Spikes before slice 2

1. **Ephemeral sheet:** run a ceremony in an ephemeral `ASWebAuthenticationSession` with iCloud Keychain, 1Password and a YubiKey (NFC and USB-C). Fallback: a shared session, which shows iOS's sign-in alert each time.
2. **The sheet's identity:** confirm the sheet's requests carry the same tailnet identity as the web view's. They should, since it's the same device and the same Tailscale connection; spike c suggests they do.
3. **Closing the sheet:** confirm that navigating to the custom scheme from the sheet page's script, after a `fetch`, closes the sheet. iOS may require that navigation to follow a tap; if so, the sheet shows a "Return to the app" button.

## Questions for the operator

0. **Client binding:** A (App Attest) or B (Safari view only). See "Open: which client gets the result".
1. **The ephemeral sheet** (no "wants to use … to sign in" alert), if spike 1 passes. Recommended.
2. **Scope:** checks and every-time actions now; enrollment from the app later. Recommended.
3. **Where the scheme lives:** one Home Base setting per household, matched by the app's operator config. Recommended.
