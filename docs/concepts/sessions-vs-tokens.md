# Sessions vs. tokens — two clocks, one login

> **Concept doc (explanation).** Stage 4. Anchored on **mini-token**'s session store and
> **mini-oidc**. New terms link to [`GLOSSARY.md`](../GLOSSARY.md); rationale in
> [`DIRECTION.md`](../DIRECTION.md). Diagram: [`auth-code-pkce`](../diagrams/auth-code-pkce.md). Lab:
> [`04`](../tutorials/04-human-sso-end-to-end.md).

When a human logs in, **two** things are created with **two different lifetimes**, and conflating
them is a common source of bugs:

- a **browser SSO session** — "this browser has a logged-in human" — carried in a cookie;
- one or more **tokens** — "here is a verifiable assertion for an app/API" — carried in headers.

They answer different questions, live in different places, and expire on different clocks.

| | **Session** | **Token (access / ID)** |
| --- | --- | --- |
| Answers | "is this *browser* logged in?" | "is this *request* authorized?" |
| Lives in | a cookie (`mioidc_session`), server-side store | the `Authorization` header / the app |
| Verified by | a lookup in the shared store | offline signature check (no lookup) |
| Lifetime | the SSO session TTL (longer) | short token TTL (minutes) |
| Who reads it | mini-oidc (and mini-gateway, as a *reader*) | any verifier with the JWKS |

---

## Why the session lifetime ≠ the token TTL

This is the crux. **Access tokens are deliberately short-lived** (minutes) so a leaked one expires
fast and so revocation windows stay small — and because they verify *offline*, nobody can reach out
to kill one mid-life. The **session is longer-lived** so the human doesn't re-authenticate every few
minutes.

The session is what lets the short token be short: when the access token expires, the app gets a new
one *without bothering the human*, because the **session** (or a refresh token) still vouches for the
login. Two clocks, on purpose:

```
login ──┬───────────────────────── session valid (hours) ─────────────────────────┐
        │                                                                          │
        ├─ token #1 (5 min) ─┐                                                     │
        │                    └─ token #2 (5 min) ─┐                                │
        │                                         └─ token #3 (5 min) ─┐  …        │
        └──────────────────────────────────────────────────────────────────────── logout / expiry
```

If you gave tokens the session's lifetime, a single leaked token would be valid for hours with no
way to retract it. If you gave the session the token's lifetime, the human would log in every five
minutes. The split buys you both: short blast radius *and* a usable experience.

---

## The cookie, concretely

mini-oidc's session cookie is deliberately conservative (`server/Cookies.java`):

- **Name** `mioidc_session` (the shared `SessionService.DEFAULT_COOKIE_NAME`).
- **HttpOnly** — JavaScript can't read it (XSS can't steal it).
- **SameSite=Lax** — it rides the top-level GET redirect back from the OP, but not arbitrary
  cross-site POSTs (CSRF mitigation).
- **Secure** — configurable; **must** be on behind a TLS proxy (`--secure-cookies`).
- **Path=/**, host-only — which is what lets mini-gateway, on a *shared hostname*, read the same
  cookie.

**The session id is never stored in the clear.** The store keeps `SHA-256(sessionId)`; the random id
lives only in the cookie. A stolen *store* doesn't yield usable session ids. (OWASP session
management, in the family's style.)

---

## The shared session store — one writer, many readers

The SSO session lives in **mini-token** (`session/SessionService` over the `DocumentStore` SPI),
persisted to `sessions.json`. The important architectural fact:

> **mini-oidc is the sole *writer*. mini-gateway is a *reader* of the same file.** There is not a
> second session mechanism — the gateway authenticates a browser by looking up the *same* cookie in
> the *same* store.

That's why a human who logged into mini-oidc is immediately recognized at a mini-gateway-protected
app: same cookie name, same store, shared hostname. (Stage 5.) It also means a `SCOPE`-gated route
can't be satisfied by a session alone — a **session carries no scopes**, only an identity; scopes
live in *access tokens*. (A trust-boundary detail in the
[threat-model overview](../security/threat-model-overview.md).)

---

## Refresh tokens — extending the login safely

When the access token expires, the app trades a **refresh token** for a fresh pair without
re-authenticating the human. mini-oidc makes refresh tokens **rotate on every use** with
**family-based replay defense**:

- each use issues a *new* refresh token (same "family") and marks the old one used;
- if a *spent* refresh token is ever presented again, that's the signature of theft (someone has a
  stolen copy) — so the **entire family is revoked.** Both the thief's and the legitimate client's
  tokens die, failing safe.

`auth_time` (when the human actually authenticated) is carried **unchanged** across refreshes, so an
app's "re-authenticate if older than X" check stays honest even after many silent refreshes.

---

## Now read it

- **The session:** `libs/mini-token` → `session/SessionService` (create/lookup/destroy; SHA-256 at
  rest), `session/BrowserSession`; `services/mini-oidc` → `server/Cookies` (the flags above).
- **Refresh rotation:** `services/mini-oidc` → `service/RefreshTokenService` (rotate + family-revoke).
- **The shared reader:** `services/mini-gateway` → `auth/SessionAuthenticator` (same store, as a
  reader).

Lab: [`04-human-sso-end-to-end.md`](../tutorials/04-human-sso-end-to-end.md). Next concept:
[`envelope-encryption-and-kms.md`](envelope-encryption-and-kms.md).
