# Mini OIDC

**mini-oidc** is the **human SSO / OpenID Provider** for the mini- family. It runs the OAuth 2.0
**authorization-code flow with [PKCE](https://datatracker.ietf.org/doc/html/rfc7636)**, authenticates
people with **passkeys** ([WebAuthn](https://www.w3.org/TR/webauthn-2/)), and issues **ID + access
tokens** (signed by the shared [`mini-token`](../../libs/mini-token) plane, so they verify *offline*
against the same JWKS as mini-idp's) plus rotating **refresh tokens**. Where
[mini-idp](../mini-idp) authenticates *machines* (the client-credentials grant), mini-oidc
authenticates *people* (a browser flow with login, consent, and a session).

It is an **educational** project — a sibling to mini-kms and mini-idp: heavily commented, real but
un-audited crypto, built to be *read*. Its defining trait is **composition over reinvention** — it
invents almost nothing, wiring together four existing pieces:

| Concern | Delegated to |
| --- | --- |
| Passkey ceremony (WebAuthn) + backup-code recovery | **pk-auth** (`com.codeheadsystems:pk-auth-*`, embedded) |
| Token signing, JWKS, key rotation | **[mini-token](../../libs/mini-token)** (reused — *not* re-implemented) |
| Scope authorization (which scopes a user may get) | **[mini-policy](../../libs/mini-policy)** (`decide(principal, scope, "oidc:scope")`) |
| Resolving the user to a principal + grants + profile | **[mini-directory](../mini-directory)** (via the `UserDirectory` SPI) |

The *only* code added to the shared token plane for OIDC was an **additive** generic
`Jws.sign(JwsHeader, Map, PrivateKey)` overload, so OIDC claim sets sign with the same format and
keys as mini-idp's typed tokens. mini-idp's path is untouched.

> **Not for production.** Passkeys live in an in-memory credential store (lost on restart); passkey
> enrolment is currently unauthenticated self-enrolment; and the server speaks plain HTTP on loopback.
> Any LAN exposure **must** be behind a TLS-terminating reverse proxy with `--secure-cookies` — both
> WebAuthn and `Secure` cookies require a secure context.

## Table of contents

- [What it does](#what-it-does)
- [Glossary](#glossary)
- [The authorization-code + PKCE flow](#the-authorization-code--pkce-flow)
- [Quick start](#quick-start)
- [The integration contract (for a relying party)](#the-integration-contract)
  - [Discovery & JWKS URLs](#discovery--jwks-urls)
  - [Token claim schemas](#token-claim-schemas)
  - [How to verify a token offline](#how-to-verify-a-token-offline)
- [Endpoints](#endpoints)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Security notes](#security-notes)
- [Current limitations](#current-limitations)
- [Building & testing](#building--testing)

## What it does

- **Authenticates humans with passkeys.** `GET /authorize` parks a validated request server-side and
  shows a login page; the browser runs a WebAuthn assertion (verified by the embedded pk-auth), which
  establishes an SSO **session** cookie. Lost your device? A view-once **backup code** is the wired
  fallback.
- **Gets consent and issues a code.** A consent page lists the requested scopes; on approval a
  one-time **authorization code** is redirected back to the client's pre-registered URI.
- **Exchanges the code for tokens.** `POST /token` (`grant_type=authorization_code`) verifies the
  PKCE `code_verifier` and returns an **ID token**, an **access token**, and a **refresh token**.
- **Rotates refresh tokens** (`grant_type=refresh_token`) with family-based replay defense.
- **Serves `/userinfo`** — profile/email claims for the access token's subject, filtered by the
  scopes that were granted.
- **Single logout** (`GET /logout`) — destroys the session and revokes the subject's refresh tokens.
- **Registers relying parties** (admin API) and **publishes discovery + JWKS** so any RP verifies
  tokens offline.
- **Documents everything** as an OpenAPI 3.1 spec served at a stable URL and rendered by a bundled
  Swagger UI.

## Glossary

| Term | Meaning here |
| --- | --- |
| **OP** (OpenID Provider) | This service — it authenticates the user and issues tokens. |
| **RP** (Relying Party) | A registered client app (`OidcClient`) that sends users here to log in. |
| **Authorization-code flow** | The browser gets a short-lived **code**; the RP's server swaps it for tokens at `/token`. The code never carries token material. |
| **PKCE** | Proof Key for Code Exchange (RFC 7636). The RP commits to a secret `code_verifier` up front via a `code_challenge`; only the holder of the verifier can redeem the code. **Mandatory here for every request.** |
| **ID token** | A JWT *about the authentication event*, for the RP. Audience = the client. Carries `sub`, `auth_time`, optional `nonce`, and profile/email per scope. |
| **Access token** | A JWT *for calling a resource* (here, `/userinfo`). Audience = the OP's userinfo URL. Carries `scope` + `azp`. |
| **Refresh token** | An opaque `id.secret` value (not a JWS) the RP swaps for fresh tokens. Rotates on every use. |
| **Confidential / public client** | Confidential has a secret (Argon2id-hashed); public has none and relies on PKCE alone. |
| **Session** | The browser's SSO state, in a cookie. Its lifetime is **separate** from (and longer than) the token TTLs — one login, many token issuances. |
| **Pending authorization** | A validated `/authorize` request parked server-side (keyed by an opaque `requestId`) while the human logs in and consents, so request params can't be tampered with mid-flow. |
| **Family** (refresh) | The chain of refresh tokens descended from one login. Replaying a rotated token scorches the whole family. |

## The authorization-code + PKCE flow

```
 ┌─ browser ─────────────────────────────────────────────────────────────────────────┐
 │                                                                                     │
 │  1. GET /authorize?response_type=code&client_id=…&redirect_uri=…                    │
 │       &scope=openid%20profile&state=…&nonce=…&code_challenge=…&code_challenge_method=S256
 │           │  OP validates: known client? redirect_uri pre-registered? scope has     │
 │           │  openid? PKCE present? → parks a PendingAuthorization (requestId+CSRF).  │
 │           ▼                                                                          │
 │  2. login page  ──POST /login/passkey/start {requestId, username}──▶ WebAuthn opts   │
 │       │         ◀─ browser runs navigator.credentials.get() (the passkey) ─┐         │
 │       └──POST /login/passkey/finish {requestId, csrf, challengeId, assertion}        │
 │              │  pk-auth verifies the assertion → username; OP creates a session,     │
 │              │  Set-Cookie: <session> (HttpOnly; SameSite=Lax; [Secure]).            │
 │              ▼   (fallback: POST /login/recovery with a backup code)                 │
 │  3. GET /authorize/continue?req=…  ──▶  consent page (lists requested scopes)        │
 │       └──POST /authorize/decision {requestId, csrf, decision=approve}                │
 │              │  mini-policy backstop: granted = requested ∩ allowed-for-this-user.   │
 │              │  Mint a one-time AuthorizationCode (binds client/redirect/sub/PKCE).  │
 │              ▼                                                                        │
 │  4. 302 → redirect_uri?code=…&state=…                                                │
 └──────────────────────────────────────────────────│─────────────────────────────────┘
                                                     ▼   (back channel, RP's server)
 5. POST /token  grant_type=authorization_code&code=…&redirect_uri=…&code_verifier=…
        [+ client_secret / HTTP Basic if confidential]
        │  OP re-checks: code unused & unexpired? same client & redirect_uri?
        │  PKCE: SHA-256(code_verifier) == code_challenge?  (constant-time)
        ▼
    { id_token, access_token, token_type:"Bearer", expires_in, refresh_token, scope }
        ├─ verify id_token / access_token OFFLINE: GET /jwks.json → pick key by kid → EdDSA verify
        ├─ GET /userinfo  (Authorization: Bearer <access_token>)  → claims filtered by granted scope
        ├─ POST /token  grant_type=refresh_token&refresh_token=…  → ROTATED access + id + refresh
        └─ GET /logout  → session destroyed, refresh family revoked, cookie cleared

 Replay defenses:  a re-used authorization code revokes the refresh family it produced;
                   a re-used (already-rotated) refresh token revokes its entire family.
```

### The flow in code (step by step)

The same flow, traced through `server/OidcHandlers.java` and the `service/` stores:

1. **`GET /authorize`** — `authorize` (`OidcHandlers.java:163`) validates the client, exact-matches
   `redirect_uri`, requires `response_type=code`, the `openid` scope, and **PKCE `S256`** (a missing
   or non-S256 method is rejected back to the redirect URI), then parks a `PendingAuthorization`
   (opaque `requestId` + CSRF token) server-side (`:192`) and returns the login page (or consent if
   a session already exists).
2. **Passkey login** — `POST /login/passkey/start` (`:245`) returns the WebAuthn options;
   `POST /login/passkey/finish` (`:254`) verifies the assertion via pk-auth and resolves the verified
   `UserHandle` to a username; `completeLogin` (`:277`) creates the SSO session
   (`sessions.create`, `:282`) and sets the cookie. (`POST /login/recovery` is the backup-code
   fallback.)
3. **Consent** — `POST /authorize/decision` (`:214`) checks the CSRF token (`requireCsrf`, `:220`,
   constant-time), filters the requested scopes through mini-policy (`scopeAuthorizer.authorize`,
   `:229`), mints a one-time `AuthorizationCode` binding client / redirect / subject / PKCE challenge
   / `auth_time` (`codes.put`, `:232`), and 302s back to the redirect URI with `code` + `state`
   (`:240`).
4. **`POST /token` (code grant)** — `authorizationCodeGrant` (`:302`): `authenticateClient` (`:354`)
   authenticates a confidential client (or accepts a public one); `codes.consume` (`:304`) redeems
   the code exactly once — a replay revokes the refresh family it first produced (`:307`); the client
   id, redirect URI, and the **PKCE verifier** are re-checked (`Pkce.verify`, `:315`); then it mints
   the access token (`:320`) and ID token (`:321`) on mini-token's keys and issues a rotating refresh
   token (`:322`), binding the code to that refresh family (`:323`).
5. **`POST /token` (refresh grant)** — `refreshGrant` (`:327`) rotates the presented refresh token
   (`refreshTokens.rotate`, `:328`): a valid token yields a fresh access / ID / refresh set (carrying
   the **original** `auth_time`), while re-using an already-rotated token scorches the whole family.

## Quick start

Requires JDK 21+. Loopback by default; the bootstrap admin token (for **client registration**) comes
from an env var or a file — **never argv, never logged**.

```bash
export MINIOIDC_ADMIN_TOKEN="$(openssl rand -hex 32)"
./gradlew :services:mini-oidc:installDist
services/mini-oidc/build/install/mini-oidc/bin/mini-oidc \
  --port 8477 --issuer https://oidc.example \
  --rp-id oidc.example --rp-origin https://oidc.example \
  --directory-url http://127.0.0.1:8466 --directory-token-file ~/.mini-directory/admin-token \
  --secure-cookies
```

Discovery is at `/.well-known/openid-configuration`, keys at `/jwks.json`, Swagger UI at `/docs`.
Register a relying party with the admin token:

```bash
curl -s -XPOST http://127.0.0.1:8477/admin/clients \
  -H "Authorization: Bearer $MINIOIDC_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Demo","redirectUris":["https://app.example/cb"],"scopes":["openid","profile","email"],"confidential":false}'
# -> { "clientId":"…", "secret":null, "name":"Demo", "redirectUris":[…], "scopes":[…], "confidential":false }
#    (a confidential client's "secret" is returned here exactly ONCE)
```

> Without `--directory-url`, an **empty in-memory directory** is used and **no human resolves** —
> useful only for kicking the tyres. Point it at a running mini-directory for real use, and enrol the
> passkey for a username that exists there.

## The integration contract

The authoritative, machine-readable contract is the **OpenAPI 3.1** spec (`/openapi.yaml`,
`/openapi.json`, Swagger UI at `/docs`). A relying party integrates against the standard OIDC
discovery document.

### Discovery & JWKS URLs

```
GET /.well-known/openid-configuration
  -> { issuer, authorization_endpoint, token_endpoint, userinfo_endpoint, jwks_uri,
       end_session_endpoint,
       response_types_supported: ["code"],
       grant_types_supported:    ["authorization_code", "refresh_token"],
       scopes_supported:         ["openid", "profile", "email"],
       subject_types_supported:  ["public"],
       id_token_signing_alg_values_supported:    ["EdDSA"],
       token_endpoint_auth_methods_supported:     ["client_secret_basic", "client_secret_post", "none"],
       code_challenge_methods_supported:          ["S256"] }

GET /jwks.json
  -> { "keys": [ { kty:"OKP", crv:"Ed25519", x, use:"sig", alg:"EdDSA", kid }, … ] }
```

The JWKS contains the active signing key plus any **recently retired** keys (overlapping `kid`s) —
retired keys are retained for `2 × max(id-ttl, access-ttl)` — so a token signed just before a
rotation keeps verifying until it expires.

### Token claim schemas

Both tokens are compact JWS with the header `{"alg":"EdDSA","typ":"JWT","kid":"<kid>"}`.

**ID token** (audience = the client — *who logged in, and when*):

```jsonc
{
  "iss": "https://oidc.example",
  "sub": "alice",                 // the directory account id (the authenticated principal)
  "aud": "client_…",              // the client id
  "azp": "client_…",              // authorized party (same client id)
  "iat": 1781454541,
  "nbf": 1781454541,
  "exp": 1781454841,              // iat + id-ttl (default 300s)
  "auth_time": 1781454500,        // when the human actually authenticated
  "nonce": "…",                   // echoed from the request, if one was sent
  "name":  "Alice Example",       // only if the `profile` scope was granted AND known
  "email": "alice@example",       // only if the `email` scope was granted AND known
  "email_verified": false
}
```

**Access token** (audience = the OP's userinfo URL — *a bearer credential for `/userinfo`*):

```jsonc
{
  "iss":   "https://oidc.example",
  "sub":   "alice",
  "aud":   "https://oidc.example/userinfo",   // = issuer + "/userinfo"
  "azp":   "client_…",
  "scope": "openid profile",                   // space-delimited granted scopes
  "iat": 1781454541, "nbf": 1781454541,
  "exp": 1781454841                            // iat + access-ttl (default 300s)
}
```

The **refresh token** is *not* a JWS: it is an opaque `id.secret` string. Only the secret's SHA-256
is stored; presenting it at `/token` rotates it (you get a new one back; the old one is now spent).

### How to verify a token offline

1. Fetch and cache `GET /jwks.json`.
2. Read the JWS header `kid`; select the matching JWK; verify the **EdDSA (Ed25519)** signature over
   `base64url(header) + "." + base64url(payload)`.
3. Check `iss`, `aud` (the client id for an ID token; the userinfo URL for an access token), and the
   `nbf`/`exp` window (allow a little clock skew). For an ID token, also check `nonce` matches the one
   you sent.

mini-token's `JwsClaimsVerifier` is the reference implementation — and is exactly what mini-oidc's
own `/userinfo` uses to validate the presented access token (issuer + userinfo audience, 5 s skew).

## Endpoints

**Discovery / meta** (public)

| Method & path | Purpose |
| --- | --- |
| `GET /.well-known/openid-configuration` | OIDC discovery document. |
| `GET /jwks.json` | Public signing keys (overlapping `kid`s during rotation). |
| `GET /health` | Liveness. |
| `GET /openapi.yaml`, `GET /openapi.json` | The served spec. |
| `GET /docs` | Swagger UI (vendored, works offline). |

**Browser authorization-code + PKCE flow**

| Method & path | Purpose |
| --- | --- |
| `GET /authorize` | Authorization endpoint. Validates client/redirect/scope/PKCE, parks the request, shows login (or consent if already signed in). |
| `POST /login/passkey/start` · `POST /login/passkey/finish` | WebAuthn assertion (login); `finish` establishes the session. |
| `POST /login/recovery` | Backup-code fallback login. |
| `GET /authorize/continue` | Resume after login → consent page (or back to login if no session). |
| `POST /authorize/decision` | Record the consent decision; on approve, mint + redirect the code. CSRF-protected. |

**Token / userinfo / logout**

| Method & path | Purpose |
| --- | --- |
| `POST /token` | `authorization_code` and `refresh_token` grants → `access_token`, `id_token`, `refresh_token`, `expires_in`, `scope`. |
| `GET /userinfo` | Claims for the access token's `sub`, filtered by granted scope. Bad/expired token → `401 invalid_token` (no oracle). |
| `GET /logout` | Single logout: destroy session, revoke the subject's refresh tokens, clear the cookie. Optional `post_logout_redirect_uri`. |

**Passkey enrolment** (currently *unauthenticated self-enrolment* — see [limitations](#current-limitations))

| Method & path | Purpose |
| --- | --- |
| `POST /register/passkey/start` · `POST /register/passkey/finish` | WebAuthn registration ceremony. |

**Client admin** (require `Authorization: Bearer <MINIOIDC_ADMIN_TOKEN>`)

| Method & path | Purpose |
| --- | --- |
| `POST /admin/clients` | Register a relying party (returns a confidential client's secret exactly once). |
| `GET /admin/clients` | List registered clients (no secrets). |

## Configuration

Flags override environment variables override defaults (mirrors the sibling services' `ServerConfig`).

| Flag | Env var | Default | Meaning |
| --- | --- | --- | --- |
| `--host` | `MINIOIDC_HOST` | `127.0.0.1` | Loopback bind host. |
| `--port` | `MINIOIDC_PORT` | `8477` | TCP port (`0` = ephemeral). |
| `--issuer` | `MINIOIDC_ISSUER` | `http://<host>:<port>` | `iss` claim + discovery base (trailing slash stripped). |
| `--rp-id` | `MINIOIDC_RP_ID` | `localhost` | WebAuthn relying-party id (the registrable domain). |
| `--rp-name` | `MINIOIDC_RP_NAME` | `mini-oidc` | Relying-party display name. |
| `--rp-origin` | `MINIOIDC_RP_ORIGINS` | `http://localhost:<port>` | Comma-separated acceptable WebAuthn origins. |
| `--data-dir` | `MINIOIDC_DATA_DIR` | `~/.mini-oidc` (or `$XDG_DATA_HOME/mini-oidc`) | JSON stores. |
| `--admin-token-file` | `MINIOIDC_ADMIN_TOKEN_FILE` | — | File holding the admin token (alt: `MINIOIDC_ADMIN_TOKEN` env). |
| `--directory-url` | `MINIOIDC_DIRECTORY_URL` | — | mini-directory base URL (else the empty in-memory directory). |
| `--directory-token-file` | `MINIOIDC_DIRECTORY_TOKEN_FILE` | — | mini-directory admin token file (alt: `MINIOIDC_DIRECTORY_TOKEN` env). |
| `--secure-cookies` | `MINIOIDC_SECURE_COOKIES` | off | Set the `Secure` attribute on cookies (enable behind TLS). |
| `--session-ttl-seconds` | `MINIOIDC_SESSION_TTL_SECONDS` | `43200` (12h) | SSO session lifetime. |
| `--access-ttl-seconds` | `MINIOIDC_ACCESS_TTL_SECONDS` | `300` | Access-token lifetime. |
| `--id-ttl-seconds` | `MINIOIDC_ID_TTL_SECONDS` | `300` | ID-token lifetime. |
| `--refresh-ttl-seconds` | `MINIOIDC_REFRESH_TTL_SECONDS` | `2592000` (30d) | Refresh-token lifetime. |
| `--code-ttl-seconds` | `MINIOIDC_CODE_TTL_SECONDS` | `60` | Authorization-code lifetime. |
| `--argon-memory-kib` / `--argon-iterations` / `--argon-parallelism` | `MINIOIDC_ARGON_*` | pk-auth defaults | Client-secret Argon2id cost. |
| `--kms-tcp`, `--kms-key-group`, `--kms-api-token-file` | `MINIOIDC_KMS_*` | — | Optional: wrap the signing keys under mini-kms (the recursive integration; alt token env `MINIOIDC_KMS_API_TOKEN`). |

The admin (and directory, and KMS API) tokens are resolved from an env var or a `*-token-file`,
**never from a CLI argument**, and are never logged.

## Architecture

One application module under `com.codeheadsystems.minioidc`. The composition root is
`server/OidcServer` (builds every store + service + the pk-auth stack and binds a loopback JDK
`HttpServer`, one virtual thread per request); `ServerMain` resolves config + tokens and wires the
production collaborators.

- **`auth`** — the human-authentication seam. `HumanAuthenticator` (the JSON-in/JSON-out passkey
  ceremony) is implemented by `PkAuthHumanAuthenticator` over pk-auth's
  `PasskeyAuthenticationService`; `RecoveryAuthenticator` wraps pk-auth's `BackupCodeService`.
  `PasskeyStack` assembles the embedded pk-auth stack over its **in-memory** SPIs — the documented
  swap point for persistent credential storage (pk-auth's JDBI/DynamoDB SPIs).
- **`directory`** — the `UserDirectory` SPI resolving an authenticated human to a `DirectoryUser`
  (mini-policy `Principal` + grants + profile claims). `HttpUserDirectory` is the production path
  (calls mini-directory's `GET /admin/principals/{id}/resolution`, fails closed on any non-200);
  `InMemoryUserDirectory` backs tests/dev.
- **`service`** — `OidcTokens` mints ID/access tokens on mini-token's keys + `Jws`;
  `ScopeAuthorizer` authorizes scopes through mini-policy; plus the flow stores:
  `PendingAuthorizationStore` (parked requests, 10-min TTL), `AuthorizationCodeStore`
  (single-use codes, replay→family-revoke), `RefreshTokenService` (rotating, replay defense),
  `ClientService` (the RP registry over `clients.json`).
- **`model`** — the records: `OidcClient`, `PendingAuthorization`, `AuthorizationCode`,
  `RefreshTokenRecord`.
- **`server`** — `OidcServer`/`ServerMain`, `ServerConfig`, `OidcHandlers` (every endpoint),
  `LoginPages` (minimal login/consent HTML), `Cookies`, `AdminAuthenticator`, the reused `http/`
  router and `store/JsonStore`, and the OpenAPI/Swagger serving.

```
authenticate:  GET /authorize → passkey assertion (pk-auth) → session cookie → consent
issue:         AuthorizationCode --(verify PKCE)--> mini-token Jws.sign --> id_token + access_token
               (+ opaque refresh_token, rotating)
verify (RP):   token --kid--> JWK --EdDSA verify--> claims     (offline; same JWKS as mini-idp)
authorize:     requested scopes ∩ mini-policy decide(principal, scope, "oidc:scope") = granted
resolve:       username --HttpUserDirectory--> mini-directory /resolution --> Principal + grants
```

**What is reused vs. new.** Signing keys, JWKS, and rotation are mini-token's `SigningKeyService`
verbatim (and the keys can be mini-kms-wrapped exactly like mini-idp's). The SSO session mechanism is
mini-token's `SessionService` over `sessions.json` — the *same* store [mini-gateway](../mini-gateway)
reads, with the *same* cookie name (`SessionService.DEFAULT_COOKIE_NAME`). The scope decision is
mini-policy's `GrantBasedPolicyEngine`. The passkey ceremony is pk-auth. mini-oidc's own code is the
browser-flow plumbing (pending requests, codes, refresh rotation, consent UI) and the OIDC claim sets.

## Security notes

- **PKCE is mandatory** for every authorization-code request (public *and* confidential clients).
  Missing/unknown method → the request is rejected back to the redirect URI as `invalid_request`.
- **Redirects only to pre-registered URIs.** `redirect_uri` must exactly match one the client
  registered, or the request is refused *before* any redirect — open redirects are how codes get
  phished. Validation errors after that point are reported by redirecting to the (now trusted) URI
  with an OAuth `error`/`state`.
- **Browser SSO session** in an `HttpOnly`, `SameSite=Lax`, `Secure`-when-configured cookie; only a
  hash of the session id is stored server-side. The **session lifetime is distinct from the token
  TTLs** — one login backs many short-lived token issuances.
- **CSRF token** bound to each server-side pending authorization, required (constant-time compared) on
  every state-changing browser POST: login finish, recovery, and the consent decision.
- **Single-use authorization codes**, short-lived (60 s) and PKCE-bound. A replayed code revokes the
  refresh-token family it first produced.
- **Rotating refresh tokens** with family-based replay defense: redeeming rotates to a successor;
  re-using an already-rotated token scorches the entire family, so a stolen token can't outlive one
  use.
- **mini-policy scope backstop.** Even a scope the user approves on the consent screen is only issued
  if mini-policy allows it for that principal (`openid` always; an admin principal bypasses). The
  granted set gates both the access-token `scope` and the `/userinfo` claims.
- **No oracle.** One generic `invalid_grant` for any code/refresh failure; one `invalid_client` for
  client-auth failure (confidential secrets are Argon2id-hashed and compared in constant time, with a
  dummy-hash path for unknown ids); one `invalid_token` at `/userinfo`. No secret material is ever
  logged; a confidential client's secret is shown exactly once at registration.
- **At-rest:** `clients.json`, `sessions.json`, and `signing-keys.json` are written atomically and
  `0600`; with `--kms-*` the signing keys are envelope-wrapped under mini-kms (no plaintext key on
  disk). Pending requests, codes, and refresh tokens are in-memory.
- **Loopback by default.** WebAuthn and `Secure` cookies require a secure context, so any LAN exposure
  **must** run behind a TLS-terminating reverse proxy with `--secure-cookies`.

## Current limitations

- The embedded pk-auth credential store is **in-memory** — passkeys are lost on restart. The swap
  point is pk-auth's persistent `CredentialRepository` / `UserLookup` / `ChallengeStore` SPIs.
- **Passkey enrolment (`/register/passkey/**`) is unauthenticated self-enrolment**, suitable for
  bootstrapping/dev; a real deployment gates it (invite/admin).
- **Backup codes** are the wired recovery path; pk-auth's magic-link and OTP services plug into the
  same `RecoveryAuthenticator` seam once their email/SMS senders are configured.
- mini-directory does not yet model **email**, so the production `HttpUserDirectory` resolves
  `email`/`email_verified` as absent — `/userinfo` and the ID token simply omit the `email` claim even
  when the scope is granted. (`InMemoryUserDirectory` can supply it for tests.)
- Without `--directory-url`, an empty in-memory directory is used and **no human resolves**.

## Building & testing

```bash
./gradlew :services:mini-oidc:test           # this module's tests
./gradlew :services:mini-oidc:installDist     # runnable launcher at build/install/mini-oidc/bin/mini-oidc
./gradlew build                               # compile + all tests across the family (the CI gate)
```

The test suite exercises the full browser flow end-to-end (authorize → passkey login → consent →
code → token), offline verification of the issued ID/access tokens against the published JWKS, PKCE
enforcement, the no-open-redirect and CSRF guards, refresh-token rotation and family revocation on
replay, the mini-policy scope backstop, `/userinfo` scope filtering, single logout, and the OpenAPI
spec being served, parseable, and matching the live routes.
