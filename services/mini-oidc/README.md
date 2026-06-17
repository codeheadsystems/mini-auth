# mini-oidc

The **human SSO / OpenID Provider** for the mini- family. It runs the OAuth 2.0
**authorization-code flow with PKCE**, authenticates people with **passkeys** (WebAuthn), and issues
**ID + access tokens** (signed by the shared [`mini-token`](../../libs/mini-token) plane, so they
verify offline against the JWKS) plus rotating **refresh tokens**. Where [mini-idp](../mini-idp)
authenticates machines, mini-oidc authenticates people.

It is **educational, but homelab-functional**, and is a study in **composition over reinvention**:

| Concern | Delegated to |
| --- | --- |
| Passkey ceremony (WebAuthn) + backup-code recovery | **pk-auth** (`com.codeheadsystems:pk-auth-*`, embedded) |
| Token signing, JWKS, key rotation | **mini-token** (reused — not re-implemented) |
| Scope authorization | **mini-policy** (`decide(principal, scope, "oidc:scope")`) |
| Resolving the user to a principal + grants | **mini-directory** (via the `UserDirectory` SPI) |

## The flow

```
browser ──GET /authorize?client_id&redirect_uri&scope=openid…&code_challenge&state&nonce
        │   (validate client + redirect + PKCE; create a server-side pending request)
        ▼
   login page ──passkey assertion (pk-auth)──▶ session cookie ──▶ consent page ──approve──▶
        │
        ▼  302 redirect_uri?code=…&state=…
client ──POST /token (code + code_verifier [+ client_secret])──▶ { id_token, access_token, refresh_token }
        ├─ verify id_token offline: GET /jwks.json → pick key by kid → EdDSA verify → check iss/aud/exp
        ├─ GET /userinfo  (Bearer access_token)            → claims filtered by granted scope
        ├─ POST /token grant_type=refresh_token            → rotated access + refresh tokens
        └─ GET /logout                                     → session destroyed, refresh family revoked
```

## Run it locally

Loopback by default; the bootstrap admin token (for **client registration**) comes from an env var
or file — **never argv, never logged**.

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
Register a client with the admin token:

```bash
curl -s -XPOST http://127.0.0.1:8477/admin/clients \
  -H "Authorization: Bearer $MINIOIDC_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Demo","redirectUris":["https://app.example/cb"],"scopes":["openid","profile","email"],"confidential":false}'
```

## Endpoints

| Method + path | Purpose |
| --- | --- |
| `GET /.well-known/openid-configuration` · `GET /jwks.json` | Discovery + public signing keys. |
| `GET /authorize` | Authorization endpoint (code flow + PKCE); shows login or consent. |
| `POST /login/passkey/{start,finish}` · `POST /login/recovery` | Passkey login + backup-code fallback. |
| `GET /authorize/continue` · `POST /authorize/decision` | Resume after login, record consent. |
| `POST /token` | `authorization_code` and `refresh_token` grants. |
| `GET /userinfo` | Claims for the access token's subject, filtered by granted scope. |
| `GET /logout` | Single logout: destroy session, revoke refresh tokens, clear cookie. |
| `POST /register/passkey/{start,finish}` | Passkey enrolment. |
| `POST /admin/clients` · `GET /admin/clients` | Client registry (admin bearer token). |

Full contract: `/openapi.yaml`, `/openapi.json`.

## Security model

- **PKCE is mandatory** for every authorization-code request (public and confidential clients).
  Redirects are only ever to a client's **pre-registered** URIs.
- **Browser SSO session** in a `HttpOnly`, `SameSite=Lax`, `Secure` (when `--secure-cookies`) cookie;
  only the session id's SHA-256 is stored. The **session lifetime is distinct from the token TTLs**.
- **CSRF token** bound to each server-side pending authorization, required on every state-changing
  browser POST (login finish, recovery, consent).
- **Rotating refresh tokens** with family-based replay defense: a reused token scorches its family.
- **No oracle**: one generic `invalid_grant` for any code/refresh failure, one `invalid_client` for
  client-auth failure, one `invalid_token` at `/userinfo`. Confidential-client secrets are Argon2id
  hashed and compared in constant time. No secret material is logged.
- **Loopback by default.** Exposing on a LAN is an explicit operator decision and **must** be done
  behind a TLS-terminating reverse proxy with `--secure-cookies` (WebAuthn and `Secure` cookies both
  require a secure context).

## Notes / current limitations

- The embedded pk-auth credential store is **in-memory** (passkeys are lost on restart) — the
  documented swap point is pk-auth's persistent `CredentialRepository`/`UserLookup`/`ChallengeStore`
  SPIs (JDBI or DynamoDB).
- **Passkey enrolment is currently unauthenticated self-enrolment** (suitable for bootstrapping/dev);
  a real deployment gates it (invite/admin).
- **Backup codes** are the wired recovery path; pk-auth's **magic-link** and **OTP** services plug
  into the same `RecoveryAuthenticator` seam once their email/SMS senders are configured.
- Without `--directory-url`, an empty in-memory directory is used and no human resolves; point it at
  a running mini-directory for real use.
