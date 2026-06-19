# Mini IDP

**mini-idp** is a small, standalone, single-machine **identity provider**. It registers clients,
issues short-lived [Ed25519](https://ed25519.cr.yp.to/)-signed JWT access tokens via the OAuth 2.0
**client-credentials** grant, and publishes its public signing keys as a **JWKS** so any verifier
can validate those tokens **offline** — no call back to the IDP.

It is an **educational** project (a sibling to **mini-kms**): heavily commented, real but
un-audited crypto, built to be *read*. It is **step 1** of moving mini-kms off a shared static
token toward per-client identities. mini-idp does not depend on mini-kms; it mirrors its
conventions and issues tokens whose authorization claim maps cleanly onto mini-kms's identity
model, so the KMS can later turn a verified token into a `Principal` with grants.

> **Not for production.** Real but un-audited crypto, single-machine, loopback by default. Private
> signing keys are stored locally (`0600`) — or, with `--kms-tcp`/`--kms-key-group`, envelope-wrapped
> under mini-kms (the recursive integration) so no plaintext key touches disk.

## Table of contents

- [What it does](#what-it-does)
- [Quick start](#quick-start)
- [The integration contract (read this if you're the verifier)](#the-integration-contract)
  - [Discovery & JWKS URLs](#discovery--jwks-urls)
  - [Token claim schema](#token-claim-schema)
  - [How to verify a token offline](#how-to-verify-a-token-offline)
- [Endpoints](#endpoints)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Security notes](#security-notes)
- [Building & testing](#building--testing)

## What it does

- **Registers clients** (admin API) and returns a one-time client secret, hashed at rest with
  Argon2id.
- **Issues tokens** (`POST /oauth/token`, client-credentials grant): a compact Ed25519 JWS with a
  short TTL (default 5 minutes) carrying the client's granted key-group access.
- **Publishes signing keys** (`GET /.well-known/jwks.json`) with overlapping `kid`s across
  rotations, so a verifier validates signatures offline.
- **Supports key rotation and revocation**, and keeps an audit log.
- **Documents everything** as an OpenAPI 3.1 spec served at a stable URL and rendered by a bundled
  Swagger UI.

## Quick start

Requires JDK 21+.

Service accounts (the OAuth clients) live in **mini-directory**, so run one and point mini-idp at it.

```bash
./gradlew :services:mini-directory:installDist :services:mini-idp:server:installDist

export MINIDIR_ADMIN_TOKEN="$(openssl rand -hex 32)"
services/mini-directory/build/install/mini-directory/bin/mini-directory --port 8466 --data-dir ~/.mini-directory &

# 1) Create the service account in mini-directory (grants are flat action/resource pairs:
#    a key-group operation is {action: <KeyOperation>, resource: <keyGroup>}).
curl -s -X POST localhost:8466/admin/service-accounts \
  -H "Authorization: Bearer $MINIDIR_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"displayName":"billing-svc","grants":[
       {"action":"ENCRYPT","resource":"billing"},{"action":"DECRYPT","resource":"billing"}]}'
# -> { "id": "svc_…", "secret": "…", ... }   (the secret is shown ONCE)

export MINIIDP_ADMIN_TOKEN="$(openssl rand -hex 32)"        # mini-idp's own admin credential
export MINIIDP_DIRECTORY_TOKEN="$MINIDIR_ADMIN_TOKEN"       # so mini-idp may call the directory
services/mini-idp/server/build/install/server/bin/server --port 8455 --data-dir ~/.mini-idp \
  --directory-url http://127.0.0.1:8466 &

# 2) Exchange the client credentials for a token (mini-idp resolves the account from mini-directory).
curl -s -X POST localhost:8455/oauth/token \
  -d 'grant_type=client_credentials&client_id=svc_…&client_secret=…'
# -> { "access_token": "eyJ…", "token_type": "Bearer", "expires_in": 300, "scope": "billing:ENCRYPT billing:DECRYPT" }

# 3) Browse the live API docs.
open http://localhost:8455/docs
```

> Migrating an existing `clients.json`? See mini-directory's README (`ClientRegistryMigration`).

## The integration contract

The authoritative, machine-readable contract is the **OpenAPI 3.1** spec. A verifier (the future
mini-kms) can integrate from the spec alone:

| What | URL |
| --- | --- |
| OpenAPI spec (YAML) | `GET /openapi.yaml` |
| OpenAPI spec (JSON) | `GET /openapi.json` |
| Swagger UI | `GET /docs` |

### Discovery & JWKS URLs

```
GET /.well-known/idp-configuration   -> { issuer, token_endpoint, jwks_uri, grant_types_supported, ... }
GET /.well-known/jwks.json           -> { "keys": [ { kty:"OKP", crv:"Ed25519", x, use:"sig", alg:"EdDSA", kid } ] }
```

The JWKS contains the active signing key plus any **recently retired** keys (overlapping `kid`s),
so a token signed just before a rotation keeps verifying until it expires.

### Token claim schema

Tokens are compact JWS with the header `{"alg":"EdDSA","typ":"JWT","kid":"<kid>"}` and this payload:

```jsonc
{
  "iss": "http://127.0.0.1:8455",   // issuer URL
  "sub": "client_Wq710y7DpiM7eW5R", // clientId  -> mini-kms Principal.id
  "aud": "mini-kms",                // intended audience
  "iat": 1781454541,                // issued-at (epoch seconds)
  "nbf": 1781454541,                // not-before
  "exp": 1781454841,                // expiry  (default iat + 300s)
  "jti": "cWmkyGso5MJdbXpVHu-MMQ",  // unique id (used for revocation)
  "grants": {                       // the authorization payload
    "control": false,               //   -> mini-kms Principal.admin
    "groups": [                     //   -> per-key-group PolicyEngine decision (mini-policy)
      { "keyGroup": "billing", "operations": ["ENCRYPT", "DECRYPT"] }
    ]
  }
  // "cnf": { ... }                 // OPTIONAL, reserved for future channel binding (RFC 7800); not used yet
}
```

`operations` values are exactly mini-kms's `KeyOperation` names: `GENERATE_DATA_KEY`, `ENCRYPT`,
`DECRYPT`, `RE_ENCRYPT`. A verifier maps a token straight onto its authorization model:

```
sub             -> Principal.id
grants.control  -> Principal.admin
grants.groups[] -> per-key-group PolicyEngine decisions (mini-policy)
```

### How to verify a token offline

1. Fetch and cache `GET /.well-known/jwks.json`.
2. Read the JWS header `kid`; select the matching JWK; verify the **EdDSA (Ed25519)** signature
   over `base64url(header) + "." + base64url(payload)`.
3. Check `iss`, `aud`, and the `nbf`/`exp` window (allow a little clock skew).
4. (Optional) Poll `GET /admin/revocations` and reject any token whose `jti` is listed. Short TTLs
   are the primary control; revocation kills a specific token early.

mini-token's `TokenVerifier` (`com.codeheadsystems.minitoken.service.TokenVerifier`) is a complete
reference implementation of these steps.

## Endpoints

**Public**

| Method & path | Purpose |
| --- | --- |
| `POST /oauth/token` | Client-credentials grant → `access_token`, `token_type`, `expires_in`, `scope`. Bad creds → `401 invalid_client` (no oracle). Accepts form fields or HTTP Basic. |
| `GET /.well-known/jwks.json` | Current public signing keys (overlapping `kid`s during rotation). |
| `GET /.well-known/idp-configuration` | Discovery: issuer, `jwks_uri`, `token_endpoint`. |
| `GET /health` | Liveness. |
| `GET /openapi.yaml`, `GET /openapi.json` | The served spec. |
| `GET /docs` | Swagger UI (vendored, works offline). |

**Admin** (require `Authorization: Bearer <MINIIDP_ADMIN_TOKEN>`)

> Client/service-account management is **not** here — create and manage them in mini-directory
> (`/admin/service-accounts`). mini-idp resolves them at token issuance.

| Method & path | Purpose |
| --- | --- |
| `POST /admin/keys/rotate` | Rotate the signing key (old `kid` stays in JWKS until expiry). |
| `POST /admin/revocations` | Revoke a `jti` (pollable denylist). |
| `GET /admin/revocations` | The current denylist (for a verifier to poll). |
| `GET /admin/audit` | Issuance / grant / revocation / rotation / lifecycle audit entries. |

## Configuration

Flags override environment variables override defaults (mirrors mini-kms's `ServerConfig`).

| Flag | Env var | Default | Meaning |
| --- | --- | --- | --- |
| `--host` | `MINIIDP_HOST` | `127.0.0.1` | Loopback bind host. |
| `--port` | `MINIIDP_PORT` | `8455` | TCP port (`0` = ephemeral). |
| `--issuer` | `MINIIDP_ISSUER` | `http://<host>:<port>` | `iss` claim + discovery base. |
| `--audience` | `MINIIDP_AUDIENCE` | `mini-kms` | `aud` claim. |
| `--token-ttl-seconds` | `MINIIDP_TOKEN_TTL_SECONDS` | `300` | Access-token lifetime. |
| `--data-dir` | `MINIIDP_DATA_DIR` | `~/.mini-idp` (or `$XDG_DATA_HOME/mini-idp`) | JSON stores. |
| `--admin-token-file` | `MINIIDP_ADMIN_TOKEN_FILE` | — | File holding the admin token (alt: `MINIIDP_ADMIN_TOKEN` env). |
| `--directory-url` | `MINIIDP_DIRECTORY_URL` | — | mini-directory base URL (service-account source; required). |
| `--directory-token-file` | `MINIIDP_DIRECTORY_TOKEN_FILE` | — | mini-directory admin token file (alt: `MINIIDP_DIRECTORY_TOKEN` env). |
| `--kms-tcp`, `--kms-key-group`, `--kms-api-token-file` | `MINIIDP_KMS_*` | — | Optional: wrap signing keys under mini-kms. |

The admin token is resolved from `MINIIDP_ADMIN_TOKEN` or `--admin-token-file`, **never from a CLI
argument**, and is never logged.

## Architecture

The token plane — Ed25519 keys, the hand-rolled JWS/JWT, JWKS, the `grants` claim contract and the
auth model it maps onto, and the signing-key / revocation / audit services — lives in the shared
**[`mini-token`](../../libs/mini-token)** library (`com.codeheadsystems.minitoken`). mini-idp depends
on it and is two Gradle modules under `com.codeheadsystems.miniidp`:

- **`core`** — now just `store/JsonStore` (atomic + 0600), which **implements mini-token's
  `DocumentStore` SPI** and backs the signing-key / revocation / audit documents. (The client
  registry and Argon2 secret hashing moved to mini-directory.)
- **`server`** — `ServerMain`/`IdpServer` (composition root — wires mini-token's services over the
  `JsonStore`s), `ServerConfig`, a tiny `http/` router over the JDK `HttpServer`, `ApiHandlers`, the
  `directory/` package (`ServiceAccountDirectory` SPI + the HTTP client to mini-directory + grant
  reassembly), `AdminAuthenticator`, and the OpenAPI/Swagger serving. Each request runs on a virtual
  thread.

Service accounts (the OAuth clients) live in **mini-directory**; mini-idp resolves a client's
credentials and grants from it at token issuance via the `ServiceAccountDirectory` SPI. The token
plane — `crypto/Ed25519Keys`, `token/{Base64Url,JwsHeader,Jws,JwtClaims,GrantsClaim}`,
`jwks/{Jwk,JwkSet}`, `auth/{KeyOperation,Grant,Authorization}`, and the `SigningKeyService` /
`TokenIssuer` / `TokenVerifier` / `RevocationService` / `AuditService` services — lives under
`com.codeheadsystems.minitoken.*` in **[`mini-token`](../../libs/mini-token)**.

```
keys:             Ed25519 keypair --kid--> signing-keys.json   (private key 0600, or mini-kms-wrapped)
issue:            client creds --(verify @ mini-directory)--> subject + grants --Ed25519 JWS--> access_token
verify (offline): access_token --kid--> JWK --EdDSA verify--> claims --map--> Principal + grants
```

### How issuance works (step by step)

`POST /oauth/token` (the client-credentials grant), traced through the code:

1. **Parse + grant check** — `server/ApiHandlers.token` (`ApiHandlers.java:92`) reads the form and
   rejects anything but `grant_type=client_credentials`. Credentials arrive as `client_secret_post`
   form fields or HTTP Basic.
2. **Authenticate the client** — `directory.authenticate(clientId, secret)` (`ApiHandlers.java:110`)
   resolves the service account over the `ServiceAccountDirectory` SPI: in production
   `HttpServiceAccountDirectory` POSTs to mini-directory's `/admin/service-accounts/authenticate`,
   so the secret is verified *there* (constant-time) and never leaves the directory. Any failure
   collapses to one generic `invalid_client` (`ApiHandlers.java:115`) — no oracle — and the secret
   `char[]` is zeroed in a `finally`.
3. **Mint the token** — `tokenIssuer.issue(subject, authorization)` (`ApiHandlers.java:117` →
   mini-token `service/TokenIssuer.issue`, `TokenIssuer.java:66`) builds the `JwtClaims`, folds the
   grants into the `grants` claim (`GrantsClaim.from`), stamps `iat`/`nbf`/`exp` and a random `jti`,
   and signs with the active key — `Jws.sign(JwsHeader.forKid(kid), claims, privateKey)`
   (`TokenIssuer.java:83`); the header carries the `kid` for rotation.
4. **Audit + respond** — the issuance is recorded by `jti` (`ApiHandlers.java:118`) and the compact
   JWS is returned as `access_token` with `token_type`, `expires_in`, and a `scope` summary
   (`ApiHandlers.java:120`).

## Security notes

- **Ed25519/EdDSA** signatures via the JDK. Client-secret hashing (Argon2id) lives in mini-directory.
- **No credential oracle**: any token-endpoint auth failure returns a single generic
  `invalid_client`; secret verification is constant-time, and an unknown client still incurs a
  hash comparison so timing doesn't reveal existence.
- **No secret leakage**: client secrets, private keys, and raw tokens are never logged (a test
  enforces this); access logs carry only method/path/status. The client secret is returned exactly
  once, at registration.
- **At-rest**: every store file is written atomically and `0600`. Private signing keys are stored
  locally by default, or — with `--kms-tcp`/`--kms-key-group` — envelope-wrapped under mini-kms so no
  plaintext key touches disk (the recursive integration).
- **Loopback by default**: like mini-kms, this is a local-trust service; exposing it beyond
  loopback (or setting `--issuer` behind a proxy) is an explicit operator decision.

## Building & testing

```bash
./gradlew build                 # compile + all tests (the CI gate)
./gradlew :services:mini-idp:server:installDist   # launcher at services/mini-idp/server/build/install/server/bin/server
```

The test suite covers: token issue + offline JWKS verification; rejection of expired /
not-yet-valid / wrong-audience / tampered tokens; client-secret round-trip; admin-set grants
appearing in issued tokens; key rotation (old `kid` still verifies, new tokens use the new `kid`);
revocation showing up on the denylist; the OpenAPI spec being served, parseable, and matching the
live routes; and the no-secrets-in-logs invariant.
