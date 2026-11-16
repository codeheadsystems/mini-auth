# Mini IDP

> 🎓 **Learning?** This is stage 3 of the course — read
> [`oauth-and-oidc-flows`](../../docs/concepts/oauth-and-oidc-flows.md) then run lab
> [`03-machine-identity-end-to-end`](../../docs/tutorials/03-machine-identity-end-to-end.md). Full
> syllabus: [docs/TEACHING.md](../../docs/TEACHING.md).

**mini-idp** is a small, standalone, single-machine **identity provider**. It registers clients,
issues short-lived [Ed25519](https://ed25519.cr.yp.to/)-signed JWT access tokens via the OAuth 2.0
**client-credentials** grant, and publishes its public signing keys as a **JWKS** so any verifier
can validate those tokens **offline** — no call back to the IDP. A client may ask for a token for
another allowlisted **audience** (RFC 8707 `resource`), and an operator can have tokens for a given
audience signed with **ES256** instead — that is how mini-idp serves as a trusted issuer for
[config-server](#using-mini-idp-as-a-token-issuer-for-config-server), whose JOSE stack does not
accept EdDSA.

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
- [Per-token audience and signing algorithm](#per-token-audience-and-signing-algorithm)
- [Using mini-idp as a token issuer for config-server](#using-mini-idp-as-a-token-issuer-for-config-server)
- [Running without mini-directory: container image & embedded test issuer](#running-without-mini-directory)
- [Endpoints](#endpoints)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Security notes](#security-notes)
- [Building & testing](#building--testing)

## What it does

- **Registers clients** (admin API) and returns a one-time client secret, hashed at rest with
  Argon2id.
- **Issues tokens** (`POST /oauth/token`, client-credentials grant): a compact Ed25519 JWS with a
  short TTL (default 5 minutes; ES256 instead for audiences an operator maps to it) carrying the client's granted key-group access.
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
GET /.well-known/openid-configuration     -> { issuer, token_endpoint, jwks_uri, grant_types_supported,
GET /.well-known/oauth-authorization-server    token_endpoint_auth_methods_supported,
GET /.well-known/idp-configuration             id_token_signing_alg_values_supported, ... }
GET /.well-known/jwks.json                -> { "keys": [ { kty:"OKP", crv:"Ed25519", x, use:"sig", alg:"EdDSA", kid },
                                                         { kty:"EC", crv:"P-256", x, y, use:"sig", alg:"ES256", kid } ] }
```

The three discovery URLs serve the same document (OpenID Connect Discovery 1.0, RFC 8414, and the
original mini-idp name). `id_token_signing_alg_values_supported` lists `["EdDSA"]`, or
`["EdDSA", "ES256"]` when an audience is mapped to ES256; the EC key appears in the JWKS only then.

The JWKS contains the active signing key plus any **recently retired** keys (overlapping `kid`s),
so a token signed just before a rotation keeps verifying until it expires.

### Token claim schema

Tokens are compact JWS with the header `{"alg":"EdDSA","typ":"JWT","kid":"<kid>"}` (or `"alg":"ES256"`
for an audience mapped to ES256) and this payload:

```jsonc
{
  "iss": "http://127.0.0.1:8455",   // issuer URL
  "sub": "client_Wq710y7DpiM7eW5R", // clientId  -> mini-kms Principal.id
  "aud": "mini-kms",                // intended audience (the default, or the one the client requested)
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
2. Read the JWS header `kid`; select the matching JWK; verify the **EdDSA (Ed25519)** signature —
   or **ES256** (raw 64-byte `R || S`) for an `EC`/`P-256` key — over
   `base64url(header) + "." + base64url(payload)`. Pin the algorithm per key; never trust the
   token's own `alg`.
3. Check `iss`, `aud`, and the `nbf`/`exp` window (allow a little clock skew).
4. (Optional) Poll `GET /admin/revocations` and reject any token whose `jti` is listed. Short TTLs
   are the primary control; revocation kills a specific token early.

mini-token's `TokenVerifier` (`com.codeheadsystems.minitoken.service.TokenVerifier`) is a complete
reference implementation of these steps for EdDSA tokens (it accepts only EdDSA, which is all the
family itself issues for its own audiences).

## Per-token audience and signing algorithm

By default every token carries the configured default audience (`--audience`, `mini-kms`) and is
signed with Ed25519, exactly as before. Two additive knobs change that per token:

- **The client chooses the audience.** Send `resource=<audience>` (RFC 8707) or
  `audience=<audience>` with the token request. With neither, the default audience is used. A named
  audience must be the default or on **that client's allowlist**; anything else is
  `400 invalid_target`, returned only after the client authenticated (a bad secret is still the one
  generic `401 invalid_client`). A token for one audience is not accepted by a verifier expecting
  another, so a service calling both mini-kms and config-server gets one token for each.
- **The operator chooses the algorithm per audience.** `--audience-algorithm config-server=ES256`
  (repeatable; or `MINIIDP_AUDIENCE_ALGORITHMS=config-server=ES256,other=ES256`) signs tokens for
  that audience with **ES256** (ECDSA P-256, SHA-256, raw `R || S` signatures). Unmapped audiences,
  including the default, stay EdDSA. The ES256 keys are a separate key set
  (`signing-keys-es256.json`) with their own `kid`s and the same rotation/retention rules and at-rest
  protection (`0600`, or wrapped under mini-kms with `--kms-*`); both sets are published in one JWKS,
  and `POST /admin/keys/rotate` rotates both.

**Where the allowlist lives.** In mini-directory, as ordinary grants on the service account with the
action `token:audience` and the audience as the resource:

```bash
curl -s -X POST http://127.0.0.1:8466/admin/service-accounts \
  -H "Authorization: Bearer $MINIDIR_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"id":"billing","grants":[{"action":"ENCRYPT","resource":"billing"},
                                {"action":"token:audience","resource":"config-server"}]}'
```

No new directory schema is needed: mini-idp ignores these grants when building the `grants` claim
and reads them only as the audience allowlist. A wildcard (`"resource":"*"`) is **not** honored.
In the [seeded in-memory mode](#running-without-mini-directory) the same allowlist is the
`audiences` array.

## Using mini-idp as a token issuer for config-server

config-server (the `com.codeheadsystems:config-*` project) verifies `Authorization: Bearer <JWT>`
from issuers it is configured to trust: it discovers keys through
`<issuer>/.well-known/openid-configuration`, accepts RS/PS/ES 256/384/512 (no EdDSA), and checks
`iss`, a non-blank `sub`, `aud` and `exp`/`nbf`.

**mini-idp side:**

```bash
--issuer https://idp.example                       # the exact URL config-server is told to trust
--audience-algorithm config-server=ES256           # config-server does not accept EdDSA
# and allowlist the audience on each calling service account (token:audience grant, above)
```

**config-server side** (one trusted issuer):

| Setting | Value |
| --- | --- |
| issuer | mini-idp's issuer URL, exactly as in `iss` (e.g. `https://idp.example`; `http` only on loopback) |
| audience | `config-server` (whatever the client requests and the operator mapped to ES256) |
| subjects to grant | the service account's **client id** (`sub` is the client id, stable for the account's life) |

**Client side:** `POST /oauth/token` with `grant_type=client_credentials`, the client credentials,
and `resource=config-server`. The result is an ES256 token with `aud: "config-server"`.

**Step-by-step guide** (production setup, CI with the container image or `TestIdp`, what a
relying party's tests should cover, troubleshooting), for config-server or any other project:
[`docs/howto/use-mini-idp-as-an-external-issuer.md`](../../docs/howto/use-mini-idp-as-an-external-issuer.md).

`services/mini-idp/testkit`'s `ConfigServerCompatibilityTest` verifies tokens exactly the way
config-server does (Nimbus `DefaultJWTProcessor`, discovery, config-server's algorithm set and claim
checks), including finding a rotated ES256 key by refetching the JWKS.

## Running without mini-directory

For other projects' integration tests (and a zero-dependency local run), mini-idp can seed an
**in-memory service-account directory** from configuration instead of calling mini-directory. Set
exactly one of `MINIIDP_SERVICE_ACCOUNTS` (inline JSON, env only, since it holds secrets) or
`--service-accounts-file` / `MINIIDP_SERVICE_ACCOUNTS_FILE`, and no `--directory-url`:

```json
[
  { "clientId": "billing", "secret": "s3cret", "audiences": ["config-server"] },
  { "clientId": "ops", "secret": "…", "admin": true,
    "grants": [{ "action": "ENCRYPT", "resource": "billing" }] }
]
```

`clientId` and `secret` are required; `audiences`, `admin` and `grants` (mini-directory's flat
`{action, resource}` shape) are optional. The token's `sub` is the `clientId`.

### Container image

`ghcr.io/codeheadsystems/mini-idp:<version>` (published by `.github/workflows/mini-idp-image.yml` on
a `mini-idp-vX.Y.Z` tag; `linux/amd64` + `linux/arm64`). It binds `0.0.0.0` inside the container,
keeps its data in `/data`, runs as a non-root user, and defaults the issuer to
`http://localhost:$MINIIDP_PORT`.

| Env var | Purpose |
| --- | --- |
| `MINIIDP_ADMIN_TOKEN` | Required (key rotation / admin API). |
| `MINIIDP_SERVICE_ACCOUNTS` | The seed above. |
| `MINIIDP_AUDIENCE_ALGORITHMS` | e.g. `config-server=ES256`. |
| `MINIIDP_PORT` | Listen port (default `8455`). |
| `MINIIDP_ISSUER` | Override the issuer (default `http://localhost:$MINIIDP_PORT`). |
| `MINIIDP_TOKEN_TTL_SECONDS`, `MINIIDP_AUDIENCE` | As in [Configuration](#configuration). |

Health: `GET /health` → `200 {"status":"ok"}`.

**The port-mapping catch.** A verifier on the host compares `iss` with the URL it fetched discovery
from. So pick a free port `P`, run the container with `MINIIDP_PORT=P` and a **fixed** mapping
`P:P`, and trust `http://localhost:P`. With Testcontainers:

```java
int port = /* a free host port */;
GenericContainer<?> idp = new GenericContainer<>("ghcr.io/codeheadsystems/mini-idp:<version>")
    .withEnv("MINIIDP_PORT", Integer.toString(port))
    .withEnv("MINIIDP_ADMIN_TOKEN", "test-admin")
    .withEnv("MINIIDP_AUDIENCE_ALGORITHMS", "config-server=ES256")
    .withEnv("MINIIDP_SERVICE_ACCOUNTS",
        "[{\"clientId\":\"billing\",\"secret\":\"s3cret\",\"audiences\":[\"config-server\"]}]")
    .withCreateContainerCmdModifier(cmd -> cmd.getHostConfig().withPortBindings(
        new PortBinding(Ports.Binding.bindIpAndPort("127.0.0.1", port), new ExposedPort(port))))
    .waitingFor(Wait.forHttp("/health").forPort(port));
// issuer = "http://localhost:" + port; token: POST /oauth/token with resource=config-server
```

Build it locally:

```bash
./gradlew :services:mini-idp:server:installDist
docker build -f services/mini-idp/docker/Dockerfile --build-context docker=services/mini-idp/docker \
  -t mini-idp:dev services/mini-idp/server/build/install/server
```

### Embedded test issuer (`testkit`)

`:services:mini-idp:testkit` (`com.codeheadsystems.miniidp.testkit.TestIdp`) runs the real server
in-process on an ephemeral loopback port with an in-memory directory and a temp data dir, and
derives the issuer from the bound port:

```java
try (TestIdp idp = TestIdp.builder().audienceAlgorithm("config-server", "ES256").start()) {
  idp.addServiceAccount("billing", "s3cret", "config-server");
  String token = idp.token("billing", "s3cret", "config-server"); // ES256, aud=config-server
  String issuer = idp.issuer();                                    // http://127.0.0.1:<port>
  idp.rotateKeys();                                                // {EdDSA=…, ES256=…}
}
```

It is **not yet published to Maven Central** (mini-auth has no publishing setup); inside this repo
it backs the compatibility test.

## Endpoints

**Public**

| Method & path | Purpose |
| --- | --- |
| `POST /oauth/token` | Client-credentials grant → `access_token`, `token_type`, `expires_in`, `scope`. Bad creds → `401 invalid_client` (no oracle). Accepts form fields or HTTP Basic. Optional `resource` / `audience` → that audience (allowlisted), else `400 invalid_target`. |
| `GET /.well-known/jwks.json` | Current public signing keys, every algorithm in use (overlapping `kid`s during rotation). |
| `GET /.well-known/openid-configuration` | Discovery (OpenID Connect Discovery 1.0 location). |
| `GET /.well-known/oauth-authorization-server` | The same document (RFC 8414 location). |
| `GET /.well-known/idp-configuration` | The same document (original name). |
| `GET /health` | Liveness. |
| `GET /openapi.yaml`, `GET /openapi.json` | The served spec. |
| `GET /docs` | Swagger UI (vendored, works offline). |

**Admin** (require `Authorization: Bearer <MINIIDP_ADMIN_TOKEN>`)

> Client/service-account management is **not** here — create and manage them in mini-directory
> (`/admin/service-accounts`). mini-idp resolves them at token issuance.

| Method & path | Purpose |
| --- | --- |
| `POST /admin/keys/rotate` | Rotate every signing key set (old `kid`s stay in JWKS until expiry). Returns `activeKid` (EdDSA) and `activeKids` per algorithm. |
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
| `--audience` | `MINIIDP_AUDIENCE` | `mini-kms` | Default `aud` claim (when the client names none). |
| `--audience-algorithm AUD=ALG` (repeatable) | `MINIIDP_AUDIENCE_ALGORITHMS` (`a=ES256,b=ES256`) | all `EdDSA` | Sign tokens for `AUD` with `EdDSA` or `ES256`. |
| `--token-ttl-seconds` | `MINIIDP_TOKEN_TTL_SECONDS` | `300` | Access-token lifetime. |
| `--data-dir` | `MINIIDP_DATA_DIR` | `~/.mini-idp` (or `$XDG_DATA_HOME/mini-idp`) | JSON stores. |
| `--admin-token-file` | `MINIIDP_ADMIN_TOKEN_FILE` | — | File holding the admin token (alt: `MINIIDP_ADMIN_TOKEN` env). |
| `--directory-url` | `MINIIDP_DIRECTORY_URL` | — | mini-directory base URL (service-account source; required unless a seed is given). |
| `--service-accounts-file` | `MINIIDP_SERVICE_ACCOUNTS_FILE` | — | Seed an in-memory directory instead (alt: `MINIIDP_SERVICE_ACCOUNTS` env, inline JSON). |
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

1. **Parse + grant check** — `server/ApiHandlers.token` (`ApiHandlers.java:133`) reads the form and
   rejects anything but `grant_type=client_credentials`. Credentials arrive as `client_secret_post`
   form fields or HTTP Basic.
2. **Authenticate the client** — `directory.authenticate(clientId, secret)` (`ApiHandlers.java:151`)
   resolves the service account over the `ServiceAccountDirectory` SPI: in production
   `HttpServiceAccountDirectory` POSTs to mini-directory's `/admin/service-accounts/authenticate`,
   so the secret is verified *there* (constant-time) and never leaves the directory. Any failure
   collapses to one generic `invalid_client` (`ApiHandlers.java:156`) — no oracle — and the secret
   `char[]` is zeroed in a `finally`.
3. **Pick the audience and algorithm** — `requestedAudience` (`ApiHandlers.java:158`) takes
   `resource`/`audience` (default when absent) and checks the client's allowlist (`invalid_target`
   otherwise); `config.signingAlgorithmFor(audience)` picks EdDSA or ES256 and so the key set.
4. **Mint the token** — `tokenIssuer.issue(subject, authorization, audience, keySet)`
   (`ApiHandlers.java:160` → mini-token `service/TokenIssuer.issue`, `TokenIssuer.java:85`) builds
   the `JwtClaims`, folds the grants into the `grants` claim (`GrantsClaim.from`), stamps
   `iat`/`nbf`/`exp` and a random `jti`, and signs with that key set's active key —
   `Jws.sign(JwsHeader.forKid(alg, kid), claims, privateKey)` (`TokenIssuer.java:103`); the header
   carries the `alg` and the `kid` for rotation.
5. **Audit + respond** — the issuance is recorded by `jti`, audience and algorithm
   (`ApiHandlers.java:162`) and the compact JWS is returned as `access_token` with `token_type`,
   `expires_in`, and a `scope` summary (`ApiHandlers.java:166`).

## Security notes

- **Ed25519/EdDSA** signatures via the JDK; **ES256** (P-256, `SHA256withECDSAinP1363Format` for the
  raw `R || S` JWS form) only for audiences an operator maps to it. Client-secret hashing (Argon2id) lives in mini-directory.
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
  loopback (or setting `--issuer` behind a proxy) is an explicit operator decision. The container
  image binds `0.0.0.0` *inside* the container; publishing its port is that decision.
- **Audience allowlist**: a client can only get tokens for the default audience or audiences
  explicitly allowlisted for it (no wildcard), so it cannot mint a token for a relying party it was
  not granted.

## Building & testing

```bash
./gradlew build                 # compile + all tests (the CI gate)
./gradlew :services:mini-idp:server:installDist   # launcher at services/mini-idp/server/build/install/server/bin/server
```

The test suite covers: token issue + offline JWKS verification; rejection of expired /
not-yet-valid / wrong-audience / tampered tokens; client-secret round-trip; admin-set grants
appearing in issued tokens; key rotation (old `kid` still verifies, new tokens use the new `kid`);
revocation showing up on the denylist; the OpenAPI spec being served, parseable, and matching the
live routes; the no-secrets-in-logs invariant; and (in `testkit`) config-server compatibility:
ES256 tokens for `config-server` verified with Nimbus via OpenID discovery, wrong-audience refusal,
the audience allowlist, ES256 rotation found by JWKS refetch, and default EdDSA tokens unchanged.
