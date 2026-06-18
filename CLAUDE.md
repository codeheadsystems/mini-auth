# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this
repository. It is the **single** guide for the whole `mini-` family: the umbrella conventions
first, then a folded-in section per shipping service (mini-kms, mini-idp, mini-directory, mini-oidc,
mini-gateway, mini-ca). There are no per-module `CLAUDE.md` files — this is it.

> **Read first.** `docs/DIRECTION.md` is the canonical map of the family — the vision, the
> component catalog, the architecture, the runtime relationships, the roadmap, and the
> `mini-common` extraction candidates. Read it before touching code, then read the relevant
> service section below and the module's own `README.md`.

## What this is

mini-auth is the **monorepo** for a family of small, single-responsibility auth/identity services
and libraries, built in the spirit of **mini-kms** and **mini-idp**: **educational, but
homelab-functional.** The code is meant to be *read* — heavily commented, JDK-first, real-but-
un-audited crypto via vetted libraries. mini-auth itself is two things:

1. **One aggregator build** — `./gradlew build` from the root compiles and tests the whole family
   (vendored services included), under one wrapper, one version catalog, and one set of
   convention plugins.
2. **The shared direction doc** (`docs/DIRECTION.md`) — the map the individual modules can't carry.

mini-kms and mini-idp were **two formerly-independent Gradle builds**, pulled in and unified here:
one root wrapper, one `settings.gradle.kts`, one `gradle/libs.versions.toml`, one `build-logic`
convention-plugin set, and one CI workflow. mini-auth does **not re-implement** what the shipping
services already do — it composes them and adds the connective tissue (`mini-token`,
`mini-policy`) and the new front doors (`mini-oidc`, `mini-gateway`, `mini-directory`).

## The "mini-" ethos (non-negotiable)

- **Small, single-responsibility, readable.** A "mini" is either a *library* (focused machinery)
  or a *service* (a thin deployable front door that wires libraries together and adds a transport).
  Clarity and correct security reasoning matter more than features; comments carry teaching weight.
- **Real but un-audited crypto via vetted libraries.** Never hand-roll crypto you can get from
  **pk-auth** or the existing **token plane** (mini-idp / the future mini-token). Where the family
  *does* hand-roll a format (mini-idp's JWS, mini-kms's envelopes), it is deliberate, isolated, and
  heavily commented — match that bar, don't add new hand-rolled crypto casually.
- **`core` stays I/O-free.** Crypto and domain logic never import a transport (no sockets, HTTP,
  or CLI parsing in `core`). The composition root lives in the `server`/`application` module.
- **Scaffolds say so.** A "scaffolded" module compiles and passes a trivial test, with the real
  protocol/crypto left as clearly-marked TODOs at the seams. Do **not** turn a scaffold into a
  half-built service that *looks* finished — preserve the honest seams.

## Security conventions (mirror these everywhere)

- **No secrets in logs.** Tokens, passphrases, private keys, and request/response bodies are
  never logged. Access logs record method/path/status only.
- **No oracles.** Auth/crypto failures collapse to one generic error (mini-idp's single
  `invalid_client`; mini-kms's single `DecryptionFailed`) — never distinguish unknown-principal
  from wrong-secret, or leak *why* a decrypt failed.
- **Constant-time secret comparison** (`MessageDigest.isEqual`); handle passphrases as `char[]`
  and zero them.
- **Secrets via env/file, never argv.** Follow the existing `resolveAdminToken` / `resolveToken`
  / `readPassphrase` patterns.
- **At-rest stores are atomic + `0600`** (temp-file → `ATOMIC_MOVE` → `0600`; mini-idp's
  `JsonStore`, mini-kms's `Keystore`). Integrity-protect metadata where the siblings do.
- **Loopback bind by default.** Exposing anything beyond loopback is an explicit operator decision.
- Use `System.Logger`, not a third-party logging dependency.

## Build & test

JDK 21+ on `PATH` (the Gradle toolchain is pinned to 21; foojay can auto-download it). There is
**one root wrapper** — run every Gradle command from the repo root.

```bash
./gradlew build        # compile + run ALL tests across the whole family — this IS the CI gate
./gradlew test         # tests only, all modules
./gradlew :services:mini-idp:core:test                              # one module
./gradlew :services:mini-kms:core:test --tests "*LocalKeyringTest"  # one class
./gradlew :services:mini-oidc:installDist                           # runnable launcher
```

There is **no separate linter/formatter**; `./gradlew build` is the full gate. Tests are JUnit 5.
Gradle's configuration cache is on (`org.gradle.configuration-cache=true`), so build-script changes
(including edits to `build-logic`) may need `--no-configuration-cache` while iterating.

**After any change, `./gradlew build` from the repo root must be green and all pre-existing tests
must still pass.**

## Layout & build structure

Modules are grouped by role under `services/` and `libs/`; the Gradle project path follows the
directory.

```
mini-auth/
├── settings.gradle.kts          # one build: includes every module + pluginManagement.includeBuild(build-logic)
├── build.gradle.kts             # just the `base` plugin — conventions live in build-logic
├── gradle/libs.versions.toml    # one catalog for the whole family (Jackson 3.x)
├── build-logic/                 # included build: the shared convention plugins
│   └── src/main/kotlin/
│       ├── miniauth.java-conventions.gradle.kts         # toolchain 21, JUnit 5, -parameters, test deps
│       ├── miniauth.library-conventions.gradle.kts      # java-conventions + java-library
│       └── miniauth.application-conventions.gradle.kts  # java-conventions + application
├── docs/DIRECTION.md
├── services/                    # deployable front doors
│   ├── mini-kms/   {core, server, client}   (shipping)
│   ├── mini-idp/   {core, server}           (shipping)
│   ├── mini-oidc/                           (shipping; human SSO / OpenID Provider, embeds pk-auth)
│   ├── mini-gateway/                        (shipping; forward-auth for a reverse proxy)
│   ├── mini-directory/                      (shipping; identity source of truth, standalone)
│   ├── mini-ca/                             (shipping; internal CA, CA key wrapped under mini-kms)
│   └── mini-console/                        (roadmap placeholder)
└── libs/                        # shared libraries (no transport)
    ├── mini-token/                          (shipping; token plane + shared SSO session store)
    └── mini-policy/                         (shipping; shared decision engine)
```

| Module | Project path | Type | Status |
| --- | --- | --- | --- |
| mini-kms | `:services:mini-kms:core/server/client` | service | **shipping** (§ below) |
| mini-idp | `:services:mini-idp:core/server` | service | **shipping** (§ below) |
| mini-oidc | `:services:mini-oidc` | service (application) | **shipping** (§ below) — embeds pk-auth |
| mini-gateway | `:services:mini-gateway` | service (application) | **shipping** (§ below) |
| mini-directory | `:services:mini-directory` | service (application) | **shipping** (§ below) |
| mini-ca | `:services:mini-ca` | service (application) | **shipping** (§ below) |
| mini-console | `:services:mini-console` | service (future) | roadmap placeholder (no logic) |
| mini-token | `:libs:mini-token` | library | **shipping** (token plane extracted from mini-idp) |
| mini-policy | `:libs:mini-policy` | library | **shipping** (shared decision engine; consumed by directory/oidc/gateway/kms) |

- **Convention plugins, not `subprojects {}`.** The shared Java conventions (JDK 21 toolchain,
  Maven Central, JUnit 5 + the common test stack, the `-parameters` flag) live in the `build-logic`
  included build and are applied per-module by id: `id("miniauth.library-conventions")` for
  libraries and the I/O-free `core`s, `id("miniauth.application-conventions")` for runnable
  services. The empty grouping projects (`:services`, `:libs`) stay inert.
- **Editing `build-logic`:** keep its plugin descriptors valid by building the whole repo. One
  sharp edge: **do not put backticks in a comment that precedes a `plugins {}` block** in any
  `*.gradle.kts` — Gradle's lightweight prescan of that block can be derailed by backtick-quoted
  text in the comment, and the plugin silently fails to apply.
- **Base package** is `com.codeheadsystems.<mini>` (e.g. `com.codeheadsystems.minitoken`). The
  package names are independent of the directory grouping — they were **not** renamed when modules
  moved under `services/` / `libs/`.
- **Use the shared version catalog** (`gradle/libs.versions.toml`) — never pin a version inline.
- **`-parameters` is required family-wide** (set in `miniauth.java-conventions`): Jackson binds
  records (protocol/keystore/store/claim DTOs) by constructor parameter name.
- **Jackson 3.x (`tools.jackson.*`)** everywhere. Mappers are immutable — build with
  `JsonMapper.builder()…build()` (no instance `enable`/`configure`); read/write throw the
  **unchecked** `tools.jackson.core.JacksonException`. Only `jackson-annotations` stays on
  `com.fasterxml.jackson.annotation`, so `@JsonProperty`/`@JsonInclude`/`@JsonCreator` imports are
  unchanged. YAML uses `tools.jackson.dataformat.yaml.YAMLMapper`.
- **pk-auth is external, not vendored** — `com.codeheadsystems:pk-auth-core` from Maven Central
  (mini-oidc's passkey credential layer).

## Working in this repo

- **Read `docs/DIRECTION.md` and the relevant existing module(s) before writing code.** The
  runtime relationships (both issuers go through mini-token; everything decides through mini-policy;
  mini-token's signing keys are eventually wrapped by mini-kms; mini-directory is the identity
  source of truth) shape where new code belongs.
- **Refactors are behavior-preserving** — structure only, no functional change; the test suite
  must still pass unchanged.
- **The token-claim contract aligns across the family.** mini-idp's `grants` claim maps onto
  mini-kms's authorization model (`sub → Principal.id`, `grants.control → Principal.admin`,
  `grants.groups[] → KeyAuthorizationPolicy`); `auth/KeyOperation` string values are the contract —
  don't rename them. Preserve this mapping in mini-token / mini-policy work.
- **Don't duplicate foundation code.** Argon2 hashing, the atomic-`0600` JSON store, base64url,
  constant-time compare, and the `ServerConfig` env/file token pattern exist in *both* shipping
  services today. They are catalogued as **`mini-common` extraction candidates** in
  `docs/DIRECTION.md` — when adding similar machinery, prefer extending one of those (and note the
  duplication) over writing a third copy. The extraction itself is a planned, separate step.

---

# Service: mini-kms (`services/mini-kms`)

mini-kms is an **educational** single-machine Key Management Service in Java: envelope encryption
with rotatable keys served to local processes over sockets. Heavily commented on purpose — the
code is meant to be *read* to learn how a KMS works. Real, sound crypto (Argon2id, AES-256-GCM/AEAD),
explicitly not production-audited.

**Run it locally.** Server reads the passphrase with no echo (`Console.readPassword`), or
`MINIKMS_PASSPHRASE` when there's no TTY. Both tokens come from env vars or files, **never CLI args**.

```bash
export MINIKMS_API_TOKEN="$(openssl rand -hex 32)"      # data plane
export MINIKMS_ADMIN_TOKEN="$(openssl rand -hex 32)"    # control plane
./gradlew :services:mini-kms:server:installDist :services:mini-kms:client:installDist
services/mini-kms/server/build/install/server/bin/server --tcp-port 9123 --keystore ~/.mini-kms/keystore.json
services/mini-kms/client/build/install/client/bin/client   --tcp 127.0.0.1:9123 health      # data-plane CLI
services/mini-kms/client/build/install/client/bin/kms-admin --tcp 127.0.0.1:9123 list-keys  # control-plane CLI
```

**Architecture.** Three modules under base package `com.codeheadsystems.minikms` (paths
`:services:mini-kms:core/server/client`):

- **`core`** — all crypto + key management, **no socket/transport/CLI code**. Owns the
  wire-protocol DTOs (shared by server + client), the envelope formats, the keyring, and the
  request handler. This I/O-free separation is load-bearing.
- **`server`** — the socket daemon (`ServerMain`); depends on `core`.
- **`client`** — `KmsClient` library plus two CLIs (`ClientMain` = data plane, `KeyringAdminMain` =
  control plane); depends on `core`. The `client` build registers a second launcher (`kms-admin`)
  in the same distribution — preserve that when touching its build file.
- **`client/KmsSigningKeyStore`** — the **recursive integration**: a `DocumentStore<SigningKeys>`
  (mini-token's key-at-rest SPI) that envelope-wraps each Ed25519 signing key under a mini-kms key
  group via `KmsClient.encrypt`/`decrypt` (and `reEncrypt` for KEK rotation), so the auth services'
  signing keys never sit plaintext on disk. It lives here (not in mini-token) to keep the dependency
  acyclic — `client` gained a `mini-token` dependency; mini-token knows nothing of mini-kms. mini-idp
  and mini-oidc opt in via `--kms-tcp`/`--kms-key-group`. Note the **leaf-name jar fix**: both
  `mini-kms:core` and `mini-idp:core` set a unique `base.archivesName`, because a service bundling
  both would otherwise collide on `core.jar`.

- **Two planes, two tokens.** Every `RequestType` is tagged `DATA` or `CONTROL` (`RequestPlane`).
  `KmsRequestHandler` (in `core`) routes by plane and validates the matching token — the **API
  token** for data ops, a **separate admin token** for control ops. Data-plane ops also pass
  through `KeyAuthorizationPolicy` per key group; the shipped `AllowAllPolicy` is the documented
  seam for per-client authz later (the thing `mini-policy` generalizes).
- **The two seams.** `KmsRequestHandler` depends only on `MasterKeyProvider` (data:
  `wrap/unwrap/encrypt/decrypt/keyIdOf`) and `KeyringManager` (control:
  `create/rotate/list/disable/enable/destroy`), both implemented by `LocalKeyring`. Each ciphertext
  carries its own `kek_id` inside the opaque blob, so a remote/HSM provider can drop in later.
  **Preserve this boundary** — don't make the handler reach past these interfaces.
- **Key hierarchy.** `passphrase --Argon2id+salt--> root key --wraps--> KEK versions --wrap--> DEKs
  --AES-GCM--> data`. Root key and KEKs exist only as `byte[]` and are zeroed on shutdown
  (`LocalKeyring.close()`). `DestroyVersion` is intentionally irreversible (crypto-shredding).
- **Crypto & formats.** `crypto/AesGcm` is the **only** place raw symmetric crypto happens
  (nonces always fresh-random, never caller-supplied). Three nested binary formats: `EnvelopeFormat`,
  `KekEnvelope` (client-facing blob), client-only `FileEnvelope` (`MKE1`). The keystore
  (`keystore.json`, `0600`) holds an HMAC over all metadata (`KeystoreIntegrity`); the MAC is
  **required** on load (tampering is rejected; pre-MAC keystores fail to load).
- **Transport.** Loopback TCP + a Unix domain socket (`0600` in a `0700` dir); each connection on a
  virtual thread. Newline-delimited JSON, bounded per frame; a `Semaphore` connection cap + an
  idle-timeout watchdog. `ConnectionHandler` is transport-agnostic.
- **Conventions.** `core` stays I/O-free (no sockets/files beyond `Keystore`/CLI). Any keyring/AEAD
  failure flattens to one `DecryptionFailed`. Secrets via `resolveToken`/`readPassphrase`
  (passphrases as `char[]`, zeroed).
- **Docs.** `services/mini-kms/README.md` (architecture, formats, glossary) and
  `services/mini-kms/docs/security/` (review findings: connection exhaustion, keystore integrity;
  one open item: loopback-TCP local exposure).

---

# Service: mini-idp (`services/mini-idp`)

mini-idp is an **educational** identity provider in Java. It issues short-lived Ed25519-signed JWT
access tokens via the OAuth 2.0 **client-credentials** grant and publishes its public signing keys
(JWKS) so a verifier can validate tokens **offline**. It is a pure token issuer: **service accounts
(the OAuth clients) live in mini-directory**, and mini-idp resolves a client's credentials and grants
from there at token issuance (over the `ServiceAccountDirectory` SPI). Real crypto (Ed25519/EdDSA),
not production-audited. Optionally wraps its signing keys under mini-kms (the recursive integration);
otherwise no code-level dependency on mini-kms.

**Run it locally.** The bootstrap admin token comes from an env var or a file, **never a CLI arg,
and is never logged**.

```bash
export MINIIDP_ADMIN_TOKEN="$(openssl rand -hex 32)"
./gradlew :services:mini-idp:server:installDist
services/mini-idp/server/build/install/server/bin/server --port 8455 --data-dir ~/.mini-idp
# Register a client (admin), then exchange credentials for a token; browse the API at /docs.
```

**Architecture.** Two modules under base package `com.codeheadsystems.miniidp` (paths
`:services:mini-idp:core/server`):

- **`core`** — now just the atomic-`0600` `store/JsonStore` (which implements mini-token's
  `DocumentStore` SPI), backing the signing-key / revocation / audit documents. The token plane was
  extracted to `:libs:mini-token`; the client registry + Argon2 hashing moved to mini-directory. Both
  are consumed as dependencies.
- **`server`** — the HTTP daemon (`ServerMain`, JDK `com.sun.net.httpserver.HttpServer` on
  loopback), router, handlers, config, the `directory/` package (the `ServiceAccountDirectory` SPI +
  `HttpServiceAccountDirectory`/`InMemoryServiceAccountDirectory` + grant reassembly), and the
  OpenAPI spec + vendored Swagger UI. Depends on `core`, mini-token, and mini-kms:client.

- **Service accounts come from mini-directory.** At `/oauth/token`, mini-idp resolves the client via
  the `ServiceAccountDirectory` SPI — production `HttpServiceAccountDirectory` POSTs to
  mini-directory's `/admin/service-accounts/authenticate` (verification happens there; the secret
  hash never leaves the directory), tests use `InMemoryServiceAccountDirectory`. The resolved grants
  are reassembled into the per-key-group `grants` claim, so the token is identical to the old
  registry's output. `--directory-url` + a directory admin token are required.
- **The token plane lives in `mini-token`.** The Ed25519 keys, the hand-rolled JWS/JWT, the JWKS
  model, the `grants` claim, the auth model the claim maps onto, and the signing-key /
  revocation / audit services are all in `:libs:mini-token` (`com.codeheadsystems.minitoken.*`).
  mini-idp wires them in `server/IdpServer`; the issuer takes a `(subject, Authorization)`.
- **The token contract.** `server/src/main/resources/openapi.yaml` (served at `/openapi.yaml`,
  `/openapi.json`, `/docs`) is authoritative. The `grants` claim (mini-token's
  `token/GrantsClaim` over `auth/Authorization`) maps to mini-kms: `sub → Principal.id`,
  `grants.control → Principal.admin`, `grants.groups[] → KeyAuthorizationPolicy`. `auth/KeyOperation`
  is a **deliberate mirror** of mini-kms's enum — the string values are the contract, do not rename
  them. A `cnf` claim is reserved (RFC 7800) but not enforced yet.
- **Crypto & formats (hand-rolled bits, now in mini-token).** Ed25519 via the JDK only
  (`crypto/Ed25519Keys`). The JWS is hand-rolled in `token/Jws` (not a JOSE lib):
  `base64url(header).base64url(payload).base64url(sig)`; `service/TokenVerifier` is the reference
  offline verifier (signature first, then `iss`/`aud`/time/revocation). Client secrets — which stay
  in mini-idp — are hashed with Argon2id (`secret/Argon2SecretHasher`), verified in constant time.
- **Persistence & rotation.** All state is JSON via mini-idp's `store/JsonStore` (atomic temp-file +
  `ATOMIC_MOVE` + `0600`), passed to the token services through the `DocumentStore` SPI. Private
  signing keys in `signing-keys.json` (`0600`) by default — or, with `--kms-tcp`/`--kms-key-group`,
  **envelope-wrapped under mini-kms** so no plaintext key touches disk (the recursive integration;
  see the mini-kms section and `docs/DIRECTION.md`). Rotation (mini-token's `service/SigningKeyService`)
  keeps retired keys in the JWKS (`retiredKeyRetention`, = 2× token TTL) so in-flight tokens verify.
- **Conventions.** `core` stays HTTP-free (composition root is `server/IdpServer`). The token
  endpoint returns one generic `invalid_client` for any auth failure. Admin token via
  `resolveAdminToken`. **The OpenAPI spec is the contract** — `OpenApiContractTest` fails if a
  documented path/method doesn't resolve on the live server, so keep `openapi.yaml` and the routes
  in `ApiHandlers` in sync.
- **Docs.** `services/mini-idp/README.md` — endpoint list, token claim schema, JWKS/discovery URLs.

---

# Service: mini-directory (`services/mini-directory`)

mini-directory is the **single identity source of truth** for the family: it owns **humans**,
**service accounts**, **groups**, and **roles**, and the grant mappings between them. Its defining
job is **resolution** — turning any stored account into a **mini-policy `Principal` plus a
fully-expanded, de-duplicated set of `(action, resource)` grants** (roles expand to grants; group
memberships are inherited), which is exactly what a `mini-policy` decision function consumes. It is
**shipping but standalone**: the issuers do **not** read from it yet (that is Phase 3/4 work; see the
open client-registry question in `docs/DIRECTION.md`).

**Run it locally.** The bootstrap admin token comes from an env var or a file, **never a CLI arg,
and is never logged**. Loopback by default.

```bash
export MINIDIR_ADMIN_TOKEN="$(openssl rand -hex 32)"
./gradlew :services:mini-directory:installDist
services/mini-directory/build/install/mini-directory/bin/mini-directory --port 8466 --data-dir ~/.mini-directory
# Create a role/group/human (admin), then GET /admin/principals/{id}/resolution. Browse /docs.
```

**Architecture.** One application module under base package `com.codeheadsystems.minidirectory`:

- **`model`** — the records: `Account` (a `HUMAN` or `SERVICE_ACCOUNT`, the resolvable identity),
  `Group`, `Role`, the flat `GrantSpec` (`{action, resource}`, the JSON-friendly mirror of a
  mini-policy `Grant`), and `ResolvedPrincipal` (a mini-policy `Principal` + expanded `Grant`s).
- **`service/DirectoryService`** — the I/O-free heart: CRUD for accounts/groups/roles, assignment,
  `resolve(id)` (the role/group → grant expansion), `authenticate(id, secret)` (no-oracle,
  constant-time, dummy-hash for unknown — the family's credential-check pattern), and
  `importServiceAccount(...)` (the migration entry point). All methods `synchronized`; persisted on
  every mutation. mini-idp now reads service accounts from here (via the authenticate endpoint).
- **`secret`** — `Argon2SecretHasher`/`SecretHash`/`Argon2Settings`: the family's Argon2id pattern
  (a `mini-common` candidate), **replicated** here so the service stays standalone. Only
  service accounts carry a hash; humans carry none.
- **`store`** — `JsonStore` (atomic temp-file → `ATOMIC_MOVE` → `0600`, the replicated family store)
  holding one `DirectoryDocument` (`directory.json`: accounts + groups + roles in one atomic file).
- **`server`** — `ServerMain`/`DirectoryServer` (composition root), `ServerConfig`, `ApiHandlers`,
  `AdminAuthenticator`, the OpenAPI/Swagger serving, and the reused `http/` router. JDK
  `HttpServer` on loopback, one virtual thread per request.

- **Reuse over reinvention.** The `server/http` router, `AdminAuthenticator`, `OpenApiDocument`,
  `SwaggerUiPage`, the Argon2 hasher, and `JsonStore` are deliberate copies of mini-idp's (the
  documented `mini-common` candidates) so the service is self-contained until that library exists.
  The decision model is **not** copied — it depends on `:libs:mini-policy` and resolves into its
  `Principal`/`Grant`/`GrantBasedPolicyEngine` types directly.
- **Conventions.** Admin API guarded by the bootstrap bearer token (`MINIDIR_ADMIN_TOKEN`).
  Service-account secrets returned exactly once at creation, hashed at rest, never logged. Loopback
  bind by default. Id collisions → 409, dangling role/group references → 400. **The OpenAPI spec is
  the contract** — `OpenApiContractTest` fails if a documented path/method doesn't resolve on the
  live server, so keep `openapi.yaml` and the routes in `ApiHandlers` in sync.
- **Docs.** `services/mini-directory/README.md` — the record model, the resolution rule, and the
  endpoint list.

---

# Service: mini-oidc (`services/mini-oidc`)

mini-oidc is the **human SSO / OpenID Provider**: the OAuth 2.0 **authorization-code flow with
PKCE**, authenticating people with **passkeys** (WebAuthn) and issuing **ID + access tokens** (plus
rotating **refresh tokens**) that verify offline against the shared JWKS. Where mini-idp
authenticates machines, mini-oidc authenticates people. **Shipping**, and **composition over
reinvention**: it embeds pk-auth, mints through mini-token, decides through mini-policy, and resolves
identities from mini-directory.

**Run it locally.** Loopback by default; the bootstrap admin token (for client registration) comes
from env/file, never argv, never logged.

```bash
export MINIOIDC_ADMIN_TOKEN="$(openssl rand -hex 32)"
./gradlew :services:mini-oidc:installDist
services/mini-oidc/build/install/mini-oidc/bin/mini-oidc \
  --port 8477 --issuer https://oidc.example --rp-id oidc.example --rp-origin https://oidc.example \
  --directory-url http://127.0.0.1:8466 --secure-cookies
# Discovery at /.well-known/openid-configuration, JWKS at /jwks.json, docs at /docs.
```

**Architecture.** One application module under base package `com.codeheadsystems.minioidc`:

- **`auth`** — the human-authentication seam. `HumanAuthenticator` (passkey ceremony) is implemented
  by `PkAuthHumanAuthenticator` over pk-auth's `PasskeyAuthenticationService`; `RecoveryAuthenticator`
  wraps pk-auth's `BackupCodeService` for fallback login. `PasskeyStack` assembles the embedded
  pk-auth stack over its in-memory SPIs (the documented swap point for persistent credential storage;
  reading the authenticated `UserHandle` off the verified assertion, never pk-auth's JWT).
- **`directory`** — the `UserDirectory` SPI that resolves an authenticated human to a mini-policy
  `Principal` + grants + profile claims. `HttpUserDirectory` is the production path (calls
  mini-directory's `/admin/principals/{id}/resolution`); `InMemoryUserDirectory` backs tests/dev.
- **`service`** — `OidcTokens` mints ID/access tokens via mini-token's keys + `Jws` (see below);
  `OidcTokenVerifier` is the offline reference verifier; `ScopeAuthorizer` authorizes scopes through
  mini-policy; plus the flow stores (`PendingAuthorizationStore`, `AuthorizationCodeStore` with
  replay→family-revoke, `SessionService`, `RefreshTokenService` rotating with replay defense,
  `ClientService`).
- **`server`** — `ServerMain`/`OidcServer` (composition root), `ServerConfig`, `OidcHandlers` (every
  endpoint), `LoginPages` (minimal login/consent UI), `Cookies`, `AdminAuthenticator`, the reused
  `http/` router, and the OpenAPI/Swagger serving.

- **The token plane is REUSED, not re-implemented.** ID/access tokens are signed with mini-token's
  `SigningKeyService` keys and published through its JWKS + rotation. The only addition to mini-token
  was an **additive** generic `Jws.sign(JwsHeader, Map, PrivateKey)` overload, so OIDC claim sets
  (`nonce`, `auth_time`, `scope`, profile/email) sign with the same format and keys — mini-idp's
  typed path is untouched.
- **Browser-flow security.** Secure (configurable), HttpOnly, SameSite=Lax session cookie; the SSO
  **session lifetime is distinct from the token TTLs**; per-pending-authorization **CSRF token** on
  every state-changing browser POST; PKCE **mandatory** for every code request; redirect only to
  pre-registered URIs. Loopback by default — any LAN exposure MUST be behind a TLS reverse proxy with
  `--secure-cookies`.
- **Conventions.** No oracle (one `invalid_grant` for every code/refresh failure, one
  `invalid_client` for client-auth failure, one `invalid_token` at userinfo), constant-time secret
  comparison, no secrets in logs. **The OpenAPI spec is the contract** — `OpenApiContractTest` keeps
  `openapi.yaml` and the routes in sync.
- **Not yet wired by default.** `--directory-url` is optional; without it an empty in-memory
  directory is used (nobody resolves). Passkey enrolment (`/register/passkey/**`) is currently
  unauthenticated self-enrolment — a real deployment gates it.
- **Docs.** `services/mini-oidc/README.md` — the flow, the endpoint list, and the security model.

---

# Service: mini-gateway (`services/mini-gateway`)

mini-gateway is the **forward-auth endpoint** a reverse proxy (Traefik ForwardAuth, Caddy
forward_auth, nginx auth_request) calls before forwarding a request, to gate upstreams that have no
auth of their own. **Shipping**, and pure composition: it reuses mini-token (session store + JWS
verification) and mini-policy (the decision), inventing nothing.

**Run it.** No secrets of its own; it validates the family's sessions/tokens.

```bash
./gradlew :services:mini-gateway:installDist
services/mini-gateway/build/install/mini-gateway/bin/mini-gateway \
  --port 8488 --sessions-file ~/.mini-oidc/sessions.json --routes-file ./routes.json \
  --login-url "https://example.com/authorize?response_type=code&client_id=gateway&redirect_uri=https://example.com/&scope=openid&code_challenge=…&code_challenge_method=S256" \
  --jwks-url https://example.com/jwks.json --issuer https://example.com --audience https://example.com/userinfo
```

**Architecture.** One application module under base package `com.codeheadsystems.minigateway`:

- **`server/GatewayHandlers`** — the `GET /verify` endpoint (registered for all methods). It reads
  the original method/URI from `X-Forwarded-*` / `X-Original-*` and the client's `Cookie` /
  `Authorization`, authenticates, evaluates the route, and answers **200** (+ `X-Auth-Subject` /
  `X-Auth-Scope` / `X-Auth-Source`), **302**-to-login (unauthenticated browser), **401** (API), or
  **403** (forbidden).
- **`auth`** — `SessionAuthenticator` (the shared mini-token `SessionService` over the *same*
  `sessions.json` mini-oidc writes), `BearerAuthenticator` (mini-token `JwsClaimsVerifier` against
  the OP JWKS), and the `JwksProvider` SPI (`HttpJwksProvider` in production; injectable in tests).
- **`service/RoutePolicy`** + **`model`** — config-driven route rules (`routes.json`: ordered
  prefix rules, `PUBLIC`/`AUTHENTICATED`/`SCOPE`); `SCOPE` decisions defer to a mini-policy
  `GrantBasedPolicyEngine` built from the caller's scopes. Deny by default for unmatched paths.
- **`server`** — `ServerMain`/`GatewayServer` (composition root), `ServerConfig`, the reused
  `http/` router and `store/JsonStore`.

- **Shared session, not a second one.** The SSO session mechanism lives in mini-token
  (`session/SessionService` + `BrowserSession` + `Sessions`, over the `DocumentStore` SPI). mini-oidc
  is the sole writer; mini-gateway is a reader of the same file. The session cookie name is the
  shared `SessionService.DEFAULT_COOKIE_NAME`. For the cookie to reach a gated app, mini-oidc and the
  app share a hostname (host-only cookie, `Path=/`) — see the README's proxy snippets.
- **Conventions.** No oracle (failures collapse to 401/403/302; bearer verification fails closed),
  no secrets in logs, deny-by-default, loopback bind (the proxy reaches it over the loopback/Docker
  network; never exposed to clients directly).
- **Docs.** `services/mini-gateway/README.md` — the decision flow, the routes config, and runnable
  Traefik / Caddy / nginx snippets; `services/mini-gateway/examples/` — `routes.json`, a Traefik
  `docker-compose`, and a `Caddyfile` that gate a no-auth `whoami` behind a mini-oidc login.

---

# Service: mini-ca (`services/mini-ca`)

mini-ca is a small **internal certificate authority** for the homelab: it issues and renews
short-lived X.509 leaf certs (mTLS between the minis + homelab services) from PKCS#10 CSRs, keeps an
issuance log + revocation list, and **wraps its own CA private key under mini-kms** (the recursive
integration). **Shipping**, and deliberately **not a full PKI** — see the README's non-goals (one
self-signed root, JSON revocation list rather than a signed DER CRL, no intermediates/ACME/OCSP).

**Run it.** Loopback by default; admin token from env/file (never argv, never logged).

```bash
export MINICA_ADMIN_TOKEN="$(openssl rand -hex 32)"
./gradlew :services:mini-ca:installDist
services/mini-ca/build/install/mini-ca/bin/mini-ca --port 8499 --data-dir ~/.mini-ca \
  --kms-tcp 127.0.0.1:9123 --kms-key-group ca-key   # --kms-* optional (else plaintext 0600)
```

**Architecture.** One application module under base package `com.codeheadsystems.minica`:

- **`ca`** — the crypto: `CaKeys` (EC P-256 keygen + self-signed root via BouncyCastle PKIX),
  `CertificateAuthority` (issues an mTLS leaf from a CSR — verifies proof-of-possession, sets the
  extension set, random serial, short TTL), and hand-rolled `Pem`.
- **`service/CaService`** — bootstraps (mint a fresh CA on first run, else load), issues/renews/
  revokes, and maintains the issuance log + revocation list. The **CA private key is persisted as a
  one-record mini-token `SigningKeys` document** through the injected `DocumentStore` — so it reuses
  `KmsSigningKeyStore` (KMS-wrapped) or a plaintext `JsonStore`, exactly like the token signing keys.
  The root cert / log / revocations are plaintext (public).
- **`server`** — `ServerMain`/`CaServer` (composition root), `ServerConfig`, `ApiHandlers`,
  `AdminAuthenticator`, the reused `http/` router + `store/JsonStore`, and the OpenAPI/Swagger
  serving.

- **CA key under mini-kms.** Reuses Prompt 6's `KmsSigningKeyStore` verbatim (the CA key is just a
  PKCS#8 in a `SigningKeys` record); with `--kms-*` set, `ca-key.json` holds only a `kms1:` envelope,
  unwrapped in memory at bootstrap. Bootstrap ordering / failure modes are the token-key ones in
  `docs/DIRECTION.md`.
- **Conventions.** `/ca` (trust anchor) + `/revocations` + `/health` are public; issuance/renewal/
  revocation/log are admin-guarded. EC P-256 / `SHA256withECDSA`; short leaf TTLs (clamped); CSR
  PoP verified (the CA never sees a requester's private key); one generic `400` for a bad CSR (no
  oracle); no secrets logged; loopback bind.
- **Docs.** `services/mini-ca/README.md` — scope, the explicit non-goals, the endpoint list, and the
  mini-kms key-wrapping wiring.
