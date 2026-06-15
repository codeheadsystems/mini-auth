# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> **Monorepo note.** mini-idp is vendored into the **mini-auth** monorepo as the module group
> `:mini-idp:core` / `:mini-idp:server`. Run all Gradle commands from the mini-auth root (the
> wrapper, `settings.gradle.kts`, version catalog, and shared Java conventions live there). JSON
> now uses **Jackson 3.x** (`tools.jackson.*`), shared family-wide. The "does not depend on
> mini-kms" note below still holds at the code level — they are co-built, not coupled. See the root
> `README.md` and `docs/DIRECTION.md`.

## What this is

mini-idp is an **educational** standalone identity provider in Java. It registers clients,
issues short-lived Ed25519-signed JWT access tokens via the OAuth 2.0 **client-credentials**
grant, and publishes its public signing keys (JWKS) so a verifier can validate tokens
**offline**. Like its sibling project **mini-kms**, it is heavily commented on purpose — the
code is meant to be *read* to learn how token issuance and offline JWS verification work. It
uses real, sound crypto (Argon2id for secrets, Ed25519/EdDSA for signatures) but is explicitly
not production-audited. Clarity and correct security reasoning matter more than features.

mini-idp is **step 1** of evolving mini-kms away from a shared static token toward per-client
identities: its tokens carry an authorization claim (`grants`) that maps cleanly onto mini-kms's
`Principal` / `KeyOperation` model. **This project does not depend on mini-kms** — it only mirrors
its conventions and targets its eventual verification contract.

## Build & test

Requires JDK 21+ (the Gradle toolchain is pinned to 21; it can auto-download via the foojay
resolver).

Run from the mini-auth root (`./gradlew build` there builds the whole family; the commands below
scope to mini-idp):

```bash
./gradlew build                       # compile + run ALL tests, whole family (this is the CI check)
./gradlew :mini-idp:core:test :mini-idp:server:test   # mini-idp tests only
./gradlew :mini-idp:core:test         # one module
./gradlew :mini-idp:core:test --tests "*TokenLifecycleTest"                                  # one class
./gradlew :mini-idp:core:test --tests "*TokenLifecycleTest.expiredTokenIsRejected"           # one method

# Runnable launcher at mini-idp/server/build/install/server/bin/server :
./gradlew :mini-idp:server:installDist
```

There is **no separate linter/formatter**; `./gradlew build` is the full gate. Tests are JUnit 5.
Gradle's configuration cache is on (`org.gradle.configuration-cache=true`), so build-script
changes may need `--no-configuration-cache` while iterating.

## Running it locally

The bootstrap admin token comes from an env var or a file, **never a CLI arg, and is never
logged**.

```bash
export MINIIDP_ADMIN_TOKEN="$(openssl rand -hex 32)"
mini-idp/server/build/install/server/bin/server --port 8455 --data-dir ~/.mini-idp

# Register a client (admin), then exchange its credentials for a token:
curl -s -X POST localhost:8455/admin/clients -H "Authorization: Bearer $MINIIDP_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"displayName":"svc","authorization":{"control":false,"groups":[{"keyGroup":"billing","operations":["ENCRYPT","DECRYPT"]}]}}'
curl -s -X POST localhost:8455/oauth/token \
  -d 'grant_type=client_credentials&client_id=CLIENT&client_secret=SECRET'

# Browse the API: http://localhost:8455/docs  (Swagger UI, vendored assets, works offline)
```

## Architecture

Two Gradle modules under base package `com.codeheadsystems.miniidp` (project paths
`:mini-idp:core`, `:mini-idp:server`):

- **`core`** — the identity model, crypto, and token machinery, with **no HTTP/transport code**.
  This separation is load-bearing (mirrors mini-kms's I/O-free `core`): the services and crypto
  can be reused and tested without a server. Owns the authorization model, Argon2id secret
  hashing, Ed25519 keys, the hand-rolled JWS/JWT, the JWKS model, the JSON file stores, and the
  services built on them.
- **`server`** — the HTTP daemon (`ServerMain`): a JDK `com.sun.net.httpserver.HttpServer` on
  loopback, the tiny router, the request handlers, config, and the OpenAPI spec + vendored
  Swagger UI. Depends on `core`.

### The token contract (why the design is shaped this way)

The published contract is `server/src/main/resources/openapi.yaml` (served at `/openapi.yaml`,
`/openapi.json`, rendered at `/docs`). The JWT claim schema there is authoritative. The key piece
is the `grants` claim, produced by `token/GrantsClaim` from a domain `auth/Authorization`:

- `sub` (clientId) → mini-kms `Principal.id`
- `grants.control` → mini-kms `Principal.admin`
- `grants.groups[]` (`keyGroup` + `KeyOperation` names) → mini-kms `KeyAuthorizationPolicy`

`auth/KeyOperation` is a **deliberate mirror** of mini-kms's enum — the string values are the
contract, so do not rename them. A `cnf` claim is reserved (RFC 7800) for future channel binding
but is not populated or enforced yet.

### Crypto & formats (the hand-rolled bits)

- **Ed25519 signing** uses only the JDK (`KeyPairGenerator`/`Signature` `"Ed25519"`).
  `crypto/Ed25519Keys` handles encoding; the JWK `x` value is the trailing 32 bytes of the SPKI.
- **The JWS is hand-rolled** in `token/Jws` (commented heavily, the way mini-kms hand-rolls its
  envelope formats) rather than via a JOSE library: `base64url(header).base64url(payload).
  base64url(sig)`, signed over the ASCII of the first two segments. `token/TokenVerifier` is the
  reference offline verifier (signature first, then `iss`/`aud`/time/revocation).
- **Client secrets** are hashed with Argon2id (`secret/Argon2SecretHasher`, mirrors mini-kms's
  `Argon2KeyDeriver`) and verified in constant time (`MessageDigest.isEqual`).

### Persistence & key rotation

- All state (clients, signing keys, revocations, audit) is JSON written via `store/JsonStore`
  with the **atomic temp-file + `ATOMIC_MOVE` + 0600** pattern (mirrors mini-kms's `Keystore`).
- Private signing keys live in `signing-keys.json` (0600). **A real deployment would wrap them
  under a KMS** — that is the eventual recursive integration with mini-kms, intentionally out of
  scope. The marker is in `model/SigningKeyRecord`.
- Rotation (`service/SigningKeyService`) activates a fresh key and retires the old one; retired
  keys stay in the JWKS (`retiredKeyRetention`, = 2× token TTL) so tokens signed just before a
  rotation still verify until they expire.

## Conventions specific to this repo

- **`core` stays HTTP-free.** No `com.sun.net.httpserver`, sockets, or request parsing belong
  there. The composition root is `server/IdpServer`.
- **`-parameters` compilation is required** — Jackson deserializes the store records and token
  claim records by constructor parameter names. Don't remove the compiler flag (set in the mini-auth
  root build) or Jackson record binding breaks.
- **Jackson 3.x (`tools.jackson.*`).** Mappers are immutable — build them with
  `JsonMapper.builder()…build()` (no instance `enable`/`configure`); read/write throw the unchecked
  `tools.jackson.core.JacksonException`. Only `jackson-annotations` stays on
  `com.fasterxml.jackson.annotation` (so `@JsonProperty`/`@JsonInclude` imports are unchanged).
  YAML parsing of the OpenAPI spec uses `tools.jackson.dataformat.yaml.YAMLMapper`.
- **No oracles, no leaks.** The token endpoint returns a single generic `invalid_client` for any
  authentication failure (no unknown-client vs. wrong-secret distinction). Client secrets, private
  keys, and raw tokens are never logged; access logs record method/path/status only.
- **Secrets via env/file, never argv.** The admin token follows the `resolveAdminToken` pattern.
- Use `System.Logger` (already the pattern), not a third-party logging dependency.
- **The OpenAPI spec is the contract.** `OpenApiContractTest` fails if a documented path/method
  doesn't resolve on the live server, so keep `openapi.yaml` and the routes in `ApiHandlers` in
  sync.

## Docs

- `README.md` — how to run it, the full endpoint list, the token claim schema, and the
  JWKS/discovery URLs (the exact contract mini-kms will consume next).
