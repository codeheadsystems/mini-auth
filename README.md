# mini-auth

The umbrella for the **mini-** family: small, readable, **educational-but-homelab-functional**
auth and identity services, built in the same spirit as
[mini-kms](../mini-kms/README.md) and [mini-idp](../mini-idp/README.md).

mini-auth is two things:

1. **An aggregator build** — one `./gradlew build` from here builds the whole family. mini-kms
   and mini-idp now live **inside** this repo as nested modules (a single monorepo build), and
   the whole family is standardized on one toolchain and **Jackson 3.x**.
2. **The canonical direction doc** — **[docs/DIRECTION.md](docs/DIRECTION.md)** is the shared map
   of the family: the vision, the catalog, the architecture, the recursive integrations, the open
   design questions, and the roadmap. **Read it first.**

> ⚠️ **Educational project.** The family uses real, sound cryptographic constructions but is not
> audited and is not a substitute for production identity infrastructure. Several modules here are
> **scaffolds** — they compile and pass a trivial test, with the real protocol/crypto left as
> clearly-marked TODOs. They are deliberately *not* half-built services that look finished.

## The guiding principle

Many small, single-responsibility **libraries** composed into a few deployable **services**.
mini-auth does not re-implement what mini-kms and mini-idp already do — it **composes** them and
adds the connective tissue (`mini-token`, `mini-policy`) and the new human-facing front doors
(`mini-oidc`, `mini-gateway`, `mini-directory`).

## The family at a glance

| Mini | Purpose | Type | Status |
| --- | --- | --- | --- |
| [mini-kms](mini-kms) | Envelope-encryption KMS; the eventual vault wrapping other services' signing keys. | service | **shipping** |
| [mini-idp](mini-idp) | Machine identity: OAuth2 client-credentials → Ed25519 JWT + JWKS. | service | **shipping** |
| `mini-token` | Shared token plane: JWS, JWKS, key rotation, revocation, audit. | library | scaffolded |
| `mini-policy` | Generalized `(principal, resource, action) → allow/deny` decision function. | library | scaffolded |
| `mini-oidc` | Human SSO / OpenID Provider (auth-code + PKCE); embeds **pk-auth** passkeys. | service | scaffolded |
| `mini-gateway` | Forward-auth endpoint for a reverse proxy (Traefik / Caddy / nginx). | service | scaffolded |
| `mini-directory` | Identity source of truth: users, groups, roles, service accounts, grants. | service | scaffolded |
| `mini-ca` | Internal CA for mTLS / workload identity. | service | roadmap (placeholder) |
| `mini-console` | Optional unified admin UI. | service | roadmap (placeholder) |
| **pk-auth** | Passkeys-first library set on Maven Central — a normal dependency, **not vendored**. | external | shipping |

See **[docs/DIRECTION.md](docs/DIRECTION.md)** for the one-line catalog, the architecture diagram,
and how these depend on each other at runtime (mini-oidc embeds pk-auth; both issuers go through
mini-token; everything decides through mini-policy; mini-token's signing keys are wrapped by
mini-kms — the recursive integration; mini-directory is the identity source of truth).

## Layout

```
mini-auth/
├── settings.gradle.kts     # one build: include mini-kms:*, mini-idp:* + the new modules
├── build.gradle.kts        # shared Java conventions applied to every module
├── gradle/libs.versions.toml   # one catalog for the whole family (Jackson 3.x)
├── docs/DIRECTION.md        # ← the direction doc
├── mini-kms/               # vendored: core/ server/ client/  (shipping)
├── mini-idp/               # vendored: core/ server/          (shipping)
├── mini-token/             # library  (scaffold)
├── mini-policy/            # library  (scaffold)
├── mini-oidc/              # service  (scaffold; depends on pk-auth, mini-token, mini-policy)
├── mini-gateway/           # service  (scaffold; depends on mini-token, mini-policy)
├── mini-directory/         # service  (scaffold; depends on mini-policy)
├── mini-ca/                # roadmap placeholder (no logic)
└── mini-console/           # roadmap placeholder (no logic)
```

Gradle project paths follow the directories: `:mini-kms:core`, `:mini-idp:server`, etc. Each
new service/library uses the same conventions as the vendored minis: base package
`com.codeheadsystems.<mini>` (e.g. `com.codeheadsystems.minitoken`), Kotlin-DSL Gradle, a JDK 21
toolchain pinned via the root build, JUnit 5, and the same Jackson 3.x / Bouncy Castle versions.

## Building

Requires a JDK 21+ on `PATH` (the toolchain is pinned to 21; foojay can auto-download it).

```bash
./gradlew build        # compile + test EVERYTHING: the new modules AND vendored mini-kms + mini-idp
./gradlew test         # tests only, all modules
./gradlew :mini-oidc:installDist   # a runnable launcher for one scaffolded service
```

The first build resolves `pk-auth-core` from Maven Central (for `mini-oidc`) and the Jackson 3.x
artifacts; after that the build is offline-friendly. The scaffolded service entry points run but
only print a status banner — they do not yet bind a server (by design).

### Build aggregation, in brief

This is a single **monorepo** Gradle build: mini-kms and mini-idp were pulled in as nested module
groups (`include("mini-kms:core")`, …) so `./gradlew build` covers the whole family with no
composite or submodule machinery, and the family standardized on **Jackson 3.x** (`tools.jackson.*`,
matching pk-auth's transitive Jackson). Full rationale and the migration notes: the
[Build aggregation](docs/DIRECTION.md#build-aggregation) section of the direction doc.

## Status & intent

mini-auth is at **Phase 0** of the [roadmap](docs/DIRECTION.md#roadmap): a green umbrella build and
the correct module skeleton. The next step is extracting mini-idp's token machinery into
`mini-token`. Nothing here ships finished auth or crypto yet — and where it isn't done, it says so.
