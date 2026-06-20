# mini-auth

The umbrella for the **mini-** family: small, readable, **educational-but-homelab-functional**
auth and identity services, built in the same spirit as
[mini-kms](services/mini-kms/README.md) and [mini-idp](services/mini-idp/README.md).

mini-auth is two things:

1. **An aggregator build** — one `./gradlew build` from here builds the whole family. mini-kms
   and mini-idp now live **inside** this repo as nested modules (a single monorepo build), and
   the whole family is standardized on one toolchain and **Jackson 3.x**.
2. **The canonical direction doc** — **[docs/DIRECTION.md](docs/DIRECTION.md)** is the shared map
   of the family: the vision, the catalog, the architecture, the recursive integrations, the open
   design questions, and the roadmap — the full architecture reference.

> 🎓 **New here? Start with [docs/TEACHING.md](docs/TEACHING.md).** It's a course-style track
> (concepts → hands-on labs → security) that teaches authentication & authorization using the family
> as the worked example, and it routes you to the right next step in one screen.
>
> It links you onward to the other entry points when you need them: **[docs/LEARNING.md](docs/LEARNING.md)**
> if you'd rather read the *source* in dependency order (code-first instead of concepts-first),
> **[docs/GLOSSARY.md](docs/GLOSSARY.md)** for the crypto / OAuth / OIDC vocabulary, and
> **[docs/DIRECTION.md](docs/DIRECTION.md)** for the whole architecture map.

> ⚠️ **Educational project.** The family uses real, sound cryptographic constructions but is **not
> audited** and is not a substitute for production identity infrastructure. All seven services —
> including `mini-console`, the admin console + exercise harness over the family — and the shared
> libraries (`mini-token`, `mini-policy`, plus `mini-client-common` and the per-service client libs)
> ship and run. Nothing here is a half-built service that *looks* finished — where a module isn't
> done, it says so.

## The guiding principle

Many small, single-responsibility **libraries** composed into a few deployable **services**.
mini-auth does not re-implement what mini-kms and mini-idp already do — it **composes** them and
adds the connective tissue (`mini-token`, `mini-policy`) and the new human-facing front doors
(`mini-oidc`, `mini-gateway`, `mini-directory`).

## The family at a glance

| Mini | Purpose | Type | Status |
| --- | --- | --- | --- |
| [mini-kms](services/mini-kms) | Envelope-encryption KMS; the vault wrapping other services' signing keys. | service | **shipping** |
| [mini-idp](services/mini-idp) | Machine identity: OAuth2 client-credentials → Ed25519 JWT + JWKS. | service | **shipping** |
| [mini-token](libs/mini-token) | Shared token plane: JWS, JWKS, key rotation, revocation, audit, SSO session store. | library | **shipping** |
| [mini-directory](services/mini-directory) | Identity source of truth: humans, service accounts, groups, roles, grants. | service | **shipping** |
| [mini-oidc](services/mini-oidc) | Human SSO / OpenID Provider (auth-code + PKCE); embeds **pk-auth** passkeys. | service | **shipping** |
| [mini-gateway](services/mini-gateway) | Forward-auth endpoint for a reverse proxy (Traefik / Caddy / nginx). | service | **shipping** |
| [mini-ca](services/mini-ca) | Internal CA for mTLS / workload identity; CA key wrapped under mini-kms. | service | **shipping** |
| [mini-policy](libs/mini-policy) | Generalized `(principal, action, resource) → allow/deny` decision function; the shared authorization engine. | library | **shipping** |
| [mini-console](services/mini-console) | Optional unified admin console + exercise harness over the family; adds no new authority. | service | **shipping** |
| [mini-client-common](libs/mini-client-common) + `*-client` | Shared client HTTP/token/JSON plumbing (no-oracle collapse) + the per-service client libs mini-console consumes. | libraries | **shipping** |
| **pk-auth** | Passkeys-first library set on Maven Central — a normal dependency, **not vendored**. | external | shipping |

See **[docs/DIRECTION.md](docs/DIRECTION.md)** for the one-line catalog, the architecture diagram,
and how these depend on each other at runtime (mini-oidc embeds pk-auth; both issuers go through
mini-token; everything decides through mini-policy; mini-token's signing keys are wrapped by
mini-kms — the recursive integration; mini-directory is the identity source of truth).

## Layout

Modules are grouped by role under `services/` (deployable front doors) and `libs/` (shared
libraries); the Gradle project path follows the directory.

```
mini-auth/
├── settings.gradle.kts          # one build: includes every module + build-logic (convention plugins)
├── build.gradle.kts             # just the `base` plugin — conventions live in build-logic/
├── gradle/libs.versions.toml    # one catalog for the whole family (Jackson 3.x)
├── build-logic/                 # included build: miniauth.java/library/application-conventions
├── docs/DIRECTION.md            # ← the direction doc
├── services/                    # deployable front doors
│   ├── mini-kms/                #   core/ server/ client/  (shipping)
│   ├── mini-idp/                #   core/ server/          (shipping)
│   ├── mini-oidc/               #   shipping; human SSO, embeds pk-auth + mini-token + mini-policy + mini-directory
│   ├── mini-gateway/            #   shipping; forward-auth, reuses mini-token + mini-policy
│   ├── mini-directory/          #   shipping; identity source of truth
│   ├── mini-ca/                 #   shipping; internal CA, CA key wrapped under mini-kms
│   └── mini-console/            #   shipping; admin console + exercise harness over the family
└── libs/                        # shared libraries (no transport)
    ├── mini-token/              #   library (shipping)
    ├── mini-policy/             #   library (shipping; shared decision engine)
    ├── mini-client-common/      #   library (shipping; HTTP/token/JSON plumbing for the client libs)
    └── mini-{directory,idp,oidc,ca,gateway}-client/   #   libraries (shipping; mini-console's HTTP clients)
```

Gradle project paths follow the directories: `:services:mini-kms:core`, `:services:mini-idp:server`,
`:libs:mini-token`, etc. Base **packages are unchanged** by the grouping — each module keeps
`com.codeheadsystems.<mini>` (e.g. `com.codeheadsystems.minitoken`). Every module uses the shared
convention plugins from `build-logic/` (base package aside): Kotlin-DSL Gradle, a JDK 21 toolchain,
JUnit 5, and the same Jackson 3.x / Bouncy Castle versions from the one catalog.

## Building

Requires a JDK 21+ on `PATH` (the toolchain is pinned to 21; foojay can auto-download it).

```bash
./gradlew build        # compile + test EVERYTHING across the family — this IS the CI gate
./gradlew test         # tests only, all modules
./gradlew :services:mini-oidc:installDist   # a runnable launcher (services/mini-oidc/build/install/mini-oidc/bin/mini-oidc)
```

The first build resolves `pk-auth-core` from Maven Central (for `mini-oidc`) and the Jackson 3.x
artifacts; after that the build is offline-friendly. Each shipping service installs a real launcher
that binds a loopback HTTP (or socket) server — see the per-service README for how to run it.

### Build aggregation, in brief

This is a single **monorepo** Gradle build: mini-kms and mini-idp — two formerly-independent Gradle
builds — were pulled in and unified under one wrapper, one `settings.gradle.kts`, one version
catalog, and one set of **convention plugins** (the `build-logic/` included build), so
`./gradlew build` covers the whole family with no composite or submodule machinery. The family is
standardized on **Jackson 3.x** (`tools.jackson.*`, matching pk-auth's transitive Jackson) and a
single CI workflow (`.github/workflows/build.yml`) runs `./gradlew build` on every push/PR. Full
rationale, the layout, and the `mini-common` extraction candidates: the
[Build aggregation](docs/DIRECTION.md#build-aggregation) section of the direction doc.

## Status & intent

All seven services (mini-kms, mini-idp, mini-directory, mini-oidc, mini-gateway, mini-ca,
mini-console) and the shared libraries (`mini-token`, `mini-policy`, `mini-client-common`, and the
five `*-client` libs) **ship** — they build, test, and run as their READMEs describe. `mini-policy`
is deliberately small (the decision types, the engine seam, and a grant-based engine consumed by
four services); `mini-console` adds no new authority — it is a client of admin surfaces that already
exist. The longer arc — notably wiring the token →
mini-kms authorization path end to end (today mini-kms authenticates with shared per-plane tokens;
the `grants`-claim → KMS mapping is designed but not yet the live runtime path) and the
`mini-common` extraction — is tracked in the [roadmap](docs/DIRECTION.md#roadmap). Where a module
isn't done, it says so.
