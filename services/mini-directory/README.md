# mini-directory

**mini-directory** is the single **identity source of truth** for the mini- family. It owns
**humans**, **service accounts**, **groups**, and **roles**, plus the grant mappings between them —
and its defining job is **resolution**: turning any stored account into a
[`mini-policy`](../../libs/mini-policy) `Principal` plus a **fully-expanded, de-duplicated set of
`(action, resource)` grants**, which is exactly what a `mini-policy` decision function consumes.

Where its siblings each do one *security* job — mini-kms guards keys, mini-idp mints machine tokens —
mini-directory answers one *identity* question: **"who is this principal, and what may it do?"** It
is the place an operator defines roles and groups once and hands them to many principals, and the
read side a token issuer calls to authenticate a service account and fetch its grants.

It is an **educational** project (a sibling to mini-kms and mini-idp): heavily commented, real but
un-audited crypto, built to be *read*. It mirrors the family conventions — a loopback HTTP service,
an admin API behind a bootstrap bearer token, an atomic-`0600` JSON store, no secrets in logs, and an
OpenAPI spec served with a vendored Swagger UI.

> **Not for production.** State is a single local JSON file; the admin API is guarded by one shared
> bootstrap token (no per-operator identities); humans authenticate elsewhere (mini-oidc), not here.
> mini-idp already reads its service accounts from here; mini-oidc resolves humans from here — both
> over the loopback admin API.

## Table of contents

- [What it does](#what-it-does)
- [Glossary & the record model](#glossary--the-record-model)
- [Resolution — the point of the service](#resolution--the-point-of-the-service)
  - [The expansion rule](#the-expansion-rule)
  - [A worked example](#a-worked-example)
- [Quick start](#quick-start)
- [The grant vocabulary (`GrantSpec` ↔ mini-policy `Grant`)](#the-grant-vocabulary)
- [Service-account authentication (the read API mini-idp calls)](#service-account-authentication)
- [Endpoints](#endpoints)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Security notes](#security-notes)
- [Migrating mini-idp's client registry](#migrating-mini-idps-client-registry)
- [Building & testing](#building--testing)

## What it does

- **Defines roles** — a named, reusable bundle of grants (`POST /admin/roles`).
- **Defines groups** — a named bundle of roles + direct grants that accounts join to inherit
  authorization (`POST /admin/groups`).
- **Registers humans** (`POST /admin/humans`, operator-chosen id, no secret) and **service accounts**
  (`POST /admin/service-accounts`, generated id + a **one-time** Argon2id-hashed secret).
- **Assigns authorization** — replaces an account's admin capability, group memberships, roles, and
  direct grants (`PUT /admin/principals/{id}/assignment`).
- **Resolves** any account into a mini-policy `Principal` + effective grants
  (`GET /admin/principals/{id}/resolution`) — the inputs a `GrantBasedPolicyEngine` decides over.
- **Authenticates a service account** and returns its resolution in one call
  (`POST /admin/service-accounts/authenticate`) — the read API a token issuer (mini-idp) calls, with
  no credential oracle.
- **Documents everything** as an OpenAPI 3.1 spec served at a stable URL and rendered by a bundled
  Swagger UI.

## Glossary & the record model

Every stored record is a small immutable Java `record`; lists are defensively copied and never null.

| Record | What it is |
| --- | --- |
| **Account** | A resolvable identity — a `HUMAN` or a `SERVICE_ACCOUNT` (`PrincipalKind`). Its `id` becomes the mini-policy `Principal` id (and a future token `sub`); its `admin` flag becomes the principal's control/admin capability. It carries an `enabled` flag, direct `grants`, directly-assigned `roles`, group memberships (`memberOf`), and — for a service account that has a secret — an Argon2id `secretHash`. A human carries no secret. |
| **Role** | A named bundle of grants. Assigning a role grants every permission it carries. A role references no other roles or groups, so expanding it is a single flat step. |
| **Group** | A named bundle of roles + direct grants that accounts join (membership is recorded on the *account*, in `memberOf`). A group references roles but not other groups, so resolution stays a flat, acyclic expansion. |
| **GrantSpec** | One permission as a flat `{ "action": "...", "resource": "..." }` pair — the JSON-friendly mirror of a mini-policy `Grant`. Either coordinate may be the wildcard `"*"`. |
| **ResolvedPrincipal** | The output: a mini-policy `Principal` (id + admin) plus the flattened, de-duplicated list of mini-policy `Grant`s — *not* stored, computed on demand. |

The whole authorization graph is two flat hops deep and cycle-free by construction:

```
account ──memberOf──▶ group ──roles──▶ role ──grants──▶ GrantSpec
   │                    └────────────────────grants────▶ GrantSpec
   ├──roles───────────────────────────▶ role ──grants──▶ GrantSpec
   └──grants──────────────────────────────────────────▶ GrantSpec
```

## Resolution — the point of the service

`GET /admin/principals/{id}/resolution` (and the authenticate endpoint) resolve an account into a
mini-policy `Principal` plus its **effective grants**. This is the directory's whole reason to exist:
it is the function that turns stored identities, roles, and group memberships into exactly the inputs
a `mini-policy` `PolicyEngine` decides over.

### The expansion rule

The effective grant set is the de-duplicated union of four sources:

```
effective(account) =
      account.grants                                   ── grants assigned directly
  ∪   grants(role)  for each role in account.roles     ── roles assigned directly expand to grants
  ∪   for each group g in account.memberOf:
          g.grants                                      ── the group's own direct grants
        ∪ grants(role)  for each role in g.roles        ── and the group's roles, expanded
```

The result is flattened and **de-duplicated, preserving first-seen order** (an internal
`LinkedHashSet` of `GrantSpec`, then a final dedup into mini-policy `Grant`s). Two important
properties, both deliberate:

- **Roles expand to grants; group memberships are inherited.** There is no recursion to chase —
  groups never contain groups, roles never contain roles — so resolution is always a single flat pass.
- **Dangling references are skipped, never fatal.** If an account still cites a role or group that was
  since deleted, that reference is silently ignored. Deleting a role can never break the resolution of
  an account that still names it.

The resulting `(Principal, [Grant])` plugs straight into a `GrantBasedPolicyEngine`
(`ResolvedPrincipal.toPolicyEngine()`): an `admin` principal is permitted everything regardless of
the grant list (mirroring a mini-idp token's `grants.control`); otherwise a request is allowed iff
some grant permits that `(action, resource)`.

### A worked example

Define a role, put it in a group, and join a human to the group:

```
role  billing-operator = { (ENCRYPT, billing), (DECRYPT, billing) }
group finance          = { roles: [billing-operator], grants: [ (READ, reports) ] }
human alice            = { admin: false, memberOf: [finance], roles: [], grants: [ (DECRYPT, audit) ] }
```

Resolving `alice` walks: her direct grants `{(DECRYPT, audit)}`, then group `finance` → its direct
grants `{(READ, reports)}` and its role `billing-operator` → `{(ENCRYPT, billing), (DECRYPT, billing)}`.
Flattened and de-duplicated:

```jsonc
GET /admin/principals/alice/resolution
{
  "id": "alice",
  "admin": false,
  "grants": [
    { "action": "DECRYPT", "resource": "audit" },
    { "action": "READ",    "resource": "reports" },
    { "action": "ENCRYPT", "resource": "billing" },
    { "action": "DECRYPT", "resource": "billing" }
  ]
}
```

## Quick start

Requires JDK 21+. The bootstrap admin token comes from an env var or a file — **never a CLI arg, and
never logged**.

```bash
export MINIDIR_ADMIN_TOKEN="$(openssl rand -hex 32)"
./gradlew :services:mini-directory:installDist
services/mini-directory/build/install/mini-directory/bin/mini-directory --port 8466 --data-dir ~/.mini-directory
```

```bash
B=http://127.0.0.1:8466; H="Authorization: Bearer $MINIDIR_ADMIN_TOKEN"

# 1) Define a reusable role, put it in a group.
curl -s -XPOST $B/admin/roles  -H "$H" \
  -d '{"id":"billing-operator","grants":[{"action":"ENCRYPT","resource":"billing"},
       {"action":"DECRYPT","resource":"billing"}]}'
curl -s -XPOST $B/admin/groups -H "$H" -d '{"id":"finance","roles":["billing-operator"]}'

# 2) Create a human (no secret) who is a member of the group.
curl -s -XPOST $B/admin/humans -H "$H" -d '{"id":"alice","memberOf":["finance"]}'

# 3) Resolve — roles and group memberships are expanded and de-duplicated.
curl -s $B/admin/principals/alice/resolution -H "$H"
#  => {"id":"alice","admin":false,"grants":[{"action":"ENCRYPT","resource":"billing"},
#                                           {"action":"DECRYPT","resource":"billing"}]}

# 4) Create a service account (generated id + ONE-TIME secret).
curl -s -XPOST $B/admin/service-accounts -H "$H" \
  -d '{"displayName":"billing-svc","memberOf":["finance"]}'
#  => {"id":"svc_…","secret":"…","account":{...}}   (the secret is shown ONCE)

# 5) Browse the live API docs.
open http://localhost:8466/docs
```

## The grant vocabulary

A `GrantSpec` is the stored and on-the-wire form of one permission — a flat
`{ "action": "...", "resource": "..." }` pair. It is a thin, JSON-friendly mirror of mini-policy's
`Grant`, whose `Action` and `Resource` are themselves `record(String value)` wrappers; serializing
those directly would nest a `{"value": …}` object per coordinate, so the directory keeps the flat
shape and converts with `GrantSpec.toPolicyGrant()`:

```
GrantSpec { action, resource }   ─toPolicyGrant()→   Grant( Action.of(action), Resource.of(resource) )
```

The wildcard `"*"` maps to mini-policy's `Action.ANY` / `Resource.ANY` (its wildcards are just the
value `"*"`), so `("*", "billing")` means "any action on key group `billing`". The action/resource
vocabulary is **not** fixed by the directory — today it carries mini-kms `KeyOperation` names
(`ENCRYPT`, `DECRYPT`, `GENERATE_DATA_KEY`, `RE_ENCRYPT`) against key-group resources, which is
exactly the contract mini-idp reassembles into a token's `grants` claim. The directory stores and
resolves the strings; the consuming policy engine gives them meaning.

## Service-account authentication

`POST /admin/service-accounts/authenticate` is the read API a token issuer (mini-idp) calls at token
issuance: it presents `{ "id", "secret" }`, the directory verifies the secret **server-side**, and on
success returns the account's full **resolution** (principal + expanded grants) in the same response.
This is what lets the secret hash never leave the directory — mini-idp gets grants, not credentials.

The verification is **no-oracle** by construction (`DirectoryService.authenticate`):

- Verification is constant-time (`MessageDigest.isEqual` over the Argon2id output).
- An **unknown id**, a **human**, or a **secretless service account** still incurs an Argon2id
  verification against a fixed throwaway `DUMMY_HASH`, so the timing of a failed lookup does not
  reveal *which* check failed.
- A **disabled** account fails verification even with the right secret.
- Any failure surfaces as a single generic `401 invalid_client` — never "no such account" vs. "wrong
  secret".

The endpoint is itself admin-guarded (only an authorized issuer may call it), and the presented
secret `char[]` is zeroed in a `finally` after the attempt.

## Endpoints

All `/admin/**` endpoints require `Authorization: Bearer <admin-token>`; a missing/wrong token returns
`401`. The full machine-readable contract is the OpenAPI 3.1 spec: `/openapi.yaml`, `/openapi.json`,
Swagger UI at `/docs`.

**Public**

| Method & path | Purpose |
| --- | --- |
| `GET /health` | Liveness → `{"status":"ok"}`. |
| `GET /openapi.yaml`, `GET /openapi.json` | The served spec. |
| `GET /docs` | Swagger UI (vendored, works offline). |

**Roles** (admin)

| Method & path | Purpose |
| --- | --- |
| `POST /admin/roles` | Create a role → `201`. |
| `GET /admin/roles` | List roles. |
| `GET /admin/roles/{id}` | Read a role. |
| `PUT /admin/roles/{id}` | Replace a role's description + grants. |
| `DELETE /admin/roles/{id}` | Delete a role (`204`). |

**Groups** (admin) — identical shape: `POST`/`GET` (list)/`GET {id}`/`PUT {id}`/`DELETE {id}` under
`/admin/groups`.

**Principals — humans + service accounts** (admin)

| Method & path | Purpose |
| --- | --- |
| `POST /admin/humans` | Create a human (operator-chosen id, no secret) → `201`. |
| `POST /admin/service-accounts` | Create a service account (generated id + **one-time** secret) → `201`. |
| `POST /admin/service-accounts/authenticate` | Verify a service-account secret, return its resolution. Failure → generic `401 invalid_client`. |
| `GET /admin/principals` | List all accounts (secret hash omitted). |
| `GET /admin/principals/{id}` | Read one account (secret hash omitted). |
| `PUT /admin/principals/{id}/assignment` | Replace enabled flag, admin capability, memberships, roles, direct grants. |
| `DELETE /admin/principals/{id}` | Delete an account (`204`). |
| `GET /admin/principals/{id}/resolution` | Resolve to a mini-policy principal + effective grants. |

**Error mapping** (`ApiHandlers.guard`): an id collision (`IllegalStateException`) → `409`; bad input
or a dangling role/group reference (`IllegalArgumentException`) → `400`; an unknown id on a
read/update → `404`.

## Configuration

Flags override environment variables override defaults (mirrors mini-kms's / mini-idp's `ServerConfig`).

| Flag | Env var | Default | Meaning |
| --- | --- | --- | --- |
| `--host` | `MINIDIR_HOST` | `127.0.0.1` | Loopback bind host. |
| `--port` | `MINIDIR_PORT` | `8466` | TCP port (`0` = ephemeral; one above mini-idp's 8455 so the family doesn't collide locally). |
| `--data-dir` | `MINIDIR_DATA_DIR` | `$XDG_DATA_HOME/mini-directory` or `~/.mini-directory` | Directory holding `directory.json`. |
| `--admin-token-file` | `MINIDIR_ADMIN_TOKEN_FILE` | — | File holding the admin token (alt: `MINIDIR_ADMIN_TOKEN` env). |
| `--argon-memory-kib` | `MINIDIR_ARGON_MEMORY_KIB` | `65536` (64 MiB) | Argon2id memory cost for new service-account secrets. |
| `--argon-iterations` | `MINIDIR_ARGON_ITERATIONS` | `3` | Argon2id time cost (passes). |
| `--argon-parallelism` | `MINIDIR_ARGON_PARALLELISM` | `1` | Argon2id lanes. |

The admin token is resolved from `MINIDIR_ADMIN_TOKEN` or `--admin-token-file`, **never from a CLI
argument**, and is never logged. The Argon2 cost parameters apply to *new* hashes only; verifying an
existing hash always re-derives under the parameters stored *in that hash*, so a later cost bump never
locks existing service accounts out.

## Architecture

One application module under base package `com.codeheadsystems.minidirectory`:

- **`model/`** — the records: `Account`, `Group`, `Role`, the flat `GrantSpec`, `PrincipalKind`, and
  the resolution output `ResolvedPrincipal`.
- **`service/DirectoryService`** — the I/O-free heart: CRUD for accounts/groups/roles, `assign(...)`,
  `resolve(id)` (the expansion above), `authenticate(id, secret)` (no-oracle), and
  `importServiceAccount(...)` (the migration entry point). All methods are `synchronized` — the
  directory is small and writes are infrequent, so a single coarse lock keeps concurrent HTTP worker
  threads consistent. State is held in insertion-ordered in-memory maps and **persisted on every
  mutation**.
- **`secret/`** — `Argon2SecretHasher` / `SecretHash` / `Argon2Settings`: the family's Argon2id
  pattern. Only service accounts carry a hash; humans carry none.
- **`store/JsonStore`** — one `DirectoryDocument` (accounts + groups + roles) written atomically:
  temp-file → `ATOMIC_MOVE` → `0600`.
- **`server/`** — `ServerMain` / `DirectoryServer` (the composition root), `ServerConfig`,
  `ApiHandlers` (thin: validate → call the service → map to `HttpResponse`), `AdminAuthenticator`, the
  OpenAPI/Swagger serving, and the reused `http/` router. A JDK `com.sun.net.httpserver.HttpServer`
  binds loopback and runs **one virtual thread per request**.
- **`migration/ClientRegistryMigration`** — the one-time importer for mini-idp's old `clients.json`.

```
admin write:    POST /admin/{roles,groups,humans,service-accounts}  ─▶  DirectoryService  ─▶  directory.json (0600)
resolve:        GET  /admin/principals/{id}/resolution              ─▶  expand roles + groups, dedup  ─▶  Principal + [Grant]
authenticate:   POST /admin/service-accounts/authenticate           ─▶  Argon2id verify (no oracle)   ─▶  resolution
```

**Reuse over reinvention.** The `server/http` router, `AdminAuthenticator`, `OpenApiDocument`,
`SwaggerUiPage`, the Argon2 hasher, and `JsonStore` are deliberate copies of mini-idp's — the
documented **`mini-common` extraction candidates** — so the service is self-contained until that
library exists. The decision model is *not* copied: it depends on `:libs:mini-policy` and resolves
into its `Principal` / `Grant` / `GrantBasedPolicyEngine` types directly.

## Security notes

- **Argon2id** for service-account secrets (Bouncy Castle), each with a fresh 16-byte random salt and
  a 32-byte derived hash. A secret is returned exactly once at creation, stored only as a salted hash,
  and verified in constant time.
- **No credential oracle**: `authenticate` spends comparable effort on a dummy hash for unknown /
  human / secretless ids, so timing reveals nothing; failures collapse to one generic `401`.
- **No secret leakage**: the secret hash is never returned by the read API (every response uses the
  secret-free `AccountView`) and never logged; access logs carry only method/path/status. The
  generated secret `char[]` is zeroed after the (single) response is built.
- **At-rest**: `directory.json` is written atomically and `0600`.
- **Loopback by default**: `--host` to change is an explicit operator decision. The admin API is the
  whole API — there is no unauthenticated mutation surface beyond `/health` and the docs.
- **Validation**: id collisions → `409`; references to a missing role/group → `400`; blank ids/grants
  are rejected at the record boundary.

## Migrating mini-idp's client registry

mini-idp no longer keeps its own client registry — it reads service accounts from here. To bring
existing clients across, run the one-time migration, which turns each client record into a
`SERVICE_ACCOUNT` (preserving its id, Argon2id secret hash, enabled flag, and grants — a key-group
operation becomes a `{action: <KeyOperation>, resource: <keyGroup>}` grant, and the control flag
becomes `admin`) via `DirectoryService.importServiceAccount`:

```bash
# Stop mini-idp first. Then, against the directory's data dir:
java -cp services/mini-directory/build/install/mini-directory/lib/'*' \
  com.codeheadsystems.minidirectory.migration.ClientRegistryMigration \
  --clients-file ~/.mini-idp/clients.json --data-dir ~/.mini-directory
# -> "Migrated N client(s) into …/directory.json; skipped M already present."
```

It is **idempotent** (a re-run skips ids already present), reads `clients.json` as plain JSON (no
mini-idp dependency), and logs only ids + counts — never secrets. After migrating, point mini-idp at
this directory with `--directory-url`; existing client secrets keep working (the hash is imported
verbatim), and issued tokens are unchanged. Once verified, delete `clients.json`.

## Building & testing

```bash
./gradlew :services:mini-directory:test          # this module's tests
./gradlew :services:mini-directory:installDist    # runnable launcher under build/install/mini-directory/bin
./gradlew build                                   # compile + all tests across the family (the CI gate)
```

The test suite covers: role/group/account CRUD and the `409`/`400`/`404` mappings; the resolution
expansion (direct grants + role expansion + group inheritance + de-duplication, and tolerance of
dangling references); the no-oracle authenticate flow (unknown vs. wrong-secret vs. disabled all
collapse to one failure, with the dummy-hash timing path); the one-time secret being returned only at
creation and never in a read; the client-registry migration round-trip; and the OpenAPI spec being
served, parseable, and matching the live routes.
