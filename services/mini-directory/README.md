# mini-directory

The single **identity source of truth** for the mini- family: it owns **humans**, **service
accounts**, **groups**, and **roles**, plus the grant mappings between them — and resolves any
account into the inputs a [`mini-policy`](../../libs/mini-policy) decision function consumes.

It is **educational, but homelab-functional**, and mirrors the conventions of its siblings
(mini-kms, mini-idp): a loopback HTTP service, an admin API behind a bootstrap bearer token, an
atomic-`0600` JSON store, no secrets in logs, and an OpenAPI spec served with a vendored Swagger UI.

> **Standalone for now.** mini-oidc (humans) and mini-idp (service accounts) are *intended* to read
> identities and grants from here, but that wiring is deliberately future work — today the service
> stands alone. See `docs/DIRECTION.md`.

## The model

| Record | What it is |
| --- | --- |
| **Account** | A resolvable identity — a `HUMAN` or a `SERVICE_ACCOUNT`. Its `id` becomes a mini-policy `Principal` id (and a future token `sub`); its `admin` flag becomes the control/admin capability. Holds direct grants, role assignments, and group memberships. A service account additionally has an Argon2id secret hash; a human has none. |
| **Role** | A named bundle of grants. Assigning a role grants every permission it carries. |
| **Group** | A named bundle of roles + direct grants that accounts join (`memberOf`) to inherit authorization. |
| **GrantSpec** | One permission as a flat `{ "action": "...", "resource": "..." }` pair — the JSON-friendly mirror of a mini-policy `Grant`. Either coordinate may be the wildcard `"*"`. |

## Resolution (the point of the service)

`GET /admin/principals/{id}/resolution` resolves an account into a mini-policy `Principal` plus its
**effective grants**, computed as the de-duplicated union of:

```
account.grants
  ∪  grants of each role in account.roles
  ∪  for each group in account.memberOf:  group.grants  ∪  grants of each role in group.roles
```

Roles expand to grants; group memberships are inherited. The resulting `(Principal, [Grant])` plugs
straight into a `GrantBasedPolicyEngine` — an `admin` principal is permitted everything; otherwise a
request is allowed iff some grant permits that `(action, resource)`. Dangling role/group references
are tolerated (skipped), never fatal.

## Run it locally

The bootstrap admin token comes from an env var or a file — **never a CLI arg, and never logged**.

```bash
export MINIDIR_ADMIN_TOKEN="$(openssl rand -hex 32)"
./gradlew :services:mini-directory:installDist
services/mini-directory/build/install/mini-directory/bin/mini-directory --port 8466 --data-dir ~/.mini-directory
```

```bash
B=http://127.0.0.1:8466; H="Authorization: Bearer $MINIDIR_ADMIN_TOKEN"
curl -s -XPOST $B/admin/roles -H "$H" \
  -d '{"id":"billing-operator","grants":[{"action":"ENCRYPT","resource":"billing"}]}'
curl -s -XPOST $B/admin/groups -H "$H" -d '{"id":"finance","roles":["billing-operator"]}'
curl -s -XPOST $B/admin/humans -H "$H" -d '{"id":"alice","memberOf":["finance"]}'
curl -s $B/admin/principals/alice/resolution -H "$H"
#  => {"id":"alice","admin":false,"grants":[{"action":"ENCRYPT","resource":"billing"}]}
```

## API

All `/admin/**` endpoints require `Authorization: Bearer <admin-token>`. Full contract: `/openapi.yaml`,
`/openapi.json`, Swagger UI at `/docs`.

| Method + path | Purpose |
| --- | --- |
| `GET /health` | Liveness (public). |
| `POST /admin/roles` · `GET /admin/roles` · `GET/PUT/DELETE /admin/roles/{id}` | Role CRUD. |
| `POST /admin/groups` · `GET /admin/groups` · `GET/PUT/DELETE /admin/groups/{id}` | Group CRUD. |
| `POST /admin/humans` | Create a human (operator-chosen id, no secret). |
| `POST /admin/service-accounts` | Create a service account (generated id + **one-time** secret). |
| `GET /admin/principals` · `GET/DELETE /admin/principals/{id}` | List / read / delete accounts. |
| `PUT /admin/principals/{id}/assignment` | Replace an account's enabled flag, admin capability, group memberships, roles, and direct grants. |
| `GET /admin/principals/{id}/resolution` | Resolve to a mini-policy principal + effective grants. |

## Security notes

- **Argon2id** for service-account secrets (Bouncy Castle); each secret is returned exactly once at
  creation, stored only as a salted hash, and verified in constant time with no credential oracle.
- **No secrets in logs**; access logs record method/path/status only.
- **Loopback bind by default** (`--host` to change — an explicit operator decision).
- **Atomic `0600` store**: `directory.json` is written temp-file → `ATOMIC_MOVE` → `0600`.
- Id collisions return `409`; references to a missing role/group return `400`.
