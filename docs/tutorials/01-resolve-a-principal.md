# Lab 01 — Resolve a principal

> **Tutorial (hands-on, guaranteed to succeed).** Stage 1. ~10 minutes. You'll run mini-directory,
> create a role, a group, and a human, then **predict the resolved grant set by hand** before asking
> the service. This is the smallest *complete* idea in the family: identity → grants.
>
> **Concept behind it:** [`concepts/authorization-model.md`](../concepts/authorization-model.md).
> **Exact API:** mini-directory's `README.md` and `/docs` (Swagger UI) are authoritative — this lab
> links out rather than copying the full schema.

## What you need

- JDK 21+ and a green `./gradlew build` (the whole-family gate).
- `curl`. (Outputs below are pretty-printed JSON exactly as the service returns them.)

## 1. Build and start mini-directory

```bash
# from the repo root
./gradlew :services:mini-directory:installDist

export MINIDIR_ADMIN_TOKEN="$(openssl rand -hex 32)"   # admin token via env, never argv
services/mini-directory/build/install/mini-directory/bin/mini-directory \
  --port 8466 --data-dir "$(mktemp -d)"
```

It binds **loopback only** and prints its URL. In another shell, set up the variables the rest of
the lab uses:

```bash
B="http://127.0.0.1:8466"
H="Authorization: Bearer $MINIDIR_ADMIN_TOKEN"
curl -fsS "$B/health"        # => {"status":"ok"}
```

> The admin API is guarded by that bearer token. **Predict:** what status does a request with *no*
> `Authorization` header get? (Answer at the end of step 4.)

## 2. Build the org chart

We'll model a sliver of the homelab scenario the later labs reuse: protecting `grafana`. Create two
**roles** (named bundles of grants), a **group** that carries a role plus a direct grant, then a
**human** who pulls from all of it.

```bash
# Two roles — each a named bundle of (action, resource) grants
curl -fsS -X POST "$B/admin/roles" -H "$H" -H 'Content-Type: application/json' \
  -d '{"id":"grafana-viewer","description":"read-only Grafana","grants":[{"action":"view","resource":"grafana"}]}'

curl -fsS -X POST "$B/admin/roles" -H "$H" -H 'Content-Type: application/json' \
  -d '{"id":"grafana-editor","description":"edit Grafana dashboards","grants":[{"action":"edit","resource":"grafana"}]}'

# A group: carries the grafana-viewer role AND a direct grant of its own
curl -fsS -X POST "$B/admin/groups" -H "$H" -H 'Content-Type: application/json' \
  -d '{"id":"observability","description":"obs team","roles":["grafana-viewer"],"grants":[{"action":"view","resource":"prometheus"}]}'

# A human: member of the group, assigned the grafana-editor role directly, plus one direct grant
curl -fsS -X POST "$B/admin/humans" -H "$H" -H 'Content-Type: application/json' \
  -d '{"id":"alice","displayName":"Alice","admin":false,"memberOf":["observability"],"roles":["grafana-editor"],"grants":[{"action":"view","resource":"logs"}]}'
```

Each call echoes the stored record. Note Alice carries no secret — **humans authenticate with
passkeys, not secrets** (that's stage 4); her record is pure authorization data.

## 3. Predict before you resolve

Alice's *effective* grants are everything that flows into her from all three sources.
**Before running the next command, write down the set you expect.** Work it out from the
[resolution rule](../concepts/authorization-model.md#where-the-grants-come-from-resolution):

```
alice's direct grants .......... view:logs
+ alice's direct roles ......... grafana-editor → edit:grafana
+ her group's direct grants .... observability  → view:prometheus
+ her group's roles ............ grafana-viewer → view:grafana
```

So you should predict **four** grants. Also predict their **order** — the resolver flattens
direct-grants → direct-roles → group-grants → group-roles, de-duplicated, first-seen order kept.

## 4. Resolve, and check your prediction

```bash
curl -fsS "$B/admin/principals/alice/resolution" -H "$H"
```

```json
{
  "id" : "alice",
  "admin" : false,
  "grants" : [ {
    "action" : "view",
    "resource" : "logs"
  }, {
    "action" : "edit",
    "resource" : "grafana"
  }, {
    "action" : "view",
    "resource" : "prometheus"
  }, {
    "action" : "view",
    "resource" : "grafana"
  } ]
}
```

That's a mini-policy [`ResolvedPrincipal`](../GLOSSARY.md#identity--authorization): a `Principal`
(`{id, admin}`) plus the flattened `Grant` list — **exactly the input a decision function consumes.**
The order is the resolver's: `logs` (direct) → `edit grafana` (direct role) → `prometheus` (group
grant) → `view grafana` (group role). Did your prediction match?

**The two edge cases (predict, then verify):**

```bash
# No Authorization header:
curl -s -o /dev/null -w "%{http_code}\n" "$B/admin/principals/alice/resolution"   # => 401

# A principal that doesn't exist:
curl -s -o /dev/null -w "%{http_code}\n" "$B/admin/principals/nobody/resolution" -H "$H"   # => 404
```

## What you just learned

- **Resolution is the authN→authZ handoff.** A stored identity (roles, groups, direct grants)
  becomes one flat `Principal` + grant set. The org-chart expansion lives in the *directory*; the
  *decision* over those grants lives in mini-policy — two jobs, two homes.
- **Roles and groups are just grant bundles.** Nothing magic — they expand to the same flat grants a
  human could hold directly. De-duplication means overlap is free.
- **This is the input to `decide(...)`.** In the next labs, a token will *carry* this principal and a
  policy engine will decide over these grants.

## Try it yourself (optional)

- Add `grafana-editor`'s grant to `alice` *directly* as well, re-resolve, and confirm dedup keeps
  `edit:grafana` once.
- Give Alice `"admin": true` (via `PUT /admin/principals/alice/assignment`) and re-read the concept
  doc's "admin bypass" rule — what would a `GrantBasedPolicyEngine` now decide for *any* action?
- Delete the `grafana-viewer` role, then re-resolve Alice. The dangling reference is **skipped, not
  fatal** — `view:grafana` simply disappears. (See `resolve(...)` in `DirectoryService`.)

Next: stage 2, [`02-build-and-verify-a-token-by-hand.md`](02-build-and-verify-a-token-by-hand.md) —
the keystone. How that principal travels as a signed token, and how a verifier checks it offline.
