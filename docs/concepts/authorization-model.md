# The authorization model — a decision is a pure function

> **Concept doc (explanation).** Stage 1. Anchored on **mini-policy** and **mini-directory**. New
> terms link to [`GLOSSARY.md`](../GLOSSARY.md); the rationale for one shared engine lives in
> [`DIRECTION.md`](../DIRECTION.md). Pairs with the lab
> [`tutorials/01-resolve-a-principal.md`](../tutorials/01-resolve-a-principal.md).

Authorization in this family is **one function**, reused everywhere:

```
decide(principal, action, resource) → ALLOW | DENY
```

That's it. No request object, no database call, no I/O. Given *who* (`principal`), *what verb*
(`action`), and *what thing* (`resource`), it returns one bit. Everything else — scopes, key-group
rules, forward-auth routes — is that same function with different strings plugged into `action` and
`resource`.

---

## The five nouns

mini-policy is deliberately tiny. Five records and an interface:

| Type | Is | Note |
| --- | --- | --- |
| [`Principal`](../GLOSSARY.md#identity--authorization) | the authenticated caller | `(id, admin)`. `id` is a token's `sub`; `admin` is the control capability. |
| [`Action`](../GLOSSARY.md#identity--authorization) | the verb | opaque string; `Action.ANY` is the `*` wildcard. |
| [`Resource`](../GLOSSARY.md#identity--authorization) | the thing | opaque string; `Resource.ANY` is the `*` wildcard. |
| [`Grant`](../GLOSSARY.md#identity--authorization) | one permission | an `(action, resource)` pair, with `permits(...)` honoring wildcards. |
| `Decision` | the answer | `ALLOW` or `DENY` — binary on purpose. |

`Action` and `Resource` are *opaque to the engine on purpose.* Today an action is a mini-kms
`KeyOperation` (`ENCRYPT`, `DECRYPT`, …); tomorrow it can be an HTTP method, an OIDC scope verb, or
a directory operation — **with no change to the decision function.** That opacity is why one engine
serves every service.

---

## The three rules of `GrantBasedPolicyEngine`

The real engine is `GrantBasedPolicyEngine`. Its entire decision is three rules, in order — worth
reading the actual method, it's ~10 lines:

1. **Admin bypass.** `if (principal.admin()) return ALLOW;` — the control capability is permitted
   everything. (This mirrors a token's `grants.control ⇒ full authority`.)
2. **Match a grant.** Otherwise, ALLOW iff *some* grant the principal holds `permits(action,
   resource)` — where `permits` treats `Action.ANY`/`Resource.ANY` as wildcards.
3. **Deny by default.** Fall off the end → `DENY`. Anything not explicitly granted is refused.

**Deny-by-default is the load-bearing rule.** A principal with no grants can do nothing. A typo in
an action name doesn't accidentally widen access — it silently fails closed. This is the single
most important security property of the model, and it's enforced by the *structure* (the loop
returns DENY when nothing matches), not by a check someone has to remember to write.

Deny-by-default is the *mechanism*; the *principle* behind it is **[least privilege](../GLOSSARY.md#identity--authorization)** — give each principal the minimum authority it needs and no more. That's why grants
are narrow `(action, resource)` pairs rather than broad roles, and why you should be sparing with the
`*` wildcards and with the admin bypass below: each one is standing authority that turns a single
compromise into a wide one. Admin-bypass is a deliberate, blunt capability — fine for the family's
small surface, but in a larger system a global "admin can do anything" bit is itself a least-privilege
violation and a fat target, usually replaced by scoped admin grants.

### The two trivial engines, and why both exist

- `AllowAllPolicyEngine` — permits everything. mini-kms ships this today (a single shared data-plane
  token means one principal; key groups still isolate). It is safe *only because another layer
  already gates the door.*
- `DenyAllPolicyEngine` — refuses everything. The safe default for an unconfigured generic service.

The contrast is the lesson: **allow-all and deny-all are opposite defaults for opposite
situations.** A generic engine with no rules configured must deny (fail closed); a service whose
door is already gated elsewhere may allow. Picking the wrong default is how authorization bugs are
born.

> **⚠ Wired vs. designed.** mini-kms's data plane ships `AllowAllPolicyEngine` — per-client key
> authorization is **designed, not wired**. See [`honest-seams.md`](honest-seams.md#2).

---

## Where the grants come from: resolution

The engine decides, but it doesn't *invent* a principal's grants — it's handed them. Producing them
is **mini-directory's** defining job, called **resolution**.

A stored account isn't a flat list of permissions. It has:

- **direct grants** (attached to the account),
- **assigned roles** (a role is a named bundle of grants),
- **group memberships** (a group confers its own grants *plus* its roles' grants to every member).

`DirectoryService.resolve(id)` flattens all of that into one `ResolvedPrincipal` = a mini-policy
`Principal` + a **de-duplicated, first-seen-ordered** list of `Grant`s:

```
account.grants
  ∪  grants of each assigned role
  ∪  for each group the account is in:  group.grants  ∪  grants of the group's roles
  ──────────────────────────────────────────────────────────────────────────────────
  =  the effective grant set   (dups removed, order preserved)
```

Two details worth internalizing, both visible in `resolve(...)`:

- **Dangling references are skipped, not fatal.** If an account still cites a deleted role, that role
  contributes nothing — it can't break resolution. (Failing closed again.)
- **Roles expand to grants here, not in the engine.** The engine only ever sees flat `Grant`s. The
  *expansion* (the org-chart logic) lives in the directory; the *decision* (does any grant match)
  lives in the policy engine. Two jobs, two homes.

`GrantSpec` is the JSON-friendly wire/stored mirror of a `Grant` (`{"action": "...", "resource":
"..."}`); `toPolicyGrant()` converts it to the exact type the engine evaluates. The `"*"` string
*is* the wildcard — `Action.of("*").equals(Action.ANY)`.

---

## Now read it

- **The decision function (read these five small files first):**
  `libs/mini-policy` → `Principal`, `Action`, `Resource`, `Grant` (note `Grant#permits`), `Decision`,
  the `PolicyEngine` interface, then `GrantBasedPolicyEngine#decide` (the three rules) and the
  trivial `AllowAllPolicyEngine` / `DenyAllPolicyEngine`.
- **Resolution (identity → grants):**
  `services/mini-directory` → `service/DirectoryService#resolve` (the flatten/dedup), the `model`
  records `Account` / `Group` / `Role` / `GrantSpec` / `ResolvedPrincipal`.

Now do the lab: [`tutorials/01-resolve-a-principal.md`](../tutorials/01-resolve-a-principal.md) — you
build a role, a group, and a human, then **predict the resolved grant set by hand** before asking
the service. Then continue to stage 2,
[`what-a-token-is.md`](what-a-token-is.md) — how that principal travels.
