# mini-policy

The family's **authorization decision function** — one tiny, dependency-free library that answers a
single question for every service: *may **this** principal perform **this** action on **this**
resource?* It is the shared replacement for the per-service authorization checks the family used to
hand-roll (mini-kms's former per-key-group key policy; the per-group grant checks a verifier ran
over a mini-idp token).

> ⚠️ **Educational, un-audited.** Real authorization logic, deliberately small and heavily
> read-first. Part of the [mini-auth](../../README.md) family — see [`docs/DIRECTION.md`](../../docs/DIRECTION.md)
> for the whole map and [`docs/GLOSSARY.md`](../../docs/GLOSSARY.md#identity--authorization) for the
> vocabulary. **Library only — no transport, no HTTP, no CLI.**

## The whole idea

Authorization here is **one pure function**, reused everywhere:

```
decide(principal, action, resource) → ALLOW | DENY
```

No request object, no database call, no I/O. Given *who* (`Principal`), *what verb* (`Action`), and
*what thing* (`Resource`), it returns one bit. Scopes, key-group rules, and forward-auth routes are
all that same function with different strings plugged into `action` and `resource`. That is why one
engine can serve mini-directory, mini-oidc, mini-gateway, and mini-kms.

## The model (five value types + a seam)

Base package `com.codeheadsystems.minipolicy`. Everything is a small record or enum:

| Type | Is | Notes |
| --- | --- | --- |
| `Principal` | the authenticated caller | `(String id, boolean admin)`. `id` is a token's `sub`; `admin` is the control capability. |
| `Action` | the verb | `(String value)`; `Action.ANY` is the `*` wildcard. |
| `Resource` | the thing | `(String value)`; `Resource.ANY` is the `*` wildcard. |
| `Grant` | one permission | `(Action, Resource)` with `permits(action, resource)` honoring wildcards. |
| `Decision` | the answer | `ALLOW` or `DENY` — binary on purpose. |
| `PolicyEngine` | the seam | `Decision decide(Principal, Action, Resource)`. |

`Action` and `Resource` are opaque strings *on purpose*: today an action might be a key operation
(`ENCRYPT`), tomorrow an OIDC scope verb or an HTTP method — **with no change to the engine.**

## The engines

- **`GrantBasedPolicyEngine`** — the real one. Three rules, in order:
  1. **Admin bypass** — `if (principal.admin()) return ALLOW;`
  2. **Match a grant** — ALLOW iff some grant the principal holds `permits(action, resource)`.
  3. **Deny by default** — fall off the end → `DENY`. *Anything not explicitly granted is refused,*
     enforced by the loop's structure, not by a check someone has to remember to write.
- **`DenyAllPolicyEngine`** — refuses everything; the safe default for an unconfigured generic service.
- **`AllowAllPolicyEngine`** — permits everything; safe *only* where another layer already gates the
  door. mini-kms ships this on its data plane today (a single shared per-plane token ⇒ one
  principal; key groups still isolate).

The `AllowAll` / `DenyAll` contrast is itself the lesson: **opposite defaults for opposite
situations.** Picking the wrong one is how authorization bugs are born.

## Who consumes it

| Consumer | Uses it for |
| --- | --- |
| [mini-directory](../../services/mini-directory) | resolves an account into a `Principal` + a de-duplicated set of `Grant`s (the input a decision needs). |
| [mini-oidc](../../services/mini-oidc) | authorizes requested **scopes** via `GrantBasedPolicyEngine` (`ScopeAuthorizer`). |
| [mini-gateway](../../services/mini-gateway) | decides per-route (`SCOPE` rules) and denies by default. |
| [mini-kms](../../services/mini-kms) | the data-plane authorization seam (ships `AllowAllPolicyEngine`). |

## Wired vs. designed

This library is deliberately **minimal: it evaluates the grants it is handed.** *Sourcing* those
grants family-wide is integration work that lives in the consuming services, not here:

- mini-directory → issuer grant resolution is **wired** (mini-idp resolves service accounts; mini-oidc
  resolves humans).
- The **token → mini-kms** authorization path (a JWT's `grants` claim feeding a per-key-group
  `GrantBasedPolicyEngine`) is **designed but not yet wired** — mini-kms still authenticates with a
  shared per-plane token and ships `AllowAllPolicyEngine`. See the "Wired vs. designed" note in
  [`docs/DIRECTION.md`](../../docs/DIRECTION.md#runtime-relationships) and
  [`docs/concepts/honest-seams.md`](../../docs/concepts/honest-seams.md).

## Reading order

`Principal`, `Action`, `Resource`, `Grant` (note `Grant#permits`), `Decision`, then the
`PolicyEngine` interface, then `GrantBasedPolicyEngine#decide` (the three rules) and the trivial
`AllowAllPolicyEngine` / `DenyAllPolicyEngine`. The concept doc
[`authorization-model.md`](../../docs/concepts/authorization-model.md) builds the idea from zero;
the lab [`01-resolve-a-principal.md`](../../docs/tutorials/01-resolve-a-principal.md) makes you
predict a decision by hand.

## Build & test

Part of the aggregator build — run from the repo root:

```bash
./gradlew :libs:mini-policy:test     # this library's tests
./gradlew build                      # the whole family (the CI gate)
```
