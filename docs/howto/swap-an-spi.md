# How-to: swap an SPI

> **How-to (task-oriented).** Extend the family at its designed seams: implement a `PolicyEngine`,
> swap a `DocumentStore`, a `UserDirectory`, a `ServiceAccountDirectory`, and the rest. Concept of an
> [SPI](../GLOSSARY.md#architecture--patterns): an interface the composition root injects an
> implementation of. The shipped impls are real; the in-memory ones are documented test/dev seams.

## The seams, and where to wire them

| SPI (interface) | Module | Decides / provides | Shipped impls |
| --- | --- | --- | --- |
| `PolicyEngine` | `libs/mini-policy` | the authorization decision | `GrantBasedPolicyEngine`, `AllowAllPolicyEngine`, `DenyAllPolicyEngine` |
| `DocumentStore` | `libs/mini-token` | persist a typed document | `JsonStore` (atomic `0600`), `KmsSigningKeyStore` (KMS-wrapping decorator) |
| `UserDirectory` | `services/mini-oidc` | resolve a human → principal + grants + profile | `HttpUserDirectory`, `InMemoryUserDirectory` |
| `ServiceAccountDirectory` | `services/mini-idp` | resolve a service account | `HttpServiceAccountDirectory`, `InMemoryServiceAccountDirectory` |
| `HumanAuthenticator` | `services/mini-oidc` | run the passkey ceremony | `PkAuthHumanAuthenticator` |
| `JwksProvider` | `services/mini-gateway` | fetch the OP's JWKS | `HttpJwksProvider` (+ injectable in tests) |
| `MasterKeyProvider` / `KeyringManager` | `services/mini-kms` | data-plane crypto / control-plane key mgmt | `LocalKeyring` (both); the remote/HSM drop-in seam |

**Where you wire it:** the composition root — the `*Server` / `ServerMain` of each service. `core` /
library code never constructs a concrete impl; it takes the interface. So a swap is a one-line change
at the root, not a refactor.

## Example: a custom `PolicyEngine`

`PolicyEngine` is a `@FunctionalInterface` — a custom rule can be a lambda:

```java
// deny writes to anything tagged "prod" unless the principal is admin; else fall back to grants
PolicyEngine guarded = (principal, action, resource) -> {
  if (!principal.admin() && action.value().equals("write") && resource.value().startsWith("prod:")) {
    return Decision.DENY;
  }
  return base.decide(principal, action, resource);   // delegate to a GrantBasedPolicyEngine
};
```

Wire `guarded` where the service builds its engine. Keep the family's invariant: **deny by default** —
your engine must refuse anything it doesn't explicitly allow (see
[`authorization-model.md`](../concepts/authorization-model.md)).

## Example: a persistent `DocumentStore`

`JsonStore` is a flat-file atomic store. To back documents with, say, a database, implement
`DocumentStore<T>`'s round-trip and inject it at the composition root. Two rules to preserve:

- **Atomic + owner-only.** Whatever you persist to, don't leave half-written or world-readable state
  (the [at-rest invariant](../concepts/secure-design-invariants.md)).
- **Decorators compose.** `KmsSigningKeyStore` is itself a `DocumentStore` that *wraps* another one
  (envelope-encrypting before delegating). You can layer the same way — e.g. a caching or auditing
  decorator over your persistent store.

## Example: a persistent passkey store

mini-oidc's `PasskeyStack` assembles pk-auth over **in-memory** credential SPIs (so passkeys don't
survive a restart — [honest seam #5](../concepts/honest-seams.md#5)). `PasskeyStack` is the documented
swap point: provide persistent pk-auth `CredentialRepository` / `UserLookup` / `ChallengeStore`
implementations and assemble the stack over those instead.

## The discipline for any swap

1. **Implement the interface**, nothing more — don't reach around it.
2. **Inject at the composition root** (`*Server`/`ServerMain`); leave `core`/library code untouched.
3. **Preserve the invariants** the shipped impl upheld: deny-by-default, no-oracle, atomic-`0600`,
   constant-time secret compares. The interface defines the *shape*; the
   [invariants](../concepts/secure-design-invariants.md) define the *contract*.
4. **Keep the seam honest:** if your impl is a dev/test stand-in, say so (the family names its
   in-memory impls exactly so nobody mistakes them for production).
