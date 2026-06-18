# 01 — No-oracle service-account authentication

**Severity:** Medium (account enumeration via a timing oracle)
**Status:** ✅ Fixed (dummy verify now costs the same as a real one)

**Affected code:**
- `service/DirectoryService.java` — `authenticate`
- `secret/Argon2SecretHasher.java` — `dummyHash`, `verify`

## What the issue is

mini-idp resolves a service account by calling the directory's `authenticate`
endpoint; every failure collapses to one generic error at the HTTP layer (no
*content* oracle). To avoid a *timing* oracle, an unknown id is supposed to incur
the same Argon2 work as a wrong secret for a known account — otherwise "account
exists" is observably slower than "no such account."

The defense was present in shape but defeated by its parameters. The dummy hash
used **deliberately tiny** Argon2 cost, while real service-account hashes use the
configured (heavy) cost:

```java
// DirectoryService (before) — a fixed dummy with toy parameters
private static final SecretHash DUMMY_HASH = new SecretHash(
    SecretHash.ALGORITHM_ARGON2ID, "AAAA…==", "AAAA…=", 8, 1, 1);   // 8 KiB, t=1, p=1
...
hasher.verify(secret, DUMMY_HASH);   // ~microseconds
```

Argon2 cost is dominated by `memory × iterations`. Verifying against the real
stored hash (e.g. 64 MiB, t=3) takes *hundreds of times longer* than verifying
against the 8 KiB/t=1 dummy. So:

- **unknown id / human / secretless** → cheap dummy verify (sub-millisecond)
- **known service account, wrong secret** → full-cost Argon2 (much slower)

A second, subtler leak: the known-account path short-circuited on `enabled()`
*before* running Argon2, so a **disabled** known account also returned fast —
distinguishable from a wrong secret.

## The threat it poses

An attacker hitting `/admin/service-accounts/authenticate` (reachable with any
issuer/admin token — e.g. a compromised mini-idp) can **enumerate valid service
account ids purely by response latency**: slow means "this id exists and is an
enabled service account," fast means "unknown / human / disabled." Enumeration is
the first half of a credential attack; the no-oracle property is supposed to deny
it, and the toy parameters quietly gave it back.

## The fix

The dummy hash is now built from the **hasher's own configured cost**, so a
dummy verify does the same Argon2 work as a real one; and the known-account path
always runs `verify` before consulting `enabled()`.

### After

```java
// Argon2SecretHasher.dummyHash() — a throwaway hash carrying THIS hasher's real cost params
public SecretHash dummyHash() {
  final Base64.Encoder b64 = Base64.getEncoder();
  return new SecretHash(SecretHash.ALGORITHM_ARGON2ID,
      b64.encodeToString(new byte[SALT_LENGTH_BYTES]),
      b64.encodeToString(new byte[HASH_LENGTH_BYTES]),
      settings.memoryKiB(), settings.iterations(), settings.parallelism());
}

// DirectoryService — built once at construction from the configured hasher
this.dummyHash = hasher.dummyHash();

// DirectoryService.authenticate
if (account == null || account.kind() != SERVICE_ACCOUNT || account.secretHash() == null) {
  hasher.verify(secret, dummyHash);          // same Argon2 cost as a real verify
  return Optional.empty();
}
// Always run the (expensive) verify before checking enabled(), so disabled is not
// distinguishable from wrong-secret by timing either.
final boolean secretOk = hasher.verify(secret, account.secretHash());
return (account.enabled() && secretOk) ? Optional.of(account) : Optional.empty();
```

The dummy's salt and hash are all-zero and no real secret hashes to them, so it
authenticates nothing — it exists only to spend the time.

## Why the fix works

`verify` re-derives Argon2 using the parameters carried in the `SecretHash` it is
given (so a later cost bump never locks out existing clients). By giving the dummy
the hasher's *current* configured parameters, the unknown-id path performs the
same memory-hard derivation as a wrong-secret-for-known-id path — the dominant
cost term is now identical, so the latency classes converge. Running `verify`
before `enabled()` removes the disabled-account short-circuit. The comparison
itself was already constant-time (`MessageDigest.isEqual`), so no byte-level
oracle existed; this closes the remaining *existence* oracle.

> **Residual nuance.** A stored hash keeps the parameters it was created with, so
> if the configured cost is changed, an *old* account's verify cost can differ
> slightly from the dummy's (which uses current settings). The dominant term still
> matches; the previous gap was orders of magnitude, this is noise.

## Tests

`service/DirectoryServiceTest.java` covers `authenticate`: a correct secret for an
enabled service account succeeds; a wrong secret, an unknown id, a human, and a
disabled account all return empty. The timing equivalence itself is a parameter
property (dummy cost == configured cost) rather than a unit assertion — verify
with a microbenchmark if changing the Argon2 settings.
