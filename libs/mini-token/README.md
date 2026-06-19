# mini-token

The family's shared **token plane**: the Ed25519-signed JWS/JWT machinery, the JWKS model, the
signing-key lifecycle (rotation), the revocation denylist, the audit log, the published `grants`
claim contract, a small persistence SPI, **and** the shared browser-SSO session store. It was
**extracted from mini-idp** so both issuers — [mini-idp](../../services/mini-idp) (machine
client-credentials) and [mini-oidc](../../services/mini-oidc) (human SSO) — share one implementation
instead of drifting into two.

> ⚠️ **Educational, un-audited.** Real crypto (JDK Ed25519 only — no third-party crypto dependency),
> with a **hand-rolled** compact JWS that exists to be *read*. Part of the [mini-auth](../../README.md)
> family; see [`docs/DIRECTION.md`](../../docs/DIRECTION.md) for the map and
> [`docs/GLOSSARY.md`](../../docs/GLOSSARY.md#tokens-jose-oauth-20-openid-connect) for the JOSE/OAuth
> vocabulary. **Library only — no transport, no HTTP, no CLI** (mirrors the siblings' I/O-free `core`).

## What's inside

Base package `com.codeheadsystems.minitoken`.

- **`token/`** — the hand-rolled JOSE layer. `Base64Url`, `JwsHeader` (alg/typ/kid), `JwtClaims`
  (the standard claim set), and `Jws` — the keystone. **`Jws.sign` signs the
  `base64url(header).base64url(payload)` *text*, never re-serialized JSON**, so verification
  recomputes the exact bytes. There are two overloads: a typed `sign(JwsHeader, JwtClaims,
  PrivateKey)` (mini-idp's path) and an additive generic `sign(JwsHeader, Map<String,?>,
  PrivateKey)` (so mini-oidc's ID/access claim sets sign with the same format + keys). `GrantsClaim`
  is the stable `grants` authorization contract; `JwsClaimsVerifier` is the offline reference
  verifier (pin `alg` + select key by `kid` → check signature → validate `iss`/`aud`/time; any
  failure returns empty — **no oracle**).
- **`crypto/Ed25519Keys`** — Ed25519 keygen / encode / decode via the JDK only.
- **`jwks/`** — `Jwk` + `JwkSet`: the published set of **public** keys (`OKP`/`Ed25519`) so any
  verifier checks signatures **offline**, with no callback to the issuer.
- **`service/`** — the lifecycle services over the persistence SPI:
  - `SigningKeyService` — one active key + rotation (`rotate()`, `activeKid()`); retired keys stay
    published in the JWKS until they outlive the token TTL, so in-flight tokens still verify.
  - `TokenIssuer` — `issue(subject, Authorization) → IssuedToken`; signs through `Jws` with the
    active key.
  - `TokenVerifier` — `verify(token, jwkSet, isRevoked) → Result`: pin `alg` + select the key by
    `kid`, verify the signature, then `iss`/`aud`/time, then revocation.
  - `RevocationService` — a `jti` denylist (the early kill switch; short TTLs are the primary control).
  - `AuditService` — an append-only issuance/rotation audit log.
- **`session/`** — `SessionService` (+ `BrowserSession`, `Sessions`): the **shared browser-SSO
  session**, over the same `DocumentStore` SPI. The cookie name is the shared
  `SessionService.DEFAULT_COOKIE_NAME` (`mioidc_session`); session ids are stored only as their
  SHA-256. **mini-oidc is the sole writer; mini-gateway is a reader of the same file** — there is
  exactly one session mechanism in the family.
- **`store/DocumentStore<T>`** — the persistence **SPI** (`exists()` / `load()` / `save(T)`). The
  services depend only on this, never on a concrete store. mini-idp backs it with an atomic,
  owner-only (`0600`) JSON file; mini-kms's `KmsSigningKeyStore` decorates it to envelope-wrap
  signing keys at rest.
- **`auth/`** — the authorization model the `grants` claim maps onto: `Authorization`, `Grant`,
  `KeyOperation` (the deliberate string mirror of mini-kms's operations — **do not rename the
  values**, they are the contract).

## The contract

The `grants` claim (`token/GrantsClaim` over `auth/Authorization`) is the family's stable JSON
contract; it maps onto mini-kms's authorization model: `sub → Principal.id`, `grants.control →
Principal.admin`, and `grants.groups[]` → a per-key-group `PolicyEngine` decision (mini-policy). The
string values of `auth/KeyOperation` are part of that contract. **Note this is a *designed* mapping:**
the token → mini-kms authorization step is not yet the live runtime path — see the "Wired vs.
designed" note in [`docs/DIRECTION.md`](../../docs/DIRECTION.md#runtime-relationships).

## Who consumes it

| Consumer | Uses |
| --- | --- |
| [mini-idp](../../services/mini-idp) | `SigningKeyService` + `TokenIssuer` (typed claims), `RevocationService`, `AuditService`, `JwkSet`. |
| [mini-oidc](../../services/mini-oidc) | the same keys + `Jws` generic-`sign` overload for ID/access tokens; `JwsClaimsVerifier`; `SessionService` (writer). |
| [mini-gateway](../../services/mini-gateway) | `JwsClaimsVerifier` against the OP's JWKS; `SessionService` (reader of the shared `sessions.json`). |
| [mini-ca](../../services/mini-ca) | persists its CA key as a one-record `SigningKeys` document through the `DocumentStore` SPI. |

## Dependencies

Jackson is on the **api** classpath (the JWKS document and claim records (de)serialize through it,
exactly as in mini-idp). All crypto is the JDK's Ed25519 — no third-party crypto dependency.

## Reading order

Walk `token/` in the package-doc order — `Base64Url` → `JwsHeader`/`JwtClaims` → **`Jws`** (read the
load-bearing comment on *what gets signed*) → `JwsClaimsVerifier` → `GrantsClaim`. Then
`crypto/Ed25519Keys`, `jwks/Jwk`+`JwkSet`, `service/SigningKeyService` (rotation), and
`session/SessionService`. The concept doc
[`what-a-token-is.md`](../../docs/concepts/what-a-token-is.md) and the keystone lab
[`02-build-and-verify-a-token-by-hand.md`](../../docs/tutorials/02-build-and-verify-a-token-by-hand.md)
make it concrete — you verify an Ed25519 signature yourself, then flip a byte and watch it fail.

## Build & test

Part of the aggregator build — run from the repo root:

```bash
./gradlew :libs:mini-token:test      # this library's tests
./gradlew build                      # the whole family (the CI gate)
```
