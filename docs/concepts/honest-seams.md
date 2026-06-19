# Honest seams — designed, but not (yet) wired

> **Concept doc (explanation). Required reading before any deep trace.** This is the single most
> important *correctness* page in the course. It lists the paths that are **designed but not live**,
> so a lab never sends you to trace something through running code that the running code doesn't
> actually do.

The `mini-` family is honest about its scaffolds. [`DIRECTION.md`](../DIRECTION.md) has a "Wired vs.
designed" note; the service sections of [`CLAUDE.md`](../../CLAUDE.md) flag the same seams. This doc
collects them in one place and, where it matters, names the exact symbol so you can confirm the seam
yourself.

Throughout the course, any doc that touches one of these carries the standard callout:

> **⚠ Wired vs. designed.** *<the specific seam>* is **designed, not wired**. See
> [`honest-seams.md`](honest-seams.md#N).

A "seam" here is a deliberate, well-marked swap point or future hook — not a bug. The lesson is
itself pedagogical: a real system grows by wiring its seams, and naming them honestly is how you
keep a teaching codebase from quietly lying.

---

## <a id="1"></a>1. token → mini-kms authorization is DESIGNED, not WIRED

The family documents a beautiful contract: a token's `grants` claim maps onto mini-kms's
authorization model (`sub → Principal.id`, `grants.control → Principal.admin`,
`grants.groups[] → KeyAuthorizationPolicy`). **That mapping is not a runtime path.**

- `KmsRequestHandler` (`services/mini-kms/core/.../kms/KmsRequestHandler.java`) authenticates with a
  **shared per-plane bearer token** and two fixed principals. It does **not** parse a JWT and does
  **not** read `grants`.
- `GrantsClaim.toAuthorization()` (`libs/mini-token/.../token/GrantsClaim.java`) — the method that
  would bridge a token claim into the authorization model — has **no production caller.** Its only
  caller is a test (`mini-idp` `TokenLifecycleTest`).

**Don't teach:** "a token from mini-idp authorizes a mini-kms operation." It can't today; the bridge
exists only as a designed seam. (Stage 7's optional design exercise walks *what it would take* — and
labels itself a design exercise.)

## <a id="2"></a>2. mini-kms data plane ships an allow-all policy

Every data-plane key operation passes through a `KeyAuthorizationPolicy` per key group — but the
shipped engine is **`AllowAllPolicyEngine`** (in `libs/mini-policy`): any *authenticated* caller is
permitted on any key group. (`LocalKeyring.java` notes the day "a real per-group PolicyEngine
replaces AllowAllPolicyEngine"; that swap is the future per-client decision.)

**Don't teach:** per-client key authorization in mini-kms as live behavior. The policy seam is real;
the per-client *decision* is the documented future step that `mini-policy` generalizes.

## <a id="3"></a>3. mini-oidc passkey enrolment is unauthenticated self-enrolment

The registration routes — `POST /register/passkey/start` and `/register/passkey/finish`
(`services/mini-oidc/.../server/OidcHandlers.java`) — are **not behind admin auth**. Anyone who can
reach the endpoint can enrol a passkey. That's fine for a local lab; a real deployment **must** gate
it (behind an invite, an existing session, or an admin token).

**Don't teach:** open `/register/passkey/**` as production-ready.

## <a id="4"></a>4. mini-oidc `--directory-url` is optional — and without it, nobody resolves

If you start mini-oidc with no `--directory-url`, it falls back to an **empty
`InMemoryUserDirectory`** (`ServerMain` prints "No --directory-url configured…"). Logins can't
resolve a real user, because there are none.

**Don't teach:** a mini-oidc login resolving a directory user unless the lab actually passed
`--directory-url` (or seeded the in-memory directory).

## <a id="5"></a>5. pk-auth's credential store is in-memory by default

mini-oidc's `PasskeyStack` assembles pk-auth over its **testkit in-memory** SPIs
(`InMemoryCredentialRepository`, `InMemoryChallengeStore`, `InMemoryUserLookup`) plus an
`InMemoryBackupCodeRepository`. Enrolled passkeys and backup codes **do not survive a restart.**
`PasskeyStack` is the documented swap point for persistent credential storage.

**Don't teach:** passkey persistence across restarts as current behavior.

## <a id="6"></a>6. mini-policy is minimal, and only two services decide through it today

`mini-policy` is a small, real decision engine — but its live consumers are **mini-oidc** (scope
authorization via `ScopeAuthorizer`) and **mini-gateway** (route authorization via `RoutePolicy`).
The issuers do **not** yet feed a decision into mini-kms (that's seam #1).

**Don't teach:** mini-policy as a family-wide decision bus that the issuers route through. It's a
shared library two edges use today.

## <a id="7"></a>7. the `cnf` claim is reserved, not enforced

`cnf` (RFC 7800, proof-of-possession / channel binding) is a real field on `JwtClaims`
(`libs/mini-token/.../token/JwtClaims.java`) but `TokenIssuer` writes it as **null** ("cnf
placeholder: not populated yet"). Nothing mints or checks it.

**Don't teach:** sender-constrained / proof-of-possession tokens as a working feature.

## <a id="8"></a>8. mini-ca is deliberately not a full PKI

mini-ca issues short-lived leaves from a **single self-signed root**, tracks revocation as a **JSON
list** (not a signed DER CRL), and ships **no intermediates, no OCSP, no ACME**. These are explicit
non-goals (see its README), not missing features.

**Don't teach:** mini-ca as a drop-in for a real PKI. Teach it as the *educational* shape of one.

---

## How to use this list

- **Building a lab or how-to?** If your steps cross one of these seams, either avoid it or carry the
  `> Wired vs. designed` callout. A guaranteed-to-succeed tutorial must not depend on an unwired
  path.
- **Tracing code?** When you hit `GrantsClaim.toAuthorization()`, `AllowAllPolicyEngine`, or a `cnf`
  placeholder, you've found a seam — not the "real implementation" you're missing. The code says so;
  this list says where.
- **Want to *wire* one?** That's the best kind of contribution. `DIRECTION.md`'s roadmap and the
  `security/` track frame what each wiring would have to defend.
