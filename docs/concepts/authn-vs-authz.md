# Authentication vs. authorization — the spine

> **Concept doc (explanation).** Stage 0. Builds the mental model the rest of the course hangs on,
> then points you at the code that embodies it. New terms link to [`GLOSSARY.md`](../GLOSSARY.md);
> the architecture rationale lives in [`DIRECTION.md`](../DIRECTION.md).

Two words that get slurred together are actually two different questions, asked at two different
moments, answered by two different parts of the system:

- **Authentication (authN)** — *who are you?* Proving an identity. Ends in a **principal**.
- **Authorization (authZ)** — *are you allowed to do this?* Deciding about an already-known
  principal. Ends in **ALLOW** or **DENY**.

You cannot authorize what you have not authenticated, and authenticating tells you *nothing* about
what's permitted. Keep them in separate boxes and every service in this family snaps into place.

---

## The one-sentence model

> **Identity → token → decision.** Authentication turns a *credential* into a **principal**; that
> principal is carried in a **token** (or a session); a decision function consults the principal's
> **grants** to answer one request.

Read left to right, that sentence *is* the family:

```
   credential                 principal + grants                 decide(action, resource)
 ──────────────►  authN  ──────────────────────►  carry  ──────────────────────────────►  ALLOW / DENY
 (secret, passkey,        (who you are + what          (token /        (authZ: a pure function
  client_secret, CSR)      you may do)                  session)        over the principal)
```

Each arrow is a different service's job. None of them does two jobs.

---

## Human vs. machine: same spine, different proof

The split that explains why there are *two* issuers is the **kind of actor** being authenticated.
The authorization half is identical for both — same principal, same grants, same decision function.
Only the *proof of identity* differs.

| | **Machine** (a service account) | **Human** (a person) |
| --- | --- | --- |
| Proves identity with | a `client_secret` (Argon2id-hashed at rest) | a **passkey** (WebAuthn), no shared secret |
| Flow | OAuth 2.0 **client-credentials** | OIDC **authorization-code + PKCE** |
| Issued by | **mini-idp** | **mini-oidc** |
| Gets | an access token | an ID token + an access token (+ refresh) |
| Carries a browser session? | no | yes (SSO) |

Both paths converge on the *same* token plane (**mini-token**) and the *same* identity source
(**mini-directory**). That convergence is the whole point — see [`DIRECTION.md`](../DIRECTION.md)
for the runtime relationships.

---

## Which `mini-` solves which half

This is the map you should be able to recite after stage 0. Each service owns one clearly-bounded
piece of the spine:

| Service / lib | Half | Its one job |
| --- | --- | --- |
| **mini-directory** | identity (authN input) | the **source of truth** — stores accounts and *resolves* one into a principal + expanded grants |
| **mini-idp** | authN (machines) | issues a token for a service account via client-credentials |
| **mini-oidc** | authN (humans) | logs a person in with a passkey and issues ID/access tokens |
| **mini-token** | the carrier | mints, signs (JWS), publishes (JWKS), and verifies the tokens — *and* holds the shared SSO session |
| **mini-policy** | authZ | the pure decision function `decide(principal, action, resource)` |
| **mini-gateway** | authZ (at the edge) | a forward-auth endpoint that gates a no-auth app per request |
| **mini-kms** | a crypto utility *underneath* it all | envelope-encrypts keys at rest — including the token-signing keys themselves |
| **mini-ca** | identity for workloads | issues short-lived X.509 certs for mTLS between services |

Notice **mini-token** and **mini-policy** are *libraries*, not services — the connective tissue the
issuers and gateways reuse rather than re-implement. That reuse is a recurring lesson of the family:
compose vetted machinery, don't hand-roll a second copy.

---

## Why this separation is worth the discipline

The payoff of keeping the two halves apart shows up the moment something composes:

- **Offline verification.** Because authZ is a pure function over a *signed* token, a verifier
  (mini-gateway, any RP) can check "who are you" by validating a signature against the published
  JWKS — with **no callback** to the issuer. AuthN happened once, at the issuer; everyone else just
  reads the result. (Stage 2 makes this concrete.)
- **One decision engine, many front doors.** mini-oidc authorizes *scopes*, mini-gateway authorizes
  *routes*, mini-kms authorizes *key operations* — all through the same `decide(...)` shape. The
  decision logic isn't reinvented per service.
- **Swappable proof.** Adding a new way to *authenticate* (a different passkey backend, a new
  credential type) doesn't touch the authorization model at all. The seam is clean because the two
  halves never merged.

> **Why it's built this way.** The "compose libraries, keep `core` I/O-free, two planes/two tokens"
> decisions are argued in [`DIRECTION.md`](../DIRECTION.md). This doc only names the split; that doc
> defends it.

---

## Now read it

You have the model. Go see it in the code — smallest, most self-contained first:

- **The decision function (authZ), in isolation:**
  `libs/mini-policy` → `PolicyEngine`, `GrantBasedPolicyEngine`, and the records
  `Principal` / `Action` / `Resource` / `Grant` / `Decision`.
- **Identity becoming a principal (the authN→authZ handoff):**
  `services/mini-directory` → `service/DirectoryService#resolve` (returns a `ResolvedPrincipal`) and
  `#authenticate` (the no-oracle credential check).
- **The carrier:**
  `libs/mini-token` → `token/Jws` (the signed token) and `session/SessionService` (the browser
  session) — the two ways a principal travels.

Then continue to stage 1, [`authorization-model.md`](authorization-model.md), to go deep on the
decision function — and read [`honest-seams.md`](honest-seams.md) before you trace anything end to
end.
