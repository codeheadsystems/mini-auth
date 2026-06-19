# Teaching mini-auth — documentation outline

> **What this file is.** A blueprint for a new, course-style documentation set under `docs/`
> that teaches **how authentication and authorization work in practice**, using the `mini-*`
> services as the worked example. It is the *plan* — each entry below becomes a real document.
> It does not replace the existing orientation docs; it sits on top of them.
>
> **Status:** outline / proposal. Nothing here is written yet except this file.

---

## 1. Why a new set (and how it relates to the existing docs)

The repo already ships three excellent **orientation** docs and a reference layer. They are
*not* a course:

| Existing doc | What it is | Role in the new set |
| --- | --- | --- |
| [`DIRECTION.md`](DIRECTION.md) | The **map** — vision, component catalog, runtime relationships, roadmap, the "wired vs. designed" note. | The authoritative *why/architecture*. Concept docs **hand off** to it; never restate it. |
| [`GLOSSARY.md`](GLOSSARY.md) | The **dictionary** — every term, defined once. | New docs **link** terms here on first use and never redefine. Missing a term? Add it *here*. |
| [`LEARNING.md`](LEARNING.md) | The **reading order** — the source files in dependency-DAG order. | Complementary: tutorials teach the *concepts in teaching order*, then LEARNING.md walks the *code*. Cross-link both ways. |
| Service `README.md` + OpenAPI | **Reference** — authoritative endpoints, flags, contracts. | Labs/how-tos link out for exact syntax (which drifts); never copy command tables. |
| `services/*/docs/security/*.md` | **Threat-model findings** — issue → fix → why → tests. | Pre-built case studies; the new security track *frames and sequences* them. |

**The gap this set fills**, per the analysis: there is no concept-first teaching, no runnable
*cross-service* walkthrough, no flow (sequence) diagrams, no "why this design" deep dives, and no
hands-on/threat labs. This set is **course material**; the existing docs are map, dictionary, and
reading-order.

**The one discipline to protect** (it cuts against this repo's explain-everything instinct):
keep the four document kinds *physically separate*. A tutorial step never carries a concept
digression — it links out. Concepts carry the depth; rationale hands off to `DIRECTION.md`.

---

## 2. Audience — who we are teaching

| Persona | Comes in knowing | Walks away able to | Primary path |
| --- | --- | --- | --- |
| **P1 — Backend dev learning auth** *(primary)* | HTTP/JSON, reads Java, has *used* an IdP as a black box. "JWT" = a string they copy around. | Hold a true mental model of AuthN vs AuthZ, what a signed token *is*, offline verification, why PKCE/refresh-rotation exist; reason about an auth bug. | Concepts → Tutorials 1–4 |
| **P2 — Homelab operator** | Docker, reverse proxies, CLI. Doesn't want crypto theory first. | Stand up SSO + forward-auth in front of a no-auth app, and operate it safely (where secrets live, loopback, key rotation). | How-to + Tutorials 4–5 |
| **P3 — Security student / threat-modeler** | OWASP-level vocabulary; reads the `security/` findings for fun. | Internalize the family invariants (no oracles, constant-time, deny-by-default, crypto-shredding) as transferable reflexes; extend a threat model. | Concepts + Security track |
| **P4 — Architect** *(secondary)* | System design. | Already served by `DIRECTION.md`. | Handed off, not re-served. |

---

## 3. Proposed directory shape

```
docs/
  TEACHING.md            # NEW front door / syllabus: personas → pick-your-path, links to stages
  concepts/              # EXPLANATION — learn the idea, then "now read it" code pointers
  tutorials/             # TUTORIAL — hands-on, guaranteed-to-succeed, lean, links out
  howto/                 # HOW-TO — task-oriented, for someone who already gets it
  security/              # ATTACK & DEFENSE — framings over services/*/docs/security
  diagrams/              # shared sequence/flow diagrams (mermaid), referenced by the above
  (existing) DIRECTION.md  GLOSSARY.md  LEARNING.md  TEACHING-OUTLINE.md
```

`TEACHING.md` is the new entry point; the root `README.md` gains a link to it.

---

## 4. The concept → code map (the spine every doc draws from)

Every concept the set teaches is demonstrated by real, shipping code. This table is the
authoritative anchor — each concept doc opens with the idea and closes with these pointers.

### Authentication (proving *who*)
| Concept | Standard | Code |
| --- | --- | --- |
| Secret hashing | Argon2id (OWASP password storage) | `mini-directory secret/Argon2SecretHasher`; verify in `service/DirectoryService#authenticate` (no-oracle, dummy-hash) |
| Passkeys / WebAuthn | W3C WebAuthn / FIDO2 | `mini-oidc auth/PasskeyStack`, `PkAuthHumanAuthenticator` (embeds external **pk-auth** — the "use a vetted lib" lesson) |
| OAuth2 client-credentials | RFC 6749 §4.4 | `mini-idp server/ApiHandlers` `/oauth/token` → `directory/HttpServiceAccountDirectory` |
| OIDC auth-code + PKCE | OIDC Core; RFC 7636 (S256) | `mini-oidc server/OidcHandlers`, `util/Pkce`, `service/AuthorizationCodeStore` |
| Bearer tokens | RFC 6750 | issued by `mini-token`; checked at `mini-gateway auth/BearerAuthenticator` |
| Sessions / cookies | OWASP session mgmt | `mini-token session/SessionService` (shared store); `mini-oidc server/Cookies` |
| Refresh rotation | RFC 6749 §6 + OAuth BCP | `mini-oidc service/RefreshTokenService` (reuse revokes the family) |
| mTLS / certs | X.509, PKCS#10 | `mini-ca ca/CertificateAuthority`, `ca/CaKeys` |

### Authorization (deciding *what*)
| Concept | Code |
| --- | --- |
| Pure decision function | `mini-policy PolicyEngine`, `GrantBasedPolicyEngine`, `Principal/Action/Resource/Grant/Decision` |
| Deny-by-default + admin-bypass + wildcard | `GrantBasedPolicyEngine`; `AllowAll`/`DenyAll` seams |
| Identity resolution (roles→grants, group inherit, dedup) | `mini-directory service/DirectoryService#resolve` → `ResolvedPrincipal` |
| The `grants` claim contract | `mini-token token/GrantsClaim` over `auth/Authorization`/`Grant`/`KeyOperation` |
| Scopes | `mini-oidc service/ScopeAuthorizer` (through mini-policy) |
| Data plane vs. control plane (two tokens) | `mini-kms kms/KmsRequestHandler`; seams `MasterKeyProvider`, `KeyringManager` |
| Forward-auth gating (per-route) | `mini-gateway server/GatewayHandlers`, `service/RoutePolicy`, `model/RouteRule` |

### Cross-cutting crypto & security
| Concept | Code |
| --- | --- |
| Envelope encryption / KMS (passphrase→root→KEK→DEK) | `mini-kms keyring/LocalKeyring`; only raw crypto in `crypto/AesGcm` |
| Key rotation (KEK + signing) | `mini-kms KeyringManager`; `mini-token service/SigningKeyService`; `KmsSigningKeyStore#rewrap` |
| JWS / JWKS / offline verification | `mini-token token/Jws` (signs the b64url *text*), `jwks/Jwk`/`JwkSet`, `JwsClaimsVerifier`, `service/TokenVerifier` |
| The recursive integration | `mini-kms client/KmsSigningKeyStore` (`kid` as AAD) — used by idp/oidc *and* mini-ca |
| Crypto-shredding | `mini-kms` `DestroyVersion` |
| No-oracle error design | one generic error each: `DecryptionFailed` / `invalid_client` / `invalid_grant` / dummy-hash / CSR `400` |
| Constant-time compare | `MessageDigest.isEqual` in each `AdminAuthenticator`, `Argon2SecretHasher`, `KeystoreIntegrity` |
| At-rest integrity & secrets | `mini-kms keyring/KeystoreIntegrity`; `store/JsonStore` atomic-`0600`; env/file-never-argv in each `ServerConfig` |

---

## 5. ⚠️ Honesty rules — designed-but-NOT-wired paths the docs must not teach as live

This is the single most important correctness constraint. `DIRECTION.md`'s "Wired vs. designed"
note lists seams that are *designed* but not runtime paths. A lab that sends a learner to trace
one through running code will mislead. **Every doc touching one of these carries a standard
`> Wired vs. designed` callout**, and one dedicated doc (`concepts/honest-seams.md`) enumerates
them.

1. **token → mini-kms authorization is DESIGNED, not WIRED.** `KmsRequestHandler` uses a shared
   per-plane bearer token + two fixed principals; it does not parse a JWT or read `grants`.
   `GrantsClaim.toAuthorization()` has **no production caller.**
2. **mini-kms data plane ships `AllowAllPolicy`** — any authenticated caller is permitted.
3. **mini-oidc passkey enrolment (`/register/passkey/**`) is unauthenticated self-enrolment** —
   a real deployment must gate it.
4. **mini-oidc `--directory-url` is optional**; without it, an empty in-memory directory resolves
   nobody.
5. **pk-auth credential store is in-memory** by default (no persistence across restart).
6. **mini-policy is minimal**; only mini-oidc (scopes) and mini-gateway (routes) decide through it
   today; the issuers don't yet feed mini-kms.
7. **`cnf` claim reserved (RFC 7800), not enforced.**
8. **mini-ca is deliberately not a full PKI** (one self-signed root, JSON revocation list, no
   CRL/OCSP/intermediates/ACME).

---

## 6. The document set

### 6.0 `TEACHING.md` — the syllabus (front door)
- **Audience:** everyone. **Type:** index.
- Persona-based path picker (the table in §2), the stage ladder (§7), and the explicit
  relationship to DIRECTION/GLOSSARY/LEARNING. One screen, then it routes.

### 6.1 `concepts/` — Explanation (learn the idea)
Each doc: build the concept from zero → a "Why it's built this way" callout that hands off to
`DIRECTION.md` → a **"Now read it"** box with the §4 file pointers → links terms to `GLOSSARY.md`.

1. **`authn-vs-authz.md`** — the spine. Identity → token → decision; human vs machine actor.
   *Objective: name which problem each mini solves.*
2. **`authorization-model.md`** — `decide(principal, action, resource)`, deny-by-default,
   admin-bypass, wildcards, resolution (roles/groups → grants). Anchored on mini-policy +
   mini-directory.
3. **`what-a-token-is.md`** — claims, JWS = `b64url(h).b64url(p).b64url(sig)`, signing the *text*,
   Ed25519, `kid`, JWKS, offline verification, rotation, revocation. **The keystone concept.**
4. **`oauth-and-oidc-flows.md`** — client-credentials vs auth-code+PKCE; why PKCE; ID vs access
   token; the `grants`/scope claims.
5. **`sessions-vs-tokens.md`** — browser SSO sessions, why session lifetime ≠ token TTL, cookie
   flags, the *shared* session store, refresh rotation & replay defense.
6. **`envelope-encryption-and-kms.md`** — passphrase→root→KEK→DEK, wrap/unwrap, data/control
   plane, crypto-shredding, and the recursive integration.
7. **`secure-design-invariants.md`** — the family's transferable reflexes: no oracles,
   constant-time, deny-by-default, loopback + secrets-via-env, atomic-`0600`. *(This is the
   recurring sidebar promoted to its own doc for P3.)*
8. **`honest-seams.md`** — the §5 list, in one place. Required reading before any deep trace.

### 6.2 `tutorials/` — hands-on, guaranteed-to-succeed (lean; links out)
Every tutorial uses **predict-then-run** (predict allow/deny or pass/fail before running) and one
persistent scenario ("protect `grafana` in my homelab") so services slot into one story. Each maps
to a learning stage (§7).

1. **`01-resolve-a-principal.md`** — run mini-directory; create role/group/human; `GET
   /admin/principals/{id}/resolution`; predict the grants by hand. *(AuthZ, smallest complete idea.)*
2. **`02-build-and-verify-a-token-by-hand.md`** — **the signature lab.** Issue a token, decode it,
   verify the signature against `/jwks.json` by hand/script, then **tamper one byte and watch it
   fail.** Converts "JWT = opaque string" into a real model.
3. **`03-machine-identity-end-to-end.md`** — mini-directory + mini-idp; create a service account;
   client-credentials → token → offline-verify; watch the single `invalid_client` on any failure.
4. **`04-human-sso-end-to-end.md`** — full mini-oidc auth-code+PKCE browser login with a passkey;
   inspect the ID token; exercise a refresh; **replay a spent refresh token and watch the family
   revoke.** *(Carries callouts for traps #3, #4, #5.)*
5. **`05-gate-a-no-auth-app.md`** — mini-gateway + a reverse proxy in front of a no-auth `whoami`
   (reuse the shipped `mini-gateway/examples/` compose/Caddyfile); shared session + per-route policy.
6. **`06-protect-the-signing-keys.md`** — start mini-kms; create a key group; run an issuer
   `--kms-*`; confirm only ciphertext touches disk. *(Capstone; the recursive integration.)*

### 6.3 `howto/` — task-oriented (P2's destination)
1. **`run-the-whole-family.md`** — bring up all services in dependency order
   (directory → idp/oidc/ca → gateway; kms optional), with the env-var plumbing. Pairs with a
   runnable `examples/` script. *(Closes the "no single chained walkthrough" gap.)*
2. **`sso-for-your-homelab.md`** — minimal SSO + forward-auth, loopback→behind-TLS-proxy.
3. **`rotate-signing-keys.md`** and **`rotate-a-kms-kek.md`** — rotation + `rewrap`, verify old
   artifacts still verify/decrypt.
4. **`wire-the-services-together.md`** — who calls whom, what each expects, and the **failure
   modes** (e.g. directory unreachable → all token requests fail with generic `invalid_client`).
5. **`configuration-and-secrets.md`** — ports, tokens, when to expose beyond loopback, the
   `openssl rand -hex 32` pattern, env vs file.
6. **`swap-an-spi.md`** — extension points: implement a `PolicyEngine`, swap a `DocumentStore` /
   `UserDirectory` / `ServiceAccountDirectory`.

### 6.4 `security/` — Attack & Defense (framing the existing findings)
A short index + one framing doc per existing finding (naive version → attack → what the code does →
the test that pins it). Source material already exists under `services/*/docs/security/`:
- mini-kms: pre-auth connection exhaustion; keystore metadata integrity; loopback-TCP exposure *(open item)*
- mini-idp: no-oracle authentication
- mini-oidc: PKCE downgrade; logout open-redirect
- mini-gateway: forward-auth header trust; path confusion
- mini-ca: CSR proof-of-possession; issuance authority
- Plus **`threat-model-overview.md`** — the *one* missing piece: the family's trust boundaries in
  one place (e.g. why a SCOPE route rejects a session — sessions carry no scopes).

### 6.5 `diagrams/` — the missing visual layer (sequence, not topology)
Reuse `DIRECTION.md`'s system (topology) diagram; **add sequence diagrams** the repo lacks:
client-credentials issuance; auth-code+PKCE; forward-auth subrequest; KMS wrap-on-save. Referenced
by the concept and tutorial docs.

---

## 7. Learning progression (objective-driven, dependency-ordered)

Pedagogy order leads with the *why/what*, then drops into code — deliberately different from
`LEARNING.md`'s code-DAG order. Each stage = one concept doc + one tutorial lab.

| Stage | Objective | Concept | Lab |
| --- | --- | --- | --- |
| 0 | Name the problem each mini solves | `authn-vs-authz` | — |
| 1 | A decision is a pure function; deny-by-default | `authorization-model` | `01-resolve-a-principal` |
| 2 | What a signed token *is*; verify offline | `what-a-token-is` | `02-build-and-verify-a-token-by-hand` ← **keystone** |
| 3 | Machine identity composes directory + token | `oauth-and-oidc-flows` | `03-machine-identity-end-to-end` |
| 4 | Human SSO: PKCE, passkeys, sessions, refresh | `sessions-vs-tokens` | `04-human-sso-end-to-end` |
| 5 | Gate a no-auth app via forward-auth | (reuse stage 4) | `05-gate-a-no-auth-app` |
| 6 | The family protects its own keys | `envelope-encryption-and-kms` | `06-protect-the-signing-keys` |
| ∥ | Secure-design reflexes (recurring) | `secure-design-invariants` + `security/` track | the threat labs |

**End-to-end scenarios** (thread services; all four are *wired* paths):
1. A machine gets a token and is authorized *(stage 3)*.
2. A human logs in and reaches a gated app *(stages 4–5)*.
3. The family secures its own signing keys *(stage 6)*.
4. Workload identity with mTLS via mini-ca *(capstone variant of stage 6)*.
5. *(Optional, explicitly a design exercise, never current behavior)* "What it would take to let
   mini-kms authorize on the `grants` claim" — walks traps #1/#2 as a future seam.

---

## 8. Pedagogical devices (fit the "read the code" ethos)
- **"Now read it" boxes** — every concept ends with exact `file:symbol` pointers (§4).
- **Hand-verification lab (stage 2)** — the signature device of the whole set; do it before any
  library hides the mechanism.
- **Predict-then-run** — every lab asks for a prediction first.
- **Break-it / threat-model exercises** — the `security/` findings as case studies.
- **One persistent scenario** across stages 3–6 (the homelab `grafana`).
- **Sequence diagrams** per flow (§6.5).
- **"Why this design" callouts** that hand off to `DIRECTION.md` rather than restate it.

---

## 9. Build order (suggested)
1. `TEACHING.md` + `concepts/authn-vs-authz.md` + `concepts/honest-seams.md` (the frame + the
   safety net).
2. Stage 1–2 concept + lab (`authorization-model`, `what-a-token-is`, tutorials 01–02) — the
   highest-leverage core.
3. `diagrams/` for those flows.
4. Stages 3–6 concept + lab, then `howto/run-the-whole-family.md` + the `examples/` script.
5. `security/` framings (cheapest — source material exists) + `threat-model-overview.md`.
6. Remaining how-tos.

Cross-link additions: root `README.md` → `TEACHING.md`; `LEARNING.md` ↔ `TEACHING.md` (one line
each, "concepts first vs. code first").
