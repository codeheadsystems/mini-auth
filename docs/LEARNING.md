# Learning mini-auth — a reading order

mini-auth is built to be *read*. But the repo is a family of services that depend on
each other, so reading them in directory order (or alphabetically) drops you into the
deep end. This is the order that builds the concepts up before they're used — it follows
the family's actual dependency DAG, smallest and most-foundational first.

**How to use this.** At each stop, read the named files (and run the quick-start where
there is one), then move on. Each stop lists the *concept you learn there* — that's the
point of the stop, not just the API. Keep [`GLOSSARY.md`](GLOSSARY.md) open; it defines
the vocabulary each service assumes. The honest seams are deliberate: where something is
a scaffold or a swap point, the code says so — note them as you go rather than hunting for
"the real implementation."

Prereqs: JDK 21+, and `./gradlew build` green from the repo root (the whole-family gate).

---

## 0. The map

**Read:** [`DIRECTION.md`](DIRECTION.md) (the vision, component catalog, runtime
relationships, the recursive integrations, the roadmap) and [`GLOSSARY.md`](GLOSSARY.md)
(the vocabulary).

**You learn:** what each service is for, who calls whom at runtime, and the terms the rest
of the journey uses. Don't try to absorb all of `DIRECTION.md` — skim it as a map and come
back as the pieces become concrete.

---

## 1. mini-policy — authorization, distilled

**Where:** `libs/mini-policy` (the smallest shipping unit — a handful of tiny, well-commented
files).

**Read:** `Principal`, `Action`, `Resource`, `Grant` (note `Grant.permits`), `Decision`,
`PolicyEngine`, then `GrantBasedPolicyEngine` and the trivial `AllowAllPolicyEngine` /
`DenyAllPolicyEngine`.

**You learn:** authorization as a pure function — `decide(principal, action, resource) →
ALLOW | DENY` — with admin-bypass, wildcard grants, and **deny-by-default**. This is the
decision model every other service resolves into, so it's worth seeing first in isolation.

---

## 2. mini-token — the token plane

**Where:** `libs/mini-token` (`com.codeheadsystems.minitoken`).

**Read:** `token/Jws` (the hand-rolled compact JWS — the standout teaching artifact: it
signs the base64url text, never the raw JSON), `crypto/Ed25519Keys`, `jwks/Jwk` + `JwkSet`,
`service/SigningKeyService` (rotation: one active key, retired keys kept published until
they outlive the token TTL), `token/JwsClaimsVerifier` and `service/TokenVerifier` (offline
verification — signature first, then claims, then the `alg` pin), `token/GrantsClaim` (the
authorization claim), `store/DocumentStore` (the persistence SPI), and `session/SessionService`
(the shared SSO session).

**You learn:** how a signed token is built and verified offline, why JWKS lets verification
need no callback, how key rotation stays safe, and the `grants` claim contract that ties the
family together.

---

## 3. mini-kms — envelope encryption & key management

**Where:** `services/mini-kms` (`core` / `server` / `client`). Run the quick-start in its
README.

**Read:** the README's **Glossary** and **key hierarchy** first, then `crypto/AesGcm` (the
only place raw symmetric crypto happens), `keyring/LocalKeyring` (the passphrase → root →
KEK → DEK hierarchy), the `MasterKeyProvider` / `KeyringManager` seams, and **the
`docs/security/` finding docs** — issue → threat → fix → why → tests, the best threat-modeling
lessons in the repo. Then `client/KmsSigningKeyStore` (preview of the recursive integration —
revisited at the end).

**You learn:** envelope encryption, the data-plane/control-plane split (two tokens), why
rotation is safe (each ciphertext names its `kek_id`), crypto-shredding, and how a remote/HSM
provider could drop into the seam.

---

## 4. mini-directory — identity, resolved

**Where:** `services/mini-directory`. Run the quick-start (create a role/group/human, then
`GET /admin/principals/{id}/resolution`).

**Read:** the `model` records (`Account`, `Group`, `Role`, `GrantSpec`, `ResolvedPrincipal`),
then `service/DirectoryService` — especially `resolve(...)` (roles expand to grants, group
memberships inherited, de-duplicated) and `authenticate(...)` (no-oracle, constant-time, a
real-cost dummy hash for unknown ids).

**You learn:** how stored identities become a mini-policy `Principal` + expanded grants — the
input a decision function consumes — and the family's credential-check pattern.

---

## 5. mini-idp — machine identity (composition begins)

**Where:** `services/mini-idp` (`core` / `server`). Run the quick-start (it runs mini-directory
too).

**Read:** `server/IdpServer` (the composition root — wiring mini-token's services over the
stores), `directory/ServiceAccountDirectory` + `HttpServiceAccountDirectory` (resolving the
client from mini-directory), and how the resolved grants reassemble into the `grants` claim.

**You learn:** how the OAuth 2.0 client-credentials grant composes mini-token + mini-directory
into a machine token — and that the token contract (the OpenAPI spec) is authoritative.

---

## 6. mini-oidc — human SSO (the payoff)

**Where:** `services/mini-oidc`. The most intricate service; take the flow a step at a time.

**Read:** `server/OidcHandlers` end to end (authorize → login/consent → code → token → refresh),
`util/Pkce` (S256-only), `auth/PasskeyStack` + `PkAuthHumanAuthenticator` (the embedded pk-auth
passkey stack and its swap points), `service/AuthorizationCodeStore` and
`service/RefreshTokenService` (single-use codes and rotating refresh tokens, both with
family-revoke replay defense), and `service/OidcTokens` (ID/access tokens minted through
mini-token — *not* re-implemented).

**You learn:** the authorization-code + PKCE flow, browser-flow security (sessions distinct from
token TTLs, CSRF, redirect-URI allowlist), refresh rotation/replay defense, and "composition over
reinvention" — it embeds pk-auth, mints through mini-token, decides through mini-policy, resolves
through mini-directory.

---

## 7. mini-gateway — forward-auth (reuse, not reinvention)

**Where:** `services/mini-gateway`. See its README's Traefik / Caddy / nginx snippets.

**Read:** `server/GatewayHandlers` (the `/verify` endpoint and its allow / 302 / 401 / 403
answers, plus path normalization), `auth/SessionAuthenticator` (reading the *same*
`sessions.json` mini-oidc writes) + `auth/BearerAuthenticator`, and `service/RoutePolicy` +
`model/RouteRule` (ordered, segment-aware, deny-by-default routing through mini-policy).

**You learn:** how a forward-auth endpoint gates no-auth upstreams by *reusing* the shared
session and JWS verification — inventing nothing — and why the shared session store and cookie
name matter.

---

## 8. mini-ca + the recursive integration — the capstone

**Where:** `services/mini-ca`, plus `mini-kms:client/KmsSigningKeyStore` and `DIRECTION.md`'s
"Wrapping the signing keys under mini-kms" section.

**Read:** `ca/CaKeys` + `ca/CertificateAuthority` (self-signed root, CSR proof-of-possession,
the leaf extension set), `service/CaService` (bootstrap, issue/renew/revoke), and how the CA
private key is persisted as a one-record mini-token `SigningKeys` document through
`KmsSigningKeyStore` — the *same* decorator the token plane uses.

**You learn:** how the family secures **its own** keys — an issuer's (or CA's) signing key is
envelope-wrapped under mini-kms so no plaintext key touches disk. This is the recursive
integration the earlier stops were building toward: every concept (envelope encryption, the
`DocumentStore` SPI, the `kid`-as-AAD binding, short-lived credentials) shows up at once.

---

### After the tour

You've now seen the whole DAG: `mini-policy` + `mini-token` underpin `mini-kms`, `mini-directory`,
and the issuers; `mini-oidc` / `mini-gateway` / `mini-ca` compose them at the edges; and the keys
that sign tokens are themselves wrapped by the KMS. Good next steps: implement a `PolicyEngine`
of your own, swap a `DocumentStore` or `UserDirectory` SPI, or add a finding to a service's
`docs/security/`. `mini-console` (`services/mini-console`) is the one remaining roadmap
placeholder — a natural place to build something new on top of these admin APIs.
