# Glossary

The `mini-` family spans several domains — symmetric crypto, the JOSE/OAuth token
world, OpenID Connect, WebAuthn, X.509, and a small authorization model — and each
service's README assumes the vocabulary of its corner. This file collects the terms
in one place so a newcomer can meet them *before* being dropped into a service.

The vocabulary deliberately follows real systems (AWS/GCP KMS, NIST, the relevant
RFCs) so the concepts carry over. Each entry says what the term is, **why it matters
here**, and where it lives in the code.

> New to the project? Read this alongside [`DIRECTION.md`](DIRECTION.md), then follow
> the reading order in [`LEARNING.md`](LEARNING.md).

---

## Cryptographic foundations

These come from **mini-kms** (`services/mini-kms`), the most heavily-commented crypto
in the family; its README has the canonical, longer treatment.

- **KDF (key derivation function)** — turns a low-entropy secret (a passphrase) into a
  key. mini-kms uses Argon2id (`crypto`/`master` packages).
- **Argon2id** — a *memory-hard* password-hashing KDF: deriving the key costs a tunable
  amount of RAM + time, which is what makes brute-forcing a stolen keystore (mini-kms)
  or a stolen secret hash (mini-directory / mini-oidc client secrets) expensive.
- **Salt** — per-install/per-secret random bytes mixed into the KDF so the same input
  hashes differently every time, defeating precomputation (rainbow tables).
- **Root / master key** — the top key derived from the passphrase; it lives in memory
  only and *wraps* everything below it (mini-kms `LocalKeyring`).
- **KEK (key-encryption key)** — a key whose only job is to encrypt (*wrap*) other keys,
  never bulk data. In mini-kms each key group's versions are KEKs.
- **DEK (data-encryption key)** — a per-operation key that encrypts the actual data,
  then is itself wrapped under a KEK and zeroed. The split is what envelope encryption
  buys you.
- **Envelope encryption** — encrypt data with a fresh DEK, then wrap the DEK with a KEK.
  Only the tiny wrapped DEK needs the KMS; the bulk data is encrypted locally and the
  master key never touches it. This is the core mini-kms idea, and the same wrapping
  pattern protects signing keys at rest (`KmsSigningKeyStore`).
- **Wrap / unwrap** — encrypt / decrypt a *key* under another key (vs. encrypting data).
- **AES-256-GCM** — the symmetric cipher used throughout (`crypto/AesGcm`): AES with a
  256-bit key in GCM mode, an AEAD.
- **AEAD (authenticated encryption with associated data)** — encryption that also detects
  tampering: decryption *fails* (rather than returning garbage) if the ciphertext, key,
  or AAD is wrong. Every decrypt failure in the family collapses to one generic error —
  never an oracle for *why*.
- **Nonce (a.k.a. IV)** — a "number used once" fed to the cipher. A fresh random 96-bit
  nonce is generated per encryption; reusing one with the same key breaks GCM, so nonces
  are never caller-supplied.
- **AAD (additional authenticated data) / "encryption context"** — data that is
  authenticated but not encrypted; decryption only succeeds if the same AAD is supplied.
  It binds a ciphertext to a context — e.g. `KmsSigningKeyStore` binds a wrapped signing
  key to its `kid` so a blob can't be swapped between records.
- **MAC / HMAC** — a keyed integrity tag. mini-kms HMACs its keystore metadata so offline
  tampering (re-enabling a destroyed key, splicing a KEK) is detected on load.
- **Crypto-shredding** — destroying a key so all data encrypted under it becomes
  permanently unrecoverable. mini-kms's `DestroyVersion` is intentionally irreversible.
- **Ed25519 / EdDSA** — an elliptic-curve signature scheme (RFC 8037). The whole token
  plane signs with Ed25519 (`mini-token` `crypto/Ed25519Keys`); `EdDSA` is its JOSE
  algorithm name. (Distinct from mini-ca, which signs certificates with EC P-256 /
  `SHA256withECDSA`.)

---

## Tokens: JOSE, OAuth 2.0, OpenID Connect

The token plane lives in **mini-token** (`libs/mini-token`); the issuers are **mini-idp**
(machines) and **mini-oidc** (humans).

- **JWT (JSON Web Token)** — a set of claims (a JSON object: `iss`, `sub`, `aud`, `exp`,
  …) carried as a token. Here every JWT is also a JWS.
- **JWS (JSON Web Signature)** — the signed, compact-serialized form
  `base64url(header).base64url(payload).base64url(signature)`. mini-token hand-rolls it
  in `token/Jws` (deliberately, to be read), signing the *base64url text* — never the raw
  JSON — so verification recomputes the exact bytes.
- **`kid` (key id)** — names which signing key signed a token, so a verifier can pick the
  right public key during rotation. It is the only header field that varies per key.
- **JWKS (JSON Web Key Set)** — the published set of *public* signing keys (`/jwks.json`),
  so any verifier can check signatures **offline** with no call back to the issuer
  (`mini-token` `jwks/Jwk`, `JwkSet`; served by each issuer).
- **OAuth 2.0 client-credentials grant** — the machine-to-machine flow: a service account
  presents `client_id` + `client_secret` and gets an access token. This is what
  **mini-idp** does at `/oauth/token`.
- **Authorization-code flow with PKCE** — the browser flow for humans: the user
  authenticates at the OpenID Provider, which returns a short-lived *code* to a registered
  redirect URI; the client then exchanges the code (plus a PKCE verifier) for tokens. This
  is **mini-oidc**'s core flow (`OidcHandlers`).
- **PKCE (Proof Key for Code Exchange) / S256** — binds an authorization code to the
  client instance that started the flow: the client sends `code_challenge =
  base64url(SHA-256(verifier))` up front and the `verifier` at token time, so a stolen
  code is useless. mini-oidc requires the **S256** method (`util/Pkce`); the insecure
  `plain` method is rejected.
- **OpenID Provider (OP) / Relying Party (RP)** — OIDC roles: the OP authenticates users
  and issues tokens (mini-oidc); an RP is a client app that relies on it.
- **ID token** — an OIDC JWT *about the authenticated user* (identity: `sub`, `auth_time`,
  `nonce`, profile/email by scope), for the client to consume.
- **Access token** — a JWT *for calling APIs* (`scope`, audience); presented as a Bearer
  token (e.g. to `/userinfo` or through mini-gateway).
- **Refresh token** — a long-lived opaque credential that buys new access tokens without
  re-authenticating. mini-oidc's rotate on every use with **family-based replay defense**:
  reusing a spent token revokes the whole family (`service/RefreshTokenService`).
- **`nonce` (OIDC)** — a client-supplied value echoed into the ID token, binding it to the
  authorization request to prevent token substitution. (Distinct from the crypto nonce
  above.)
- **`auth_time`** — when the human actually authenticated (not when the token was issued);
  carried unchanged across refreshes so a client's max-age / re-auth check stays honest.
- **Revocation / denylist** — a list of token ids (`jti`) a verifier can consult to reject
  a specific token before its natural expiry (`mini-token` `RevocationService`). Short TTLs
  are the primary control; revocation is the early kill switch.

---

## Identity & authorization

The decision model is **mini-policy** (`libs/mini-policy`); the identity source of truth is
**mini-directory** (`services/mini-directory`).

- **Principal** — the authenticated identity a decision is made about: an id plus an
  `admin` flag (`minipolicy.Principal`). A token's `sub` maps to `Principal.id`.
- **Action / Resource** — the two coordinates of a request: *what* is being done to *what*
  (`minipolicy.Action`, `Resource`); both support a `*` wildcard.
- **Grant** — a permission: this `Action` on this `Resource` is allowed
  (`minipolicy.Grant`, with `permits(action, resource)`). mini-directory stores the
  JSON-friendly mirror as `GrantSpec` (`{action, resource}`).
- **PolicyEngine / GrantBasedPolicyEngine** — the decision function `decide(principal,
  action, resource) → ALLOW | DENY`. The grant-based engine is admin-bypass +
  match-a-grant + **deny-by-default**; `AllowAll`/`DenyAll` are the trivial engines and
  documented seams.
- **Resolution** — mini-directory's defining job: expand an account into a `Principal` +
  a fully de-duplicated set of grants, with roles expanding to grants and group memberships
  inherited (`DirectoryService.resolve`, returning a `ResolvedPrincipal`).
- **Role / Group** — grant-bundling constructs in mini-directory: a role is a named set of
  grants; a group confers its own grants plus its roles' grants to members.
- **Service account vs. human** — the two kinds of identity (`Account.kind`): service
  accounts carry an Argon2id-hashed secret and authenticate via client-credentials (consumed
  by mini-idp); humans carry no secret and authenticate with passkeys (via mini-oidc).
- **`grants` claim** — mini-token's per-key-group authorization claim (`token/GrantsClaim`
  over `auth/Authorization`) that maps onto mini-kms's model: `sub → Principal.id`,
  `grants.control → Principal.admin`, `grants.groups[] → KeyAuthorizationPolicy`. The
  string values of `auth/KeyOperation` are a deliberate contract — do not rename them.

---

## Certificates (mini-ca)

From **mini-ca** (`services/mini-ca`), an internal CA for mTLS.

- **CA root / trust anchor** — the self-signed certificate (EC P-256) whose public key
  signs all leaves; verifiers trust it directly (`GET /ca`, `ca/CaKeys`).
- **Leaf certificate** — a short-lived end-entity cert issued to a workload for mTLS
  (`CA:false`, client+server EKU). Short TTLs are the primary control; revocation is the
  kill switch.
- **CSR (Certificate Signing Request)** — a PKCS#10 request carrying the requester's public
  key and desired subject, self-signed by the requester's private key. The requester keeps
  its private key; the CA never sees it (`ca/CertificateAuthority`).
- **Proof-of-possession (PoP)** — verifying the CSR's self-signature against its own public
  key before issuing, proving the requester holds the matching private key.
- **SAN (Subject Alternative Name)** — the DNS names / IPs a certificate is valid for (the
  field modern TLS actually checks).
- **EKU (Extended Key Usage)** — what a cert may be used for; mini-ca leaves carry
  `clientAuth` + `serverAuth` for mutual TLS.
- **Revocation list** — mini-ca's JSON list of revoked serials (`GET /revocations`). A real
  PKI would publish a signed CRL or OCSP; the JSON list is the deliberate, documented
  educational simplification.

---

## Architecture & patterns

- **SPI (Service Provider Interface)** — an interface defining a swappable seam: the family
  injects an implementation at the composition root. Examples: `ServiceAccountDirectory`
  (mini-idp), `UserDirectory` (mini-oidc), `MasterKeyProvider`/`KeyringManager` (mini-kms),
  `HumanAuthenticator` (mini-oidc). The shipped impls are real; the in-memory ones are
  documented test/dev seams.
- **DocumentStore** — mini-token's persistence SPI (`store/DocumentStore`): round-trip a
  typed document to durable storage. The default impl is the atomic-`0600` `JsonStore`; the
  KMS-wrapping `KmsSigningKeyStore` is a decorator over it, so signing keys never sit
  plaintext on disk.
- **Forward-auth** — a pattern where a reverse proxy (Traefik / Caddy / nginx) calls an auth
  endpoint before forwarding each request, to gate upstreams that have no auth of their own.
  **mini-gateway**'s `/verify` is that endpoint; it reuses the shared session + JWS
  verification and answers allow/deny.
- **Data plane vs. control plane** — the split between per-request operations (guarded by an
  API token) and management operations (guarded by a separate admin token); mini-kms tags
  every request type with its plane.
- **Composition root** — the one place (`*Server`/`ServerMain`) that wires concrete
  implementations into the I/O-free `core`/services; the rule is `core` never imports a
  transport.
