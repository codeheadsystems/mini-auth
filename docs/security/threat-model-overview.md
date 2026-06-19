# Threat-model overview — the family's trust boundaries

> **Attack & defense (the family-wide view).** The per-service findings under
> `services/*/docs/security/` each zoom in on one weakness. This doc zooms *out*: where the **trust
> boundaries** are, what each service trusts its neighbor to have already checked, and where the
> secrets live. It's the one piece the repo lacked. Read
> [`concepts/secure-design-invariants.md`](../concepts/secure-design-invariants.md) first.

A trust boundary is a line where data crosses from less-trusted to more-trusted, and **something must
be verified at the crossing.** Get the boundaries right and the per-service defenses make sense as a
system.

---

## The map of boundaries

```
            ┌─────────────────────────────────────────────────────────────────────┐
   admin ──▶│ mini-directory  (source of truth: accounts, secrets-as-hashes)       │
   token    └───────────▲───────────────────────────────▲─────────────────────────┘
                        │ authenticate(id,secret)        │ resolve(id)
                        │ (secret crosses; hash does NOT) │ (principal+grants cross)
              ┌─────────┴─────────┐             ┌─────────┴──────────┐
   client ──▶ │ mini-idp          │   human ──▶ │ mini-oidc          │ ◀── passkey
   secret     │ (machine tokens)  │   (browser) │ (human SSO)        │     (WebAuthn)
              └─────────┬─────────┘             └─────────┬──────────┘
                        │ signs with                      │ writes sessions.json
                        ▼ mini-token keys                 ▼ + signs tokens
              ┌───────────────────────────────────────────────────────┐
              │ mini-token  (JWS sign/verify, JWKS, shared session)     │
              └───────────────────────────────────────────────────────┘
                        ▲ verify offline (JWKS)           ▲ read sessions.json
              ┌─────────┴───────────────────────┐  trusted │ proxy only
   proxy ────▶│ mini-gateway  (forward-auth)    │◀─────────┘
   subreq     └─────────────────────────────────┘
                        │ (signing keys wrapped at rest)
                        ▼
              ┌─────────────────────────────────┐
              │ mini-kms  (data plane / control plane — two tokens)     │
              └─────────────────────────────────┘
```

---

## Boundary by boundary

### 1. Client/human → issuer (the credential crossing)

- **What crosses:** a `client_secret` (machine) or a passkey assertion (human).
- **Verified at the crossing:** the issuer authenticates the credential before issuing anything.
- **The defense:** *no oracle* — any failure is one generic error (you saw this in lab 03). Passkey
  assertions are verified by pk-auth; the issuer reads the authenticated `UserHandle`, never trusts a
  client-supplied identity.

### 2. Issuer → mini-directory (resolution)

- **What crosses, which way:** the issuer sends the presented secret to the directory's
  `/authenticate`; the directory sends back the account + **resolved grants**.
- **The boundary fact:** the **secret *hash* never leaves mini-directory.** Verification happens
  *inside* the directory (it's the source of truth for secrets), so a compromised issuer can't exfil
  the hash database.
- **Trust:** the issuer trusts the directory's yes/no and its resolved grants. The directory trusts
  the issuer's admin token (`MINI*_DIRECTORY_TOKEN`) to even ask.

### 3. Issuer → verifier (the token, offline)

- **What crosses:** a signed token, later, with no issuer involvement.
- **Verified at the crossing:** the verifier checks the **signature against the JWKS**, pins
  `alg=EdDSA`, then checks `iss`/`aud`/time/revocation — *signature before claims* (lab 02).
- **The boundary fact:** this crossing needs **no live trust** in the issuer — only its published
  public keys. That's the property the whole family leans on.

### 4. mini-oidc ↔ mini-gateway (the shared session)

- **What crosses:** nothing over the network — they share a *file* (`sessions.json`). **mini-oidc
  writes; mini-gateway reads.**
- **The boundary fact + a sharp edge:** a **session proves identity but carries no scopes.** So a
  `SCOPE`-gated gateway route **cannot** be satisfied by a session — it requires an *access token*
  with the scope. (A session-only caller on `/admin` gets denied even though they're "logged in.")
  This surprises people; it's correct — scopes live in tokens, not sessions. See
  [`sessions-vs-tokens.md`](../concepts/sessions-vs-tokens.md).

### 5. Reverse proxy → mini-gateway (the forward-auth contract)

- **What crosses:** the original request's method/path as `X-Forwarded-*` headers, plus the client's
  cookie/authorization.
- **The boundary fact:** mini-gateway trusts those headers **only because the proxy set them.** Two
  obligations fall out, both in the [forward-auth header-trust finding](README.md):
  1. `/verify` must be reachable **only** by the trusted proxy (else a client forges
     `X-Forwarded-Uri`).
  2. The proxy must **strip client-supplied `X-Auth-*`**, and the gateway **always emits** its own
     (empty when anonymous) so they overwrite any spoof.

### 6. Data plane vs. control plane in mini-kms

- **The boundary:** two tokens. The **API token** can encrypt/decrypt; only the **admin token** can
  create/rotate/destroy a key group.
- **The boundary fact:** a leaked data-plane credential can *use* keys but cannot rotate or **destroy**
  them — key lifecycle is gated behind a credential most callers never hold.

### 7. Signing keys at rest (the recursive boundary)

- **The boundary:** the issuer's private signing key crosses to disk **only as ciphertext**
  (`kms1:…`), wrapped under mini-kms, with `kid` as AAD (lab 06).
- **The boundary fact:** stealing `signing-keys.json` yields nothing forge-able without also
  compromising mini-kms.

---

## Where the secrets live

| Secret | Lives where | Form |
| --- | --- | --- |
| Service-account secret | mini-directory only | Argon2id hash (plaintext shown once at creation) |
| Human credential | pk-auth credential store | WebAuthn public-key credential (no shared secret) |
| Admin/API tokens | operator env/file | compared constant-time; never logged/argv |
| Session id | the browser cookie | store keeps only `SHA-256(id)` |
| Refresh token | the client | store keeps only `SHA-256`; rotates, family-revoke on replay |
| Token-signing private key | issuer memory; disk only as `kms1:` ciphertext | Ed25519 PKCS#8, wrapped under mini-kms |
| KMS root key / KEKs | mini-kms memory only | derived from passphrase; zeroed on shutdown |

---

## Residual & assumed risks (be honest)

A threat model that claims everything is covered is lying. The family documents what it does **not**
defend yet — cross-check [`concepts/honest-seams.md`](../concepts/honest-seams.md):

- **token → mini-kms authorization is not wired** (#1): a token's `grants` claim does not yet drive a
  mini-kms decision; the data plane is `AllowAllPolicyEngine` (#2). Don't model mini-kms as
  per-client-authorized today.
- **Passkey enrolment is unauthenticated** (#3) and the **credential store is in-memory** (#5) — a
  real deployment must gate enrolment and persist credentials.
- **Loopback-TCP local exposure** (mini-kms finding #3, **open**): every local user can reach the
  loopback listener. Documented, not yet closed.
- **Offline passphrase cracking** (mini-kms): a stolen keystore is brute-forceable offline — Argon2id
  is the only barrier, so security collapses to passphrase entropy.

Naming these *is* part of the model. The best contribution is to wire one shut.
