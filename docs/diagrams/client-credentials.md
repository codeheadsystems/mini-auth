# Sequence — OAuth 2.0 client-credentials (machine gets a token)

> The **machine identity** flow: a service account exchanges `client_id` + `client_secret` for a
> signed access token, which a verifier later checks **offline**. Concept:
> [`what-a-token-is.md`](../concepts/what-a-token-is.md) + [`oauth-and-oidc-flows.md`](../concepts/oauth-and-oidc-flows.md).
> Lab: [`02`](../tutorials/02-build-and-verify-a-token-by-hand.md) / [`03`](../tutorials/03-machine-identity-end-to-end.md).

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (service account)
    participant IDP as mini-idp
    participant DIR as mini-directory
    participant TOK as mini-token (lib in mini-idp)
    participant V as Verifier (offline)

    Note over C,DIR: One-time setup (admin): the service account is created in the directory
    C->>IDP: POST /oauth/token<br/>grant_type=client_credentials,<br/>client_id, client_secret
    IDP->>DIR: POST /admin/service-accounts/authenticate<br/>(id, secret)
    Note right of DIR: verify Argon2id hash, constant-time,<br/>dummy-hash on miss (no oracle)
    alt bad credentials
        DIR-->>IDP: not authenticated
        IDP-->>C: 401 invalid_client (single generic error)
    else authenticated
        DIR-->>IDP: account + resolved grants
        IDP->>TOK: issue(subject, Authorization)
        Note right of TOK: build claims (iss/sub/aud/exp/jti + grants),<br/>sign Ed25519 JWS with active key (kid)
        TOK-->>IDP: compact JWS
        IDP-->>C: 200 {access_token, token_type, expires_in, scope}
    end

    Note over C,V: Later — the token is presented to a resource/verifier
    C->>V: request + Bearer <access_token>
    V->>IDP: GET /.well-known/jwks.json (once; cacheable)
    IDP-->>V: JWKS (public keys, by kid)
    Note right of V: pin alg=EdDSA → select key by kid →<br/>verify signature → check iss/aud/time/jti.<br/>NO callback to issuer per request.
    V-->>C: allow / deny
```

**Key points**

- The secret never leaves the directory's verification path; the **hash never leaves mini-directory**
  (mini-idp POSTs the secret to `/authenticate`, the directory verifies).
- Any auth failure collapses to **one** `invalid_client` — unknown client and wrong secret are
  byte-identical (no oracle).
- The verifier checks the token **offline** against the JWKS — the dashed `JWKS` fetch is one-time
  and cacheable, not per-request.

> **⚠ Wired vs. designed.** The verifier-against-mini-kms-using-`grants` path is **designed, not
> wired** today. See [`honest-seams.md`](../concepts/honest-seams.md#1). The offline verification
> against the JWKS *is* wired (you do it by hand in lab 02).
