# Sequence — OIDC authorization-code + PKCE (human SSO login)

> The **human identity** flow: a person authenticates with a passkey, the OP issues ID + access (+
> refresh) tokens, and a browser **SSO session** is established. Concept:
> [`oauth-and-oidc-flows.md`](../concepts/oauth-and-oidc-flows.md) +
> [`sessions-vs-tokens.md`](../concepts/sessions-vs-tokens.md). Lab:
> [`04`](../tutorials/04-human-sso-end-to-end.md).

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser
    participant RP as Client app (RP)
    participant OIDC as mini-oidc (OP)
    participant DIR as mini-directory
    participant TOK as mini-token (session + JWS)

    Note over B,RP: RP starts the flow with a PKCE challenge it keeps the verifier for
    B->>OIDC: GET /authorize?client_id&redirect_uri&response_type=code<br/>&scope=openid…&state&nonce<br/>&code_challenge&code_challenge_method=S256
    Note right of OIDC: validate client/redirect/scope;<br/>require S256; store PendingAuthorization<br/>(requestId + CSRF token)
    OIDC-->>B: 200 login page (no session yet)

    B->>OIDC: POST /login/passkey/start {requestId, username}
    OIDC-->>B: WebAuthn challenge
    B->>OIDC: POST /login/passkey/finish {requestId, csrf, assertion}
    Note right of OIDC: verify CSRF (constant-time) +<br/>passkey assertion (pk-auth)
    OIDC->>TOK: SessionService.create(subject, auth_time)
    Note right of TOK: store SHA-256(sessionId) in sessions.json (0600)
    OIDC-->>B: 200 {next: /authorize/continue?req=…}<br/>Set-Cookie: mioidc_session=…; HttpOnly; SameSite=Lax; Path=/

    B->>OIDC: GET /authorize/continue?req=… (cookie rides along)
    OIDC-->>B: 200 consent page
    B->>OIDC: POST /authorize/decision {requestId, csrf, approve}
    Note right of OIDC: ScopeAuthorizer.authorize (via mini-policy);<br/>mint code bound to {client, redirect, challenge, nonce, auth_time}
    OIDC-->>B: 302 redirect_uri?code=…&state=…
    B->>RP: GET /callback?code=…&state=…

    RP->>OIDC: POST /token grant_type=authorization_code,<br/>code, redirect_uri, code_verifier
    Note right of OIDC: consume code (single-use, replay→revoke family);<br/>PKCE: base64url(SHA-256(verifier)) == stored challenge?
    OIDC->>DIR: resolve(subject) → profile + grants
    OIDC->>TOK: mint ID token + access token (Ed25519 JWS); issue refresh token
    OIDC-->>RP: 200 {id_token, access_token, refresh_token, expires_in, scope}

    RP->>OIDC: GET /userinfo  (Authorization: Bearer access_token)
    Note right of OIDC: JwsClaimsVerifier — offline (signature, iss, aud, time)
    OIDC-->>RP: 200 {sub, name?, email?}  (claims by granted scope)

    Note over RP,OIDC: Later — access token expired
    RP->>OIDC: POST /token grant_type=refresh_token, refresh_token
    Note right of OIDC: rotate: verify hash (constant-time); if already used →<br/>REVOKE WHOLE FAMILY (replay defense); else issue new pair
    OIDC-->>RP: 200 {new access_token, new refresh_token (same family), …}
```

**Key points**

- **PKCE is mandatory and S256-only.** The challenge is stored at `/authorize`; the verifier is
  checked at `/token`. A stolen code is useless without the verifier. (`plain` is rejected — see the
  [PKCE-downgrade finding](../security/README.md).)
- **CSRF** token on every state-changing browser POST; **redirect only to pre-registered URIs**.
- **The session is distinct from the tokens.** The cookie (`mioidc_session`, SHA-256-hashed at rest)
  has its own lifetime; the tokens have their own TTLs. See
  [`sessions-vs-tokens.md`](../concepts/sessions-vs-tokens.md).
- **Refresh rotation with family-revoke:** replaying a spent refresh token revokes the entire family.

> **⚠ Wired vs. designed.** Passkey **enrolment** (`/register/passkey/**`) is *unauthenticated
> self-enrolment*, the credential store is *in-memory* (no persistence across restart), and a real
> login needs `--directory-url` to resolve anyone. See
> [`honest-seams.md`](../concepts/honest-seams.md#3) (#3, #4, #5).
