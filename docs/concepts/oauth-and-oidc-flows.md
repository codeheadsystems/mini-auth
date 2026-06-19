# OAuth & OIDC flows — two ways to get a token

> **Concept doc (explanation).** Stage 3. Anchored on **mini-idp** (machines) and **mini-oidc**
> (humans). New terms link to [`GLOSSARY.md`](../GLOSSARY.md); rationale in
> [`DIRECTION.md`](../DIRECTION.md). Diagrams:
> [`client-credentials`](../diagrams/client-credentials.md), [`auth-code-pkce`](../diagrams/auth-code-pkce.md).
> Labs: [`03`](../tutorials/03-machine-identity-end-to-end.md), [`04`](../tutorials/04-human-sso-end-to-end.md).

Stage 2 showed *what a token is*. This doc shows the two **grants** — the two protocols for *getting*
one — and why they differ. They differ for exactly one reason, the stage-0 split: **who is the
actor.**

| | **client-credentials** | **authorization-code + PKCE** |
| --- | --- | --- |
| Actor | a machine (service account) | a human, via a browser |
| Proves identity with | `client_secret` | a passkey (WebAuthn) |
| Steps | one POST | a multi-step browser redirect dance |
| Issuer | mini-idp | mini-oidc |
| Returns | access token | **ID token** + access token (+ refresh) |
| Why the difference | a machine can hold a secret safely | a human can't, and a browser is a hostile relay |

---

## client-credentials: one POST (machines)

The machine flow is almost boringly simple, and that's the point — a service account *can* safely
hold a secret, so there's no ceremony:

```
POST /oauth/token
  grant_type=client_credentials & client_id=… & client_secret=…
      → { access_token, token_type: Bearer, expires_in, scope }
```

mini-idp verifies the secret (against mini-directory), resolves the account's grants, and signs a
token. That's the entire flow you ran in lab 02. The token's `sub` is the service account; its
`grants` claim is the resolved authorization from stage 1.

**There is no refresh token and no ID token.** A machine doesn't need a "who is the user" document
(it *is* the principal), and when its access token expires it just asks again with its secret.

---

## authorization-code + PKCE: the browser dance (humans)

Humans can't safely hold a secret, and the browser carrying the flow is an *untrusted relay* (it can
be redirected, its history logged, its requests observed). So the human flow is built to stay secure
*despite* the browser. The shape:

```
1. /authorize       browser arrives with a code_challenge; OP authenticates the human (passkey)
2.                  OP redirects back to the app with a one-time CODE
3. /token           app exchanges code + code_verifier  →  id_token + access_token + refresh_token
```

Walk the [sequence diagram](../diagrams/auth-code-pkce.md) once; here is *why each piece exists*:

### Why a code, then an exchange (not a token straight away)?

The token must not travel through the **browser's URL** (history, referrer headers, server logs). So
the OP hands the browser a short-lived, single-use **code**, and the app redeems it for tokens over a
**back-channel** POST the browser never sees. The valuable thing (the token) never touches the
address bar.

### Why PKCE?

A code in a redirect URL can still be **intercepted** (a malicious app registered for the same
redirect, a shared device, a proxy log). [PKCE](../GLOSSARY.md#tokens-jose-oauth-20-openid-connect)
binds the code to the client instance that *started* the flow:

- At `/authorize` the client sends `code_challenge = base64url(SHA-256(verifier))`.
- At `/token` it sends the `verifier`.
- The OP recomputes the hash and compares. A stolen code is useless without the verifier.

mini-oidc requires the **S256** method and rejects `plain` (where the challenge *is* the verifier in
clear — no protection). That "reject the weak option" decision is a case study in the
[security track](../security/README.md).

### ID token vs. access token — two different jobs

This trips everyone up. They are **not** interchangeable:

- **ID token** — *about the human, for the app.* "This person (`sub`) authenticated at `auth_time`,
  here's their `name`/`email` (by scope), and the `nonce` you sent." The app consumes it to know
  *who logged in*. It is **not** a credential for calling APIs.
- **Access token** — *for calling APIs.* Carries `scope` and an audience; presented as a Bearer token
  (e.g. to `/userinfo`, or through mini-gateway). The app **sends** it; it does not read it.

> Rule of thumb: the app *reads* the ID token and *bears* the access token. Sending an ID token to an
> API, or trusting an access token to tell you who logged in, are both classic mistakes.

### The `nonce`

The client puts a `nonce` in the `/authorize` request; the OP echoes it into the ID token. The client
checks it matches — binding the ID token to *this* login and preventing token-substitution. (Distinct
from the crypto nonce in mini-kms.)

---

## How grants/scopes ride along

Both tokens carry the principal's authorization, shaped for the consumer:

- mini-idp's token carries the **`grants` claim** (the per-key-group authorization from stage 1).
- mini-oidc's access token carries **`scope`**, authorized through mini-policy's `ScopeAuthorizer`.

Either way it's the same idea: the resolved authorization from mini-directory, signed into the token,
verified offline downstream.

> **⚠ Wired vs. designed.** mini-oidc needs `--directory-url` to resolve a real human; without it an
> empty in-memory directory resolves nobody, and passkey enrolment is unauthenticated. See
> [`honest-seams.md`](honest-seams.md#3) (#3, #4, #5).

---

## Now read it

- **Machine flow:** `services/mini-idp` → `server/ApiHandlers` (`/oauth/token`),
  `directory/HttpServiceAccountDirectory` (resolve the client).
- **Human flow:** `services/mini-oidc` → `server/OidcHandlers` (`authorize` → `login/passkey/*` →
  `authorize/decision` → `token`), `util/Pkce` (S256), `service/AuthorizationCodeStore`,
  `service/OidcTokens` (ID/access minted through mini-token — *not* re-implemented).

Labs: [`03-machine-identity-end-to-end.md`](../tutorials/03-machine-identity-end-to-end.md) then
[`04-human-sso-end-to-end.md`](../tutorials/04-human-sso-end-to-end.md). Next concept:
[`sessions-vs-tokens.md`](sessions-vs-tokens.md) — the *session* the human flow also creates.
