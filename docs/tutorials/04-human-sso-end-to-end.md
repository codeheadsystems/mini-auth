# Lab 04 — Human SSO, end to end

> **Tutorial (hands-on).** Stage 4. ~25 minutes. The human half of the scenario: a person logs in to
> **mini-oidc** with a **passkey**, gets ID + access tokens, and establishes a browser **SSO session**
> the next lab reuses.
>
> **Concepts:** [`oauth-and-oidc-flows.md`](../concepts/oauth-and-oidc-flows.md) +
> [`sessions-vs-tokens.md`](../concepts/sessions-vs-tokens.md). **Diagram:**
> [`auth-code-pkce`](../diagrams/auth-code-pkce.md).
>
> **⚠ One step needs a real browser.** The passkey ceremony (WebAuthn) cannot be done with `curl` —
> it needs a browser with a **platform authenticator or a virtual authenticator** (Chrome DevTools →
> *WebAuthn* tab works well). Everything *around* it is shown with `curl` below; the ceremony itself
> is a browser step. This lab is honest about that seam rather than faking an assertion.

## 1. Start mini-oidc (with a directory)

To resolve a real human, mini-oidc needs mini-directory. Start both:

```bash
./gradlew :services:mini-directory:installDist :services:mini-oidc:installDist

export MINIDIR_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MINIOIDC_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MINIOIDC_DIRECTORY_TOKEN="$MINIDIR_ADMIN_TOKEN"   # mini-oidc authenticates to the directory's admin API

services/mini-directory/build/install/mini-directory/bin/mini-directory --port 8466 --data-dir "$(mktemp -d)" &

# create the human alice in the directory (lab 01 style)
curl -fsS -X POST http://127.0.0.1:8466/admin/humans \
  -H "Authorization: Bearer $MINIDIR_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"id":"alice","displayName":"Alice","admin":false,"grants":[{"action":"view","resource":"grafana"}]}'

services/mini-oidc/build/install/mini-oidc/bin/mini-oidc \
  --port 8477 --issuer http://127.0.0.1:8477 --rp-id 127.0.0.1 --rp-origin http://127.0.0.1:8477 \
  --directory-url http://127.0.0.1:8466 &

O="http://127.0.0.1:8477"
```

> If you omit `--directory-url`, mini-oidc prints *"No --directory-url configured: using an empty
> in-memory directory (no human will resolve…)"* — honesty seam
> [#4](../concepts/honest-seams.md#4). We pass it, so `alice` resolves.

## 2. Look at the OP's public face (curl)

```bash
curl -fsS "$O/.well-known/openid-configuration" | python3 -m json.tool
```
```json
{ "issuer": "http://127.0.0.1:8477",
  "authorization_endpoint": "http://127.0.0.1:8477/authorize",
  "token_endpoint": "http://127.0.0.1:8477/token",
  "userinfo_endpoint": "http://127.0.0.1:8477/userinfo",
  "jwks_uri": "http://127.0.0.1:8477/jwks.json",
  "end_session_endpoint": "http://127.0.0.1:8477/logout",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "scopes_supported": ["openid", "profile", "email"],
  "id_token_signing_alg_values_supported": ["EdDSA"] }
```

The signing keys are the **same JWKS shape** as mini-idp's — same token plane (`/jwks.json`):

```bash
curl -fsS "$O/jwks.json"   # { "keys": [ { "kty":"OKP","crv":"Ed25519","x":"…","use":"sig","alg":"EdDSA","kid":"…" } ] }
```

## 3. The browser flow (with a passkey)

Now the part that needs a browser. Walk the [auth-code+PKCE diagram](../diagrams/auth-code-pkce.md)
alongside these steps.

1. **Enrol a passkey** (first time only). Open `POST /register/passkey/start` / `/finish` from a small
   page, or use the `/docs` UI. With Chrome DevTools' *WebAuthn* tab, enable a **virtual
   authenticator** first so you don't need real hardware.
   > Enrolment here is *unauthenticated self-enrolment* — honesty seam
   > [#3](../concepts/honest-seams.md#3). A real deployment gates it.
2. **Start the flow.** Navigate the browser to `/authorize` with a PKCE challenge. Generate a
   verifier/challenge pair first:
   ```bash
   VERIFIER=$(openssl rand -base64 60 | tr '+/' '-_' | tr -d '=\n')
   CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | base64 | tr '+/' '-_' | tr -d '=\n')
   echo "$O/authorize?client_id=<your-client>&redirect_uri=<registered>&response_type=code&scope=openid%20profile&state=xyz&nonce=n1&code_challenge=$CHALLENGE&code_challenge_method=S256"
   ```
   (Register a client first via `POST /admin/clients` with the admin token; see `/docs` for the body.)
3. mini-oidc serves a **login page** (no session yet) → you complete the **passkey** ceremony
   (`/login/passkey/start` → `/login/passkey/finish`). On success it **sets the session cookie**
   `mioidc_session` (HttpOnly, SameSite=Lax) and redirects to `/authorize/continue`.
4. **Consent** → `POST /authorize/decision` → you're redirected to your `redirect_uri?code=…&state=xyz`.

## 4. Exchange the code (back to curl)

The browser handed your app a **code**. The app redeems it on the back-channel with the **PKCE
verifier** from step 2:

```bash
curl -fsS -X POST "$O/token" \
  -d "grant_type=authorization_code&code=<code-from-redirect>&redirect_uri=<registered>&code_verifier=$VERIFIER" \
  -u "<client_id>:<client_secret>"      # confidential client; public clients omit -u and rely on PKCE
```
```json
{ "access_token": "eyJ…", "id_token": "eyJ…", "refresh_token": "rt_…", "token_type": "Bearer",
  "expires_in": 300, "scope": "openid profile" }
```

- **Decode the ID token** (lab 02's decoder): `sub: alice`, `auth_time`, your `nonce: n1`, and `name`
  (because `profile` scope). This is the *who-logged-in* document — your app reads it.
- **Use the access token** at `/userinfo`:
  ```bash
  curl -fsS "$O/userinfo" -H "Authorization: Bearer <access_token>"   # { "sub":"alice","name":"Alice", … }
  ```
  Note you *bear* the access token; you *read* the ID token. (Don't mix them — see the concept doc.)

## 5. Refresh rotation + replay defense (predict first)

Trade the refresh token for a fresh pair, then **replay the old one** and predict what happens:

```bash
# rotate once — get a NEW refresh_token back
curl -fsS -X POST "$O/token" -d "grant_type=refresh_token&refresh_token=<rt_old>" -u "<client_id>:<client_secret>"
# now replay the SAME old token again:
curl -s -w "\nHTTP %{http_code}\n" -X POST "$O/token" -d "grant_type=refresh_token&refresh_token=<rt_old>" -u "<client_id>:<client_secret>"
```

**Predict:** the replay is rejected — *and* it revokes the **whole family**, so even the *new* refresh
token you just got is now dead. Presenting a spent refresh token is the signature of theft, so
mini-oidc fails safe by killing the lineage. (`service/RefreshTokenService`.)

```bash
kill %1 %2 2>/dev/null   # stop the services
```

## What you just learned

- **Human SSO = the code/PKCE dance** so the token never rides the browser URL and a stolen code is
  useless without the verifier.
- **ID token ≠ access token:** read one, bear the other.
- **A session is created alongside the tokens** (the cookie) — distinct lifetime, reused next lab.
- **Refresh rotation with family-revoke** turns token theft into a self-defeating move.

## Try it yourself (optional)

- Hit `/authorize` with `code_challenge_method=plain` — it's rejected (the
  [PKCE-downgrade finding](../security/README.md)).
- Decode the access token vs. the ID token and list which claims differ (`aud`, `scope` vs.
  `nonce`, `auth_time`, `name`).

Next: stage 5, [`05-gate-a-no-auth-app.md`](05-gate-a-no-auth-app.md) — reuse *this* session to reach
a no-auth app through mini-gateway.
