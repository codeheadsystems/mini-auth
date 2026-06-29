# Lab 04 — Human SSO, end to end

> **Tutorial (hands-on).** Stage 4. ~25 minutes. The human half of the scenario: a person logs in to
> **mini-oidc** with a **passkey**, gets ID + access tokens, and establishes a browser **SSO session**
> the next lab reuses.
>
> **Concepts:** [`what-a-passkey-is.md`](../concepts/what-a-passkey-is.md) +
> [`oauth-and-oidc-flows.md`](../concepts/oauth-and-oidc-flows.md) +
> [`sessions-vs-tokens.md`](../concepts/sessions-vs-tokens.md). **Diagram:**
> [`auth-code-pkce`](../diagrams/auth-code-pkce.md).
>
> **⚠ One step needs a real browser.** The passkey ceremony (WebAuthn) cannot be done with `curl` —
> it needs a browser with a **platform authenticator or a virtual authenticator** (Chrome DevTools →
> *WebAuthn* tab works well). Everything *around* it is shown with `curl` below; the ceremony itself
> is a browser step, driven by the virtual authenticator + the helper script in step 3 — so the lab is
> still **completable end to end**. This lab is honest about the seam rather than faking an assertion.

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

# Register a PUBLIC (PKCE-only) relying-party client and capture its id. Public means no client
# secret — the PKCE verifier is what proves the token request came from the app that started the flow.
REDIRECT="http://127.0.0.1:8477/"     # any registered URI; the browser lands here with ?code=…
CLIENT_ID=$(curl -fsS -X POST "$O/admin/clients" \
  -H "Authorization: Bearer $MINIOIDC_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"name\":\"Demo App\",\"redirectUris\":[\"$REDIRECT\"],\"scopes\":[\"openid\",\"profile\",\"email\"],\"confidential\":false}" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["clientId"])')
echo "client_id = $CLIENT_ID"
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
alongside these steps. Use **Chrome** (or any Chromium browser) for the DevTools virtual authenticator.

**First, generate the PKCE pair** (you'll need the verifier again at the token step):

```bash
VERIFIER=$(openssl rand -base64 60 | tr '+/' '-_' | tr -d '=\n')
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -binary -sha256 | base64 | tr '+/' '-_' | tr -d '=\n')
echo "verifier saved; challenge = $CHALLENGE"
```

1. **Turn on a virtual authenticator and enrol a passkey for `alice`.** Open a mini-oidc page in
   Chrome — `$O/docs` works — then **DevTools → ⋮ More tools → WebAuthn →** *Enable virtual
   authenticator environment* → *Add authenticator* (the defaults are fine). The virtual authenticator
   replaces real hardware. Now open the **Console**, paste
   [`examples/passkey-enroll.js`](../examples/passkey-enroll.js), and run:
   ```js
   enrolPasskey('alice', 'Alice')   // logs: enrol alice → 201 {registered: true}
   ```
   The script must run **on a mini-oidc page** so the WebAuthn ceremony uses mini-oidc's origin (the
   script's header comment explains why a standalone file would fail).
   > Enrolment here is *unauthenticated self-enrolment* — honesty seam
   > [#3](../concepts/honest-seams.md#3). A real deployment gates it.
2. **Start the flow.** Build the authorize URL with your `$CLIENT_ID`, `$REDIRECT`, and `$CHALLENGE`,
   then open it in the same browser tab:
   ```bash
   echo "$O/authorize?client_id=$CLIENT_ID&redirect_uri=$REDIRECT&response_type=code&scope=openid%20profile&state=xyz&nonce=n1&code_challenge=$CHALLENGE&code_challenge_method=S256"
   ```
3. mini-oidc serves a **login page** (no session yet). Enter `alice` and click **Sign in with
   passkey** — the page's JS runs the assertion ceremony (`/login/passkey/start` →
   `/login/passkey/finish`) and the **virtual authenticator answers automatically**. On success
   mini-oidc **sets the session cookie** `mioidc_session` (HttpOnly, SameSite=Lax) and continues to
   `/authorize/continue`.
4. **Consent** → click **Allow** (`POST /authorize/decision`) → the browser redirects to
   `$REDIRECT?code=…&state=xyz`. The target page may show a 404 — that's fine; **copy the `code`
   value straight out of the address bar.**

## 4. Exchange the code (back to curl)

The browser handed your app a **code**. The app redeems it on the back-channel with the **PKCE
verifier** from step 3. Paste the code from the address bar:

```bash
CODE="<code-from-the-address-bar>"
curl -fsS -X POST "$O/token" \
  -d "grant_type=authorization_code&code=$CODE&redirect_uri=$REDIRECT&client_id=$CLIENT_ID&code_verifier=$VERIFIER" \
  | python3 -m json.tool
# (Public/PKCE client: no -u. A confidential client would instead authenticate with -u "id:secret".)
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
RT_OLD="<refresh_token-from-step-4>"
# rotate once — get a NEW refresh_token back
curl -fsS -X POST "$O/token" -d "grant_type=refresh_token&refresh_token=$RT_OLD&client_id=$CLIENT_ID" | python3 -m json.tool
# now replay the SAME old token again:
curl -s -w "\nHTTP %{http_code}\n" -X POST "$O/token" -d "grant_type=refresh_token&refresh_token=$RT_OLD&client_id=$CLIENT_ID"
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
