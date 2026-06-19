# Lab 05 — Gate a no-auth app

> **Tutorial (hands-on, guaranteed to succeed).** Stage 5. ~15 minutes. Put **mini-gateway** in front
> of an app that has no auth of its own, and watch it answer **allow / 302-to-login / 401 / 403** per
> route. You drive `/verify` directly (the way a reverse proxy would), so the lab needs no Docker —
> though the shipped examples wire a real proxy if you want it.
>
> **Concept:** [`authn-vs-authz.md`](../concepts/authn-vs-authz.md) (authZ at the edge) +
> [`sessions-vs-tokens.md`](../concepts/sessions-vs-tokens.md). **Diagram:**
> [`forward-auth`](../diagrams/forward-auth.md).

## How forward-auth works

A reverse proxy (Traefik / Caddy / nginx) calls `GET /verify` *before* forwarding each request,
passing the original method/path in `X-Forwarded-*` headers and the client's `Cookie` /
`Authorization`. mini-gateway answers, and the proxy forwards **only on 200**. We'll *be* the proxy
with `curl`.

## 1. Start mini-gateway with a route policy

The shipped `examples/routes.json` is a good starting policy:

```json
{ "routes": [
  { "pathPrefix": "/health", "access": "PUBLIC" },
  { "pathPrefix": "/admin",  "access": "SCOPE", "scope": "admin" },
  { "pathPrefix": "/",       "access": "AUTHENTICATED" }
] }
```

Rules are **ordered, first-match wins**, and anything unmatched is **denied**. Start the gateway:

```bash
./gradlew :services:mini-gateway:installDist

SESS=$(mktemp); echo '{}' > "$SESS"   # empty shared session store for now
services/mini-gateway/build/install/mini-gateway/bin/mini-gateway --port 8488 \
  --routes-file services/mini-gateway/examples/routes.json \
  --sessions-file "$SESS" \
  --login-url "https://oidc.example/authorize?client_id=gw&response_type=code&scope=openid&code_challenge=x&code_challenge_method=S256" &

GW="http://127.0.0.1:8488"
```

The banner reads `sessions: <file>   bearer: disabled` (we didn't pass `--jwks-url`, so only session
auth is active — fine for this lab).

## 2. Probe each route — predict the answer first

A tiny helper to read just the status + relevant headers:

```bash
probe() {  # $1 = path,  $2 = "html" to simulate a browser
  local h=""; [ "$2" = html ] && h='-H Accept:text/html'
  curl -s -D - -o /dev/null $h -H "X-Forwarded-Method: GET" -H "X-Forwarded-Uri: $1" "$GW/verify" \
    | grep -iE '^HTTP|^location|^x-auth|^www-authenticate'
}
```

**Predict each, then run it:**

**(a) PUBLIC route →** allow:
```bash
probe /health
# HTTP/1.1 200 OK
# X-Auth-Subject:        ← note: emitted but EMPTY
# X-Auth-Scope:
# X-Auth-Source:
```
The `X-Auth-*` headers are present **but empty**. That's deliberate: the proxy is configured to copy
them onto the upstream, so emitting them empty *overwrites* any `X-Auth-Subject: admin` a client tried
to inject. (The [forward-auth header-trust finding](../security/README.md).)

**(b) AUTHENTICATED route, no credentials, API client →** 401:
```bash
probe /dashboard
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: Bearer
```

**(c) Same route, but a browser →** 302 to login, carrying the original URL back:
```bash
probe /dashboard html
# HTTP/1.1 302 Temporary Redirect
# Location: https://oidc.example/authorize?...&rd=http%3A%2F%2F127.0.0.1%3A8488%2Fdashboard
```
An API client gets a clean 401; a *browser* gets bounced to mini-oidc to log in, then sent back. Same
non-authentication, two answers — chosen by `Accept`/`Sec-Fetch-Mode`.

**(d) SCOPE route `/admin`, no credentials →** 401 (you must authenticate before scope can be checked):
```bash
probe /admin/users
# HTTP/1.1 401 Unauthorized
```

**(e) Path confusion — does normalization hold?** Ask for `/x/../admin`. **Predict:** is it treated
as the `PUBLIC`/`AUTHENTICATED` `/` prefix, or normalized to `/admin`?
```bash
probe /x/../admin
# HTTP/1.1 401 Unauthorized      ← normalized to /admin, then the SCOPE rule applies
```
The gateway **normalizes the path before matching**, so `..` traversal can't dodge a deny-by-default
rule. (The [path-confusion finding](../security/README.md).)

```bash
kill %1 2>/dev/null   # stop the gateway
```

## 3. The session link (concept) + the real-proxy path

We used an empty session store. In a real setup, **mini-oidc writes** `sessions.json` (lab 04) and
**mini-gateway reads the same file** — so a human who logged in via mini-oidc is recognized here with
no second login, as long as the cookie (`mioidc_session`) reaches both (shared hostname). See
[`sessions-vs-tokens.md`](../concepts/sessions-vs-tokens.md).

Two things you'd notice with a real session/token:

- A **session** satisfies `PUBLIC` and `AUTHENTICATED` routes, but **not** a `SCOPE` route — a session
  carries *no scopes*. For `/admin` you need an **access token** with the `admin` scope (pass
  `--jwks-url`/`--issuer`/`--audience` to enable bearer auth). That session-vs-scope boundary is in
  the [threat-model overview](../security/threat-model-overview.md).

To run it behind an **actual proxy**, the repo ships working examples that gate a no-auth `whoami`
behind a mini-oidc login:

```bash
ls services/mini-gateway/examples/    # routes.json  docker-compose.traefik.yml  Caddyfile
```

See `services/mini-gateway/README.md` for the Traefik / Caddy / nginx snippets (which headers to set,
which to strip).

## What you just learned

- **Forward-auth gates a no-auth app** by answering a subrequest: allow / 302 / 401 / 403, deny by
  default for unmatched paths.
- **API vs. browser** get different non-auth answers (401 vs. 302-to-login).
- **`X-Auth-*` always emitted (empty when anonymous)** so the proxy overwrites spoofed identity
  headers; **paths are normalized before matching** so `..` can't dodge a rule.
- **mini-gateway reuses the shared session + JWS verification** — it invents no new auth.

Next: stage 6, [`06-protect-the-signing-keys.md`](06-protect-the-signing-keys.md) — the capstone:
the family encrypts its *own* signing keys.
