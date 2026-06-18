# Mini Gateway

**mini-gateway** is the **forward-auth endpoint** for a reverse proxy. A proxy (Traefik
ForwardAuth, Caddy `forward_auth`, nginx `auth_request`) calls it *before* forwarding each request;
mini-gateway validates the caller, evaluates the target route, and answers **allow / deny / log-in**.
It puts authentication in front of upstreams that have none of their own — without those upstreams
knowing anything about OIDC.

It is an **educational** project (a sibling to **mini-kms** and **mini-idp**): heavily commented,
built to be *read*, and **pure composition** — it invents no crypto, no session format, and no
decision engine of its own. Every hard part is delegated to a library the rest of the family already
uses:

| Concern | Delegated to |
| --- | --- |
| Browser SSO session validation | the **shared** mini-token `SessionService` over the *same* `sessions.json` mini-oidc writes |
| Bearer (API) token verification | mini-token's `JwsClaimsVerifier`, offline, against mini-oidc's JWKS |
| Per-route allow / deny decision | **mini-policy** (`GrantBasedPolicyEngine`), driven by a config file |

> **Not for production as-is.** The gateway binds loopback and trusts the reverse proxy in front of
> it: it reads the *proxied* request's method/URI from `X-Forwarded-*` / `X-Original-*` headers, so a
> real deployment **must** sit behind a proxy that strips and sets those headers and terminates TLS.
> Exposing `/verify` directly to clients would let them forge the path being checked.

## Table of contents

- [What it does](#what-it-does)
- [Glossary](#glossary)
- [Architecture](#architecture)
- [The decision flow (step by step)](#the-decision-flow-step-by-step)
- [Per-route policy (config-driven)](#per-route-policy-config-driven)
- [Sharing the session with mini-oidc](#sharing-the-session-with-mini-oidc)
- [Endpoints & responses](#endpoints--responses)
- [Configuration reference](#configuration-reference)
- [Running it standalone](#running-it-standalone)
- [Wiring a reverse proxy](#wiring-a-reverse-proxy)
  - [Traefik (Docker)](#example-traefik-docker)
  - [Caddy](#example-caddy)
  - [nginx `auth_request`](#example-nginx-auth_request)
- [The demo: gating a no-auth upstream](#the-demo-gating-a-no-auth-upstream-behind-a-mini-oidc-login)
- [Security notes](#security-notes)
- [Building & testing](#building--testing)

## What it does

- **Answers a single forward-auth question** — `GET /verify` (registered for *every* method): *should
  this proxied request be allowed, and if so, who is the caller?*
- **Authenticates two kinds of caller.** An **API client** presenting `Authorization: Bearer <access
  token>` (verified offline against mini-oidc's JWKS), or a **browser** carrying the shared mini-oidc
  SSO session cookie (looked up in the shared session store). Bearer is tried first, then the cookie.
- **Decides per route** through mini-policy, driven by a `routes.json`: ordered prefix rules, each
  `PUBLIC`, `AUTHENTICATED`, or `SCOPE`. **Deny by default** — a path that matches no rule is forbidden.
- **Tells the upstream who called.** On allow it returns identity headers (`X-Auth-Subject`,
  `X-Auth-Scope`, `X-Auth-Source`) that the proxy copies onto the forwarded request, so a no-auth app
  still learns the caller's identity.
- **Sends browsers to log in.** An unauthenticated *browser* hitting a gated route gets a **302** to
  mini-oidc's authorization endpoint (with the original URL preserved); an unauthenticated *API
  client* gets a **401**.

## Glossary

- **Forward auth** — a reverse-proxy pattern where, for each incoming request, the proxy first makes a
  sub-request to an external *auth endpoint* (here, `/verify`). A 2xx means "allow, and here are
  headers to copy onto the upstream request"; a 401/403 is returned to the client; a 30x is followed
  (used to send browsers to login). Traefik calls this **ForwardAuth**, Caddy **`forward_auth`**,
  nginx **`auth_request`**.
- **The proxied request** — the *original* request the client made to the protected app. The proxy
  forwards its method/URI/host to `/verify` in `X-Forwarded-Method` / `X-Forwarded-Uri` /
  `X-Forwarded-Host` / `X-Forwarded-Proto` (or the nginx-style `X-Original-Method` / `X-Original-URI`).
  mini-gateway evaluates *that* path, not the literal `/verify` request line.
- **Caller / `AuthenticatedUser`** — the validated identity behind a proxied request: a `subject`, an
  `admin` flag, a list of `scopes`, and a `source` (`"session"` or `"token"`). It resolves to a
  mini-policy `Principal(subject, admin)` for the decision.
- **Source** — *how* the caller was authenticated: `token` (a verified bearer JWS, carrying scopes) or
  `session` (a live SSO session, which carries **no scopes**). Surfaced as `X-Auth-Source`.
- **Route rule** — one entry in `routes.json`: a `pathPrefix`, optional `methods`, an `access` mode,
  and (for `SCOPE`) a required `scope`. Rules are matched **in order**; the first match wins.
- **Scope** — an OIDC scope string. The gateway expresses it as a mini-policy `Grant(Action.of(scope),
  Resource.of("oidc:scope"))`, exactly as mini-oidc does, so the `SCOPE` decision uses the family's
  shared decision function rather than an ad-hoc string check.

## Architecture

One application module under base package `com.codeheadsystems.minigateway`. It holds no secrets of
its own — it validates the family's sessions and tokens — so there is no admin API and no admin token.

- **`server`** — `ServerMain` / `GatewayServer` (the composition root), `ServerConfig`,
  `GatewayHandlers` (the `/verify` + `/health` endpoints), and the reused `http/` router over the JDK
  `com.sun.net.httpserver.HttpServer`. Each request runs on a virtual thread; binds loopback.
- **`auth`** — the two authenticators and the JWKS seam:
  - `SessionAuthenticator` — looks the session cookie up through the **shared** mini-token
    `SessionService`. A session carries no scopes, so it satisfies `PUBLIC` / `AUTHENTICATED` routes
    but never a `SCOPE` route.
  - `BearerAuthenticator` — verifies a bearer JWS **offline** with mini-token's `JwsClaimsVerifier`
    (signature, then `iss` / `aud` / expiry, with a 5-second leeway), then reads `sub`, the
    space-delimited `scope` claim, and an optional `admin` flag. Any failure collapses to *empty*.
  - `JwksProvider` (SPI) + `HttpJwksProvider` — fetches mini-oidc's `/jwks.json` and caches it for
    **5 minutes**, so verification stays offline between refreshes but still picks up key rotation. A
    fetch failure reuses the last good key set, else yields an empty set (which **fails closed**). The
    SPI lets a test inject a fixed key set.
- **`service/RoutePolicy`** + **`model`** — the config-driven decision. `GatewayRoutes` /
  `RouteRule` / `RouteAccess` model `routes.json`; `RoutePolicy.evaluate(...)` matches the first rule
  and returns an `Outcome` of `ALLOW`, `UNAUTHENTICATED`, or `FORBIDDEN`. `SCOPE` decisions defer to a
  `GrantBasedPolicyEngine` built from the caller's scopes (an `admin` principal is permitted
  everything). Unmatched → `FORBIDDEN`.
- **`store/JsonStore`** — the reused atomic-`0600` JSON store, used **read-only** here to open the
  shared `sessions.json`.

```
              ┌──────────── GET /verify (from the reverse proxy) ────────────┐
              │  X-Forwarded-Method/-Uri/-Host/-Proto  +  client Cookie/Authorization
              ▼
   authenticate ─ bearer access token (API)  ──▶ JwsClaimsVerifier + JWKS (cached 5m) ──▶ subject + scopes   [source=token]
                └ mini-oidc SSO session cookie ─▶ shared SessionService (sessions.json) ──▶ subject           [source=session]

   evaluate route (mini-policy) ─┬─ PUBLIC route ............................ 200 ALLOW
                                 ├─ AUTHENTICATED route + valid caller ...... 200 ALLOW (+ identity headers)
                                 ├─ SCOPE route + caller holds the scope .... 200 ALLOW (+ identity headers)
                                 ├─ no valid caller, browser ................ 302 → mini-oidc login (?rd=<orig>)
                                 ├─ no valid caller, API .................... 401 (WWW-Authenticate: Bearer)
                                 └─ valid caller, route forbids it .......... 403
```

## The decision flow (step by step)

For each `/verify` call (`GatewayHandlers.verify`):

1. **Reconstruct the proxied request.** Read the method from `X-Forwarded-Method` (or
   `X-Original-Method`, default `GET`) and the URI from `X-Forwarded-Uri` (or `X-Original-URI`,
   default `/`). Strip the query string to get the path.
2. **Authenticate the caller.** Try the bearer token first (if bearer is configured) using the
   request's `Authorization` header; if that yields nothing, look up the session cookie
   (`config.cookieName()`, default `mioidc_session`) in the shared store. Either may produce an
   `AuthenticatedUser`, or neither does.
3. **Evaluate the route** (`RoutePolicy.evaluate`):
   - No matching rule → `FORBIDDEN` (**deny by default**).
   - `PUBLIC` rule → `ALLOW` (caller optional).
   - No caller and the rule needs one → `UNAUTHENTICATED`.
   - `AUTHENTICATED` rule with a caller → `ALLOW`.
   - `SCOPE` rule → build a `GrantBasedPolicyEngine` from the caller's scopes and ask mini-policy
     whether the principal may perform `Action.of(scope)` on `oidc:scope`. `ALLOW` or `FORBIDDEN`.
4. **Answer:**
   - `ALLOW` → **200** with `{"allow": true}`; if a caller is present, add `X-Auth-Subject`,
     `X-Auth-Scope` (space-joined scopes), `X-Auth-Source`.
   - `FORBIDDEN` → **403** `{"error":"forbidden"}`.
   - `UNAUTHENTICATED` → if the request looks like a **browser navigation** (`Accept: text/html`, or
     `Sec-Fetch-Mode: navigate`) *and* a `--login-url` is configured → **302** to that URL with the
     original absolute URL appended as the return parameter (default `rd`). Otherwise → **401** with
     `WWW-Authenticate: Bearer`.

## Per-route policy (config-driven)

`routes.json` — an ordered list; the **first** rule whose `pathPrefix` (and optional `methods`)
matches wins; an unmatched path is **denied**.

```json
{
  "routes": [
    { "pathPrefix": "/health", "access": "PUBLIC" },
    { "pathPrefix": "/admin",  "access": "SCOPE", "scope": "admin" },
    { "pathPrefix": "/",       "access": "AUTHENTICATED" }
  ]
}
```

(This is `examples/routes.json`.) A rule may also pin `methods` (e.g. `"methods": ["GET","HEAD"]`);
omitted/empty means all methods. The three access modes:

- **`PUBLIC`** — always allowed, with or without a caller.
- **`AUTHENTICATED`** — any valid caller (an SSO session **or** a verified bearer token).
- **`SCOPE`** — a valid caller that mini-policy says holds the named `scope`. Because a session
  carries no scopes, a `SCOPE` route effectively requires a **bearer token** — unless the caller is an
  `admin` principal, who is permitted everything. A `SCOPE` rule **must** name a `scope` (enforced at
  load).

With **no** `--routes-file`, the default table is a single catch-all (`/` → `AUTHENTICATED`): the
whole site is gated behind login.

## Sharing the session with mini-oidc

The gateway does **not** invent a second session store: it opens the **same** `sessions.json` that
mini-oidc writes (mini-oidc's `--data-dir/sessions.json`), through the shared mini-token
`SessionService`. There is exactly one session mechanism in the family:

- **mini-oidc is the sole writer** — it creates a session on login and deletes it on logout. The
  gateway is a **reader**: it constructs its `SessionService` with a zero idle-extension window, so it
  never mutates the file; mini-oidc owns session lifetime and expiry.
- The cookie name is the shared `SessionService.DEFAULT_COOKIE_NAME` (`mioidc_session`), overridable
  with `--cookie-name` if you also reconfigure mini-oidc.

For that cookie to reach the gated app, the cookie's scope must cover it. mini-oidc sets the SSO
cookie **host-only** (no `Domain`), `Path=/`, so:

- **Same host, path-routed** (simplest): serve mini-oidc and the apps under one hostname
  (`example.com/…`); the host-only cookie is sent to every path. This is what the snippets below do.
- **Subdomains**: the cookie would need `Domain=.example.com` — a future mini-oidc option, not
  enabled today.

## Endpoints & responses

| Method & path | Purpose |
| --- | --- |
| `* /verify` | The forward-auth check (registered for `GET`/`POST`/`PUT`/`DELETE`/`PATCH`/`HEAD`/`OPTIONS`). Returns 200/302/401/403 per the decision flow above. |
| `GET /health` | Liveness → `{"status":"ok"}`. |

Identity headers returned on **allow** (configure the proxy to copy these onto the upstream request):

| Header | Value |
| --- | --- |
| `X-Auth-Subject` | the caller's `sub` / session subject |
| `X-Auth-Scope` | space-joined scopes (empty for a session) |
| `X-Auth-Source` | `token` or `session` |

## Configuration reference

Flags override environment variables override defaults (mirrors the family's other `ServerConfig`s).

| Flag | Env var | Default | Meaning |
| --- | --- | --- | --- |
| `--host` | `MINIGW_HOST` | `127.0.0.1` | Loopback bind host. |
| `--port` | `MINIGW_PORT` | `8488` | TCP port (`0` = ephemeral). |
| `--sessions-file` | `MINIGW_SESSIONS_FILE` | `~/.mini-oidc/sessions.json` | The **shared** SSO session store mini-oidc writes. |
| `--cookie-name` | `MINIGW_COOKIE_NAME` | `mioidc_session` | SSO session cookie name (must match mini-oidc). |
| `--routes-file` | `MINIGW_ROUTES_FILE` | — (gate everything behind login) | Per-route policy JSON. |
| `--login-url` | `MINIGW_LOGIN_URL` | — | Where to send unauthenticated browsers (mini-oidc `/authorize`). If unset, browsers also get 401. |
| `--return-param` | `MINIGW_RETURN_PARAM` | `rd` | Query param carrying the original URL on the login redirect. |
| `--jwks-url` | `MINIGW_JWKS_URL` | — (bearer disabled) | mini-oidc's `/jwks.json` for bearer verification. |
| `--issuer` | `MINIGW_ISSUER` | — | Expected bearer `iss`. |
| `--audience` | `MINIGW_AUDIENCE` | — | Expected bearer `aud`. |

The gateway holds **no secret of its own** — no admin token. Bearer verification is enabled only when
`--jwks-url` is set; otherwise only SSO sessions are accepted.

## Running it standalone

Requires JDK 21+. Build the launcher with `./gradlew :services:mini-gateway:installDist`.

```bash
services/mini-gateway/build/install/mini-gateway/bin/mini-gateway \
  --port 8488 \
  --sessions-file ~/.mini-oidc/sessions.json \
  --routes-file ./routes.json \
  --login-url "https://example.com/authorize?response_type=code&client_id=gateway&redirect_uri=https://example.com/&scope=openid&code_challenge=...&code_challenge_method=S256" \
  --jwks-url https://example.com/jwks.json --issuer https://example.com --audience https://example.com/userinfo
```

`--jwks-url` / `--issuer` / `--audience` are optional (omit to disable the bearer path and accept only
SSO sessions). The verify endpoint is `GET /verify` (and every other method).

## Wiring a reverse proxy

The proxy reaches the gateway over the loopback/Docker network and is responsible for setting the
`X-Forwarded-*` (or `X-Original-*`) headers and copying the identity headers back onto the upstream
request. Runnable examples live in `services/mini-gateway/examples/` (`routes.json`, a Traefik
`docker-compose`, and a `Caddyfile`).

### Example: Traefik (Docker)

`docker-compose.yml` (sketch — one shared volume carries `sessions.json`):

```yaml
services:
  traefik:
    image: traefik:v3
    command:
      - --providers.docker=true
      - --entrypoints.web.address=:80
    ports: ["80:80"]
    volumes: ["/var/run/docker.sock:/var/run/docker.sock:ro"]

  mini-oidc:
    image: mini-oidc
    command: >
      --port 8477 --issuer http://example.localhost --rp-id example.localhost
      --rp-origin http://example.localhost --data-dir /data --directory-url http://mini-directory:8466
    environment: { MINIOIDC_ADMIN_TOKEN: dev-admin, MINIOIDC_DIRECTORY_TOKEN: dev-dir }
    volumes: ["sso:/data"]                              # shares sessions.json with the gateway
    labels:
      - traefik.http.routers.oidc.rule=Host(`example.localhost`) && PathPrefix(`/authorize`,`/token`,`/login`,`/jwks.json`,`/.well-known`,`/userinfo`,`/logout`,`/register`)
      - traefik.http.services.oidc.loadbalancer.server.port=8477

  mini-gateway:
    image: mini-gateway
    command: >
      --port 8488 --sessions-file /data/sessions.json --routes-file /etc/routes.json
      --login-url http://example.localhost/authorize?response_type=code&client_id=gateway&redirect_uri=http://example.localhost/&scope=openid&code_challenge=PLACEHOLDER&code_challenge_method=plain
      --jwks-url http://mini-oidc:8477/jwks.json --issuer http://example.localhost --audience http://example.localhost/userinfo
    volumes: ["sso:/data", "./routes.json:/etc/routes.json:ro"]

  whoami:                                               # a no-auth upstream
    image: traefik/whoami
    labels:
      - traefik.http.routers.app.rule=Host(`example.localhost`)
      - traefik.http.routers.app.middlewares=forward-auth@docker
      - traefik.http.middlewares.forward-auth.forwardauth.address=http://mini-gateway:8488/verify
      - traefik.http.middlewares.forward-auth.forwardauth.authResponseHeaders=X-Auth-Subject,X-Auth-Scope,X-Auth-Source

volumes: { sso: {} }
```

Traefik's ForwardAuth sends the client's headers plus `X-Forwarded-Method`/`-Uri`/`-Host`/`-Proto` to
`/verify`, and on a 2xx copies the `authResponseHeaders` onto the request it forwards to `whoami`.

### Example: Caddy

```caddyfile
example.localhost {
    # The OP's own routes go straight to mini-oidc.
    @oidc path /authorize* /token /login* /jwks.json /.well-known/* /userinfo /logout /register/*
    reverse_proxy @oidc mini-oidc:8477

    # Everything else is gated by the forward-auth check, then proxied to the no-auth app.
    forward_auth mini-gateway:8488 {
        uri /verify
        copy_headers X-Auth-Subject X-Auth-Scope X-Auth-Source
    }
    reverse_proxy whoami:80
}
```

Caddy's `forward_auth` forwards the request to `/verify`; a 2xx continues to `reverse_proxy` (copying
the listed headers), a 401/403 is returned to the client, and a 30x is followed (redirect to login).

### Example: nginx `auth_request`

```nginx
location = /verify {
    internal;
    proxy_pass http://mini-gateway:8488/verify;
    proxy_set_header X-Original-URI    $request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
}
location / {
    auth_request /verify;
    auth_request_set $sub $upstream_http_x_auth_subject;
    proxy_set_header X-Auth-Subject $sub;
    error_page 401 = @login;            # redirect browsers to mini-oidc
    proxy_pass http://whoami:80;
}
location @login { return 302 http://example.localhost/authorize?...; }
```

## The demo: gating a no-auth upstream behind a mini-oidc login

1. Bring the stack up. Register a `gateway` client in mini-oidc (`POST /admin/clients`) and a user in
   mini-directory; enrol the user's passkey at mini-oidc.
2. Browse to `http://example.localhost/` (the `whoami` app). The gateway sees no session →
   **302 to mini-oidc** `/authorize`.
3. Complete the passkey login at mini-oidc. mini-oidc sets the `mioidc_session` cookie (host-only,
   so it covers the whole `example.localhost` site) and records the session in the shared
   `sessions.json`.
4. Navigate back to `http://example.localhost/`. The browser now sends `mioidc_session`; the gateway
   validates it against the shared store → **200**, and `whoami` shows the `X-Auth-Subject` header.
5. An API client instead presents `Authorization: Bearer <access token>`; the gateway verifies it
   against mini-oidc's JWKS and applies the same per-route policy (so it can satisfy `SCOPE` routes a
   bare session cannot).

## Security notes

- **No oracle.** Every authentication failure collapses to one outcome (401 / 403 / 302); the gateway
  never reveals *why*. Bearer verification fails **closed** — unknown key, wrong `iss`/`aud`, or
  expired all yield empty, and an empty JWKS (e.g. the OP is unreachable) rejects every token.
- **Deny by default.** A request matching no route rule is forbidden; only an explicit rule allows.
- **No secrets in logs.** Cookies and tokens are never logged; the gateway holds no admin token.
- **Loopback by default & trust the proxy.** The gateway binds `127.0.0.1` and reads the request to
  evaluate from `X-Forwarded-*` / `X-Original-*`. It must sit behind a reverse proxy that sets those
  headers and terminates TLS, and `/verify` must never be exposed to clients directly (they could
  forge the path being checked).
- **Reuse, not reinvention.** The session store and JWS verification are mini-token's; the decision is
  mini-policy's. One session mechanism, one decision function, shared across the family.

## Building & testing

```bash
./gradlew build                                   # compile + all tests (the CI gate)
./gradlew :services:mini-gateway:installDist      # runnable launcher at build/install/mini-gateway/bin/mini-gateway
```

The test suite covers the full forward-auth surface end to end (`ForwardAuthTest`): a valid SSO
session allowed with identity headers, an unauthenticated browser redirected to login, an
unauthenticated API client getting 401, a public route allowing anonymous access, a session being
forbidden on a scope route, a bearer token with the required scope allowed, and a bearer token for the
wrong audience rejected. `RoutePolicyTest` exercises the decision directly (public / authenticated /
scope / admin-everywhere / deny-by-default), and `ServerConfigTest` covers flag and environment
resolution.
