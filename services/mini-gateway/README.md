# mini-gateway

The **forward-auth endpoint** for a reverse proxy. A proxy calls it *before* forwarding each request;
mini-gateway validates the caller, evaluates the target route, and answers **allow / deny / log-in**.
It puts authentication in front of upstreams that have none of their own — without those upstreams
knowing anything about OIDC.

It is **educational, but homelab-functional**, and pure **composition**:

| Concern | Delegated to |
| --- | --- |
| Browser SSO session validation | the **shared** mini-token `SessionService` over the *same* `sessions.json` mini-oidc writes |
| Bearer (API) token verification | mini-token's `JwsClaimsVerifier` against mini-oidc's JWKS |
| Per-route allow/deny decision | **mini-policy** (`GrantBasedPolicyEngine`), driven by a config file |

## The decision

For each proxied request the gateway reads the original method/URI (from `X-Forwarded-*` /
`X-Original-*`) and the client's own `Cookie` / `Authorization` headers, then:

```
authenticate ─ bearer access token (API)  ──▶ JwsClaimsVerifier + JWKS  ──▶ subject + scopes
             └ mini-oidc SSO session cookie ─▶ shared SessionService     ──▶ subject

evaluate route (mini-policy) ─┬─ PUBLIC route ........................... 200 ALLOW
                              ├─ AUTHENTICATED route + valid caller ..... 200 ALLOW (+ identity headers)
                              ├─ SCOPE route + caller holds the scope ... 200 ALLOW
                              ├─ no valid caller, browser ............... 302 → mini-oidc login (?rd=<orig>)
                              ├─ no valid caller, API ................... 401 (WWW-Authenticate: Bearer)
                              └─ valid caller, route forbids it ......... 403
```

On allow, the proxy is told to copy these onto the upstream request, so a no-auth upstream learns who
the caller is: `X-Auth-Subject`, `X-Auth-Scope`, `X-Auth-Source` (`session` or `token`).

## Per-route policy (config-driven)

`routes.json` — rules are matched in order by path prefix; first match wins; unmatched is denied.

```json
{
  "routes": [
    { "pathPrefix": "/health",  "access": "PUBLIC" },
    { "pathPrefix": "/admin",   "access": "SCOPE", "scope": "admin" },
    { "pathPrefix": "/",        "access": "AUTHENTICATED" }
  ]
}
```

A `SCOPE` rule is decided by mini-policy over the caller's scopes (an `admin` principal is permitted
everything). With no `--routes-file`, the default is a single catch-all that gates everything behind
login.

## Run it standalone

```bash
services/mini-gateway/build/install/mini-gateway/bin/mini-gateway \
  --port 8488 \
  --sessions-file ~/.mini-oidc/sessions.json \
  --routes-file ./routes.json \
  --login-url "https://example.com/authorize?response_type=code&client_id=gateway&redirect_uri=https://example.com/&scope=openid&code_challenge=...&code_challenge_method=S256" \
  --jwks-url https://example.com/jwks.json --issuer https://example.com --audience https://example.com/userinfo
```

`--jwks-url`/`--issuer`/`--audience` are optional (omit to disable the bearer path and accept only
SSO sessions). The verify endpoint is `GET /verify`.

## Sharing the session with mini-oidc

The gateway does **not** invent a second session store: it opens the **same** `sessions.json` that
mini-oidc writes (mini-oidc's `--data-dir/sessions.json`), through the shared mini-token
`SessionService`. mini-oidc is the only writer (create on login, delete on logout); the gateway is a
reader. So a user who logs in at mini-oidc immediately has a session the gateway honours — provided
the SSO cookie (`mioidc_session`, host-only, `Path=/`) actually reaches the gated app:

- **Same host, path-routed** (simplest): serve mini-oidc and the apps under one hostname
  (`example.com/…`); the host-only cookie is sent to every path. This is what the snippets below do.
- **Subdomains**: the cookie must be scoped to the parent domain — a future mini-oidc option to set
  `Domain=.example.com`. Not enabled today.

## Example: Traefik (Docker)

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

## Example: Caddy

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

## Example: nginx `auth_request`

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
   against mini-oidc's JWKS and applies the same per-route policy.

## Security notes

- **No oracle.** Every authentication failure collapses to one outcome (401/403/302); the gateway
  never reveals *why*. Bearer verification fails closed (unknown key / wrong iss-aud / expired → deny).
- **No secrets in logs.** Cookies and tokens are never logged; access logs are method/path/status.
- **Deny by default.** A request matching no route rule is forbidden.
- **Loopback by default.** The proxy reaches the gateway over the loopback/Docker network; the verify
  endpoint is never exposed to clients directly, and real deployments terminate TLS at the proxy.
- **Reuse, not reinvention.** The session store and JWS verification are mini-token's; the decision is
  mini-policy's. There is exactly one session mechanism in the family.
