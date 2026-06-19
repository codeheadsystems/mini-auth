# How-to: SSO for your homelab

> **How-to (task-oriented). The operator's destination.** Put a single passkey login in front of your
> no-auth homelab apps, going from a loopback proof-of-concept to a behind-TLS-proxy deployment. If
> you want to *understand* the flow first, do [lab 04](../tutorials/04-human-sso-end-to-end.md) +
> [lab 05](../tutorials/05-gate-a-no-auth-app.md); this page is the recipe.

## The shape

```
browser ──▶ reverse proxy ──forward-auth──▶ mini-gateway ──(reads)──▶ mini-oidc sessions.json
              │  (Traefik/Caddy/nginx)            │
              └── on 200, forwards to ───────────▶ your no-auth app (Grafana, etc.)
```

One login at **mini-oidc** establishes a session; **mini-gateway** (called by your proxy before every
request) recognizes that session and lets the request through to an app that has no auth of its own.

## 1. Stand it up locally first (loopback)

Use the family launcher to get a working baseline, then point a proxy at it:

```bash
docs/examples/run-family.sh        # directory + idp + oidc + gateway on loopback
```

mini-gateway comes up reading mini-oidc's `sessions.json` and JWKS. The shipped examples gate a
no-auth `whoami` behind the login:

```bash
ls services/mini-gateway/examples/    # routes.json  docker-compose.traefik.yml  Caddyfile
```

Bring up the Traefik example (or the Caddyfile) per `services/mini-gateway/README.md`, log in once,
and watch `whoami` become reachable only after login. **Prove it locally before exposing anything.**

## 2. Write your route policy

`routes.json` is ordered, first-match-wins, deny-by-default:

```json
{ "routes": [
  { "pathPrefix": "/public", "access": "PUBLIC" },
  { "pathPrefix": "/admin",  "access": "SCOPE", "scope": "admin" },
  { "pathPrefix": "/",       "access": "AUTHENTICATED" }
] }
```

- `PUBLIC` — no auth.
- `AUTHENTICATED` — any logged-in human (a **session** suffices).
- `SCOPE` — needs an **access token** carrying that scope. A session alone is **not** enough (sessions
  carry no scopes) — so a `SCOPE` route requires bearer auth (`--jwks-url`/`--issuer`/`--audience`).

## 3. Going beyond loopback — the checklist

Exposing to your LAN/internet is a deliberate step. Do **all** of:

- [ ] **Terminate TLS at the proxy.** Never expose the services' HTTP listeners directly.
- [ ] **`--secure-cookies`** on mini-oidc (and the gateway) so the session cookie is `Secure`.
- [ ] **Shared hostname.** The session cookie is host-only, `Path=/` — mini-oidc and the gated app must
      share a hostname for the cookie to reach both. Use subpaths or a shared parent domain.
- [ ] **`/verify` is proxy-only.** mini-gateway must be reachable *only* by the proxy (loopback/Docker
      network), never by clients. The proxy must **set `X-Forwarded-*` and strip client `X-Auth-*`**
      (see the [forward-auth header-trust finding](../security/README.md)).
- [ ] **Gate passkey enrolment.** `/register/passkey/**` is unauthenticated self-enrolment out of the
      box ([honest seam #3](../concepts/honest-seams.md#3)) — put it behind an invite/existing
      session/admin step for a real deployment.
- [ ] **Persist credentials.** pk-auth's store is in-memory by default
      ([#5](../concepts/honest-seams.md#5)); swap in a persistent store
      ([`swap-an-spi.md`](swap-an-spi.md)) or your passkeys vanish on restart.
- [ ] **Real secrets, from files.** Generate with `openssl rand -hex 32`, store `0600`, pass via
      `*-token-file` ([`configuration-and-secrets.md`](configuration-and-secrets.md)).

## 4. Proxy snippets

The runnable, maintained snippets (which headers to set/strip, how to register the forward-auth
middleware) live with the code so they don't drift:

- `services/mini-gateway/README.md` — Traefik ForwardAuth, Caddy `forward_auth`, nginx `auth_request`.
- `services/mini-gateway/examples/docker-compose.traefik.yml` and `Caddyfile` — working end-to-end
  examples gating `whoami`.

## What you end up with

One passkey login, a session shared across your apps, and per-route policy in front of upstreams that
never had auth — with the family binding loopback and your proxy terminating TLS. For the security
boundaries you're relying on, read
[`security/threat-model-overview.md`](../security/threat-model-overview.md).
