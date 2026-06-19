# Sequence — forward-auth subrequest (gating a no-auth app)

> How a reverse proxy asks **mini-gateway** "should I forward this?" before handing a request to an
> upstream that has no auth of its own. Concept:
> [`authn-vs-authz.md`](../concepts/authn-vs-authz.md) (authZ at the edge). Lab:
> [`05`](../tutorials/05-gate-a-no-auth-app.md).

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (browser or API)
    participant PX as Reverse proxy<br/>(Traefik/Caddy/nginx)
    participant GW as mini-gateway /verify
    participant TOK as mini-token (session + JWS verify)
    participant UP as Upstream (no-auth app)

    C->>PX: request /something  (Cookie or Authorization)
    PX->>GW: GET /verify<br/>X-Forwarded-Method/Uri/Proto/Host,<br/>Cookie, Authorization
    Note right of GW: normalize path FIRST (decode once, collapse<br/>//, ., ..) — reject traversal → 403

    alt Authorization: Bearer present
        GW->>TOK: BearerAuthenticator → JwsClaimsVerifier (offline)
        TOK-->>GW: subject + scopes (source=token)
    else session cookie present
        GW->>TOK: SessionAuthenticator → SessionService.lookup (same sessions.json)
        TOK-->>GW: subject (source=session, no scopes)
    end

    Note right of GW: RoutePolicy.evaluate(method, path, user)<br/>— first matching rule wins; no match → deny
    alt PUBLIC route
        GW-->>PX: 200 allow  (X-Auth-* emitted empty)
    else AUTHENTICATED route + user present
        GW-->>PX: 200 allow  (X-Auth-Subject/Scope/Source set)
    else SCOPE route + scope satisfied (via mini-policy)
        GW-->>PX: 200 allow  (X-Auth-* set)
    else unauthenticated + browser
        GW-->>PX: 302 → loginUrl?return=<original>
    else unauthenticated + API
        GW-->>PX: 401 + WWW-Authenticate: Bearer
    else forbidden (no rule / scope denied)
        GW-->>PX: 403
    end

    Note over PX,UP: only on 200 does the proxy forward — copying X-Auth-* onto the upstream
    PX->>UP: forward request + X-Auth-Subject/Scope/Source
    UP-->>C: response
```

**Key points**

- **mini-gateway invents nothing.** It *reuses* the same `sessions.json` mini-oidc writes (a reader,
  not a second session) and the same JWS verification — so a logged-in human or a bearer-token client
  both work.
- **Two authenticators, one decision.** Bearer is tried, then the session cookie; the
  [`RoutePolicy`](../concepts/authorization-model.md) decides per route. **Deny by default** for any
  unmatched path.
- **SCOPE routes need a token, not just a session.** A session carries *no* scopes, so a `SCOPE` rule
  rejects a session-only caller — a trust-boundary detail covered in
  [`security/threat-model-overview.md`](../security/threat-model-overview.md).
- **`X-Auth-*` are always emitted** (empty when anonymous) so the proxy *overwrites* any
  client-supplied spoof — see the [forward-auth header-trust finding](../security/README.md).

> **Deployment contract:** `/verify` must be reachable **only** by the trusted proxy, and the proxy
> must set `X-Forwarded-*` and strip client copies. mini-gateway binds loopback by default.
