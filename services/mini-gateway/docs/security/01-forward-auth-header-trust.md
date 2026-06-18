# 01 — Forward-auth header trust (`X-Forwarded-*` / `X-Auth-*`)

**Severity:** High if mis-deployed (identity spoofing); inherent to forward-auth
**Status:** ✅ Hardened (identity headers always emitted) + ⚠️ deployment contract (documented)

**Affected code:**
- `server/GatewayHandlers.java` — `verify`, `allow`, `forwarded`, `originalUrl`

## What the issue is

A forward-auth endpoint decides *about a request it never received directly*. The
reverse proxy (Traefik ForwardAuth, Caddy `forward_auth`, nginx `auth_request`)
calls `GET /verify` and passes the original request's method/URI in
`X-Forwarded-*` / `X-Original-*` headers; the gateway answers 200/302/401/403, and
on **200** returns `X-Auth-Subject` / `X-Auth-Scope` / `X-Auth-Source` for the
proxy to copy onto the upstream so a no-auth app learns who the caller is.

Two trust facts fall out of that shape:

1. The gateway reads the request method/path from headers
   (`GatewayHandlers.verify:72-74`). Those are only trustworthy if the proxy sets
   them and **strips any client-supplied copies**.
2. The `X-Auth-*` identity headers travel to the upstream. The gateway originally
   set them **only when a caller was authenticated**:

```java
// allow (before) — headers set only when a user is present
HttpResponse response = HttpResponse.json(200, Map.of("allow", true));
if (user.isPresent()) {
  response = response.header(HEADER_SUBJECT, caller.subject()) ... ;
}
return response;
```

On a `PUBLIC` route the caller is empty, so **no** `X-Auth-*` headers were
emitted — and a client-supplied `X-Auth-Subject: admin` on the original request
would pass through untouched unless the proxy happened to strip it.

## The threat it poses

If the upstream trusts `X-Auth-Subject` as identity (the whole point of these
headers), a client that can reach a `PUBLIC` route and set `X-Auth-Subject`
spoofs any identity downstream — **privilege escalation by header injection**. And
if `/verify` is reachable by anything other than the trusted proxy, a client can
forge `X-Forwarded-Uri: /public` while the proxy forwards `/admin`, getting an
ALLOW for a path it is not actually requesting.

## The fix

The gateway now **always** emits all three identity headers — empty when there is
no authenticated caller — so a proxy configured to copy them *overwrites* rather
than passes through any client-supplied value:

```java
// allow (after)
final AuthenticatedUser caller = user.orElse(null);
return HttpResponse.json(200, Map.of("allow", true))
    .header(HEADER_SUBJECT, caller == null ? "" : caller.subject())
    .header(HEADER_SCOPE,   caller == null ? "" : String.join(" ", caller.scopes()))
    .header(HEADER_SOURCE,  caller == null ? "" : caller.source());
```

The `X-Forwarded-*` trust is **inherent to the forward-auth pattern** and cannot
be fixed in the gateway alone — it is a deployment contract:

- The proxy MUST set `X-Forwarded-*` itself and strip the client's copies.
- The proxy MUST copy the gateway's `X-Auth-*` response headers onto the upstream
  and strip any client-supplied `X-Auth-*` from the inbound request.
- `/verify` MUST be reachable only from the proxy (loopback / the proxy network),
  never exposed to clients directly.

The runnable examples in `services/mini-gateway/examples/` (Traefik, Caddy) wire
exactly this.

## Why the fix works

Always emitting the identity headers means the proxy's "copy these onto upstream"
step is deterministic: the gateway's value (possibly empty) replaces whatever the
client sent, closing the pass-through gap on PUBLIC routes. The header-trust
contract is then the only remaining assumption, and it is the irreducible one
every forward-auth deployment makes — stated loudly here rather than left
implicit. See also [02 — path confusion](02-path-confusion.md), which hardens the
*path* the gateway derives from those same headers.

## Tests

`server/ForwardAuthTest.java` boots the gateway and asserts the decision outcomes
(200 with identity headers, 302-to-login, 401, 403) for session and bearer
callers; `RoutePolicyTest` covers the per-route decisions the identity feeds.
