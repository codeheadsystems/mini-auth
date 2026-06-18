# Security review notes — mini-gateway

These notes accompany a security review of mini-gateway, in the teaching format of
`services/mini-kms/docs/security/`: a real weakness, the threat, a concrete fix,
and *why it works*.

> mini-gateway is a forward-auth endpoint — it decides about requests it never
> receives directly, so its security rests on what it trusts from the proxy and
> how it matches routes. It reuses the family's vetted pieces (mini-token session
> + JWS verification, mini-policy decisions), denies by default, and logs no
> secrets. The findings below are about the trust boundary and route matching.

## Findings

| # | Severity | Issue | Status | Doc |
|---|----------|-------|--------|-----|
| 1 | High if mis-deployed | Forward-auth header trust (`X-Forwarded-*` / `X-Auth-*`) | ✅ Hardened + documented contract | [01](01-forward-auth-header-trust.md) |
| 2 | High | Route bypass via path confusion | ✅ Fixed | [02](02-path-confusion.md) |

## Deployment contract (irreducible)

Forward-auth inherently trusts the proxy. The proxy MUST set `X-Forwarded-*`
itself and strip the client's copies, MUST copy the gateway's `X-Auth-*` response
headers onto the upstream and strip client-supplied `X-Auth-*`, and MUST keep
`/verify` reachable only from the proxy network. The `examples/` directory wires
this for Traefik and Caddy.
