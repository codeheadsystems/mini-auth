# Security review notes — mini-oidc

These notes accompany a security review of mini-oidc. They exist to **teach**:
each documents a real weakness, the threat it poses, a concrete fix, and *why the
fix works* — mirroring the format of `services/mini-kms/docs/security/`.

> mini-oidc is an educational OpenID Provider. The browser flow is built on the
> right primitives — authorization-code + mandatory PKCE, a server-side CSRF token
> on every state-changing POST, exact-match `redirect_uri`, rotating refresh
> tokens with family-revoke-on-replay, single-use codes, constant-time secret
> compares, and no secrets in logs. The findings below are the sharp edges a
> review surfaces; both were fixed.

## Findings

| # | Severity | Issue | Status | Doc |
|---|----------|-------|--------|-----|
| 1 | Medium | PKCE downgrade to `plain` | ✅ Fixed | [01](01-pkce-downgrade.md) |
| 2 | Medium | Open redirect on logout (`post_logout_redirect_uri`) | ✅ Fixed | [02](02-logout-open-redirect.md) |

## Known seams (documented, by design)

- **Session cookie `Secure` is off by default** — a loopback-dev convenience; any
  LAN exposure must be behind TLS with `--secure-cookies`.
- **Passkey enrolment (`/register/passkey/**`) is unauthenticated self-enrolment**
  — a real deployment gates it.
- **`auth_time` on refreshed ID tokens** now carries the original login time (the
  refresh family preserves it), so client max-age / re-auth checks stay honest.
