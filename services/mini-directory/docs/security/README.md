# Security review notes — mini-directory

These notes accompany a security review of mini-directory, in the teaching format
of `services/mini-kms/docs/security/`.

> mini-directory is the family's identity source of truth. Service-account secrets
> are Argon2id-hashed at rest, returned exactly once at creation, never logged;
> the admin API is bearer-gated; it binds to loopback by default; and
> authentication is designed to give no oracle. The finding below is the timing
> side of that no-oracle promise — present in shape but defeated by its
> parameters, and now fixed.

## Findings

| # | Severity | Issue | Status | Doc |
|---|----------|-------|--------|-----|
| 1 | Medium | Account enumeration via Argon2 timing oracle (dummy hash too weak) | ✅ Fixed | [01](01-no-oracle-authentication.md) |
