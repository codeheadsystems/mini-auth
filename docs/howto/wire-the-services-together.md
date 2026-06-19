# How-to: wire the services together

> **How-to (task-oriented).** Who calls whom, what each call expects, and — the part you actually need
> when something's broken — the **failure modes**. For bringing everything up, see
> [`run-the-whole-family.md`](run-the-whole-family.md); for the security view,
> [`security/threat-model-overview.md`](../security/threat-model-overview.md).

## Who calls whom

| Caller | Callee | When | Needs |
| --- | --- | --- | --- |
| mini-idp | mini-directory `/admin/service-accounts/authenticate` | every `/oauth/token` | `--directory-url` + `MINIIDP_DIRECTORY_TOKEN` (= directory admin token) |
| mini-oidc | mini-directory `/admin/principals/{id}/resolution` | on login (resolve human) | `--directory-url` + `MINIOIDC_DIRECTORY_TOKEN` (= directory admin token) |
| mini-idp / mini-oidc / mini-ca | mini-kms (data plane) | startup + key save | `--kms-tcp` + `--kms-key-group` + `MINI*_KMS_API_TOKEN` |
| mini-gateway | mini-oidc `sessions.json` (file) | every session-auth `/verify` | `--sessions-file` pointed at the file mini-oidc writes |
| mini-gateway | mini-oidc `/jwks.json` | every bearer-auth `/verify` | `--jwks-url` + `--issuer` + `--audience` |
| any verifier | issuer `/jwks.json` | first verify (cacheable) | network reachability to the issuer (once) |

## What each callee trusts

- **mini-directory** trusts the caller's **admin token** to use its admin API. It verifies secrets
  *itself* — the hash never leaves it.
- **mini-kms (data plane)** trusts the **API token**; rotating/destroying keys needs the separate
  **admin token**.
- **mini-gateway** trusts the **reverse proxy** to set `X-Forwarded-*` and strip client `X-Auth-*`. It
  must be reachable *only* by that proxy.

## Failure modes (and what the symptom looks like)

| Break | Symptom | Why |
| --- | --- | --- |
| mini-directory **down/unreachable** | every `/oauth/token` → `401 invalid_client` (generic); JWKS still 200 | no-oracle: the issuer won't say "directory down." Verified in [lab 03](../tutorials/03-machine-identity-end-to-end.md). |
| `--directory-url` set, **token missing** | issuer **refuses to start** — mini-oidc: *"a directory URL was set but no admin token"*; mini-idp: *"no mini-directory token: set MINIIDP_DIRECTORY_TOKEN or provide --directory-token-file"* (mini-idp also *requires* `--directory-url`; mini-oidc treats it as optional) | each issuer authenticates to the directory's admin API. |
| Wrong `*_DIRECTORY_TOKEN` (not the directory's) | `/admin/...` calls rejected → token requests fail generic | the token must be **mini-directory's** admin token. |
| mini-kms **down** at issuer startup (`--kms-*` set) | issuer fails to start / can't unwrap signing keys | the wrapped key is unwrapped at boot; no KMS, no key. |
| `--kms-key-group` **doesn't exist** | unwrap/encrypt fails | create it first: `kms-admin create-key --key <group>`. |
| mini-gateway `--sessions-file` ≠ mini-oidc's | logged-in humans not recognized at the gateway | the session store is shared by *file*; both must point at the same path. |
| Cookie host mismatch (oidc vs. app) | session cookie never reaches the gated app | host-only cookie, `Path=/` — mini-oidc and the app must share a hostname. |
| `SCOPE` route, session-only caller | `403` even though "logged in" | a session carries **no scopes**; that route needs an access token. |
| mini-gateway `--jwks-url` unset | bearer auth disabled (`bearer: disabled` in banner) | only session auth works; `SCOPE` routes can't be satisfied. |

## The runtime DAG (one glance)

```
mini-policy ─┐ (library)
mini-token  ─┤ (library: JWS, JWKS, sessions)
             ▼
mini-directory ◀── mini-idp, mini-oidc   (issuers resolve here)
                       │  │
                       │  └── writes sessions.json ◀── mini-gateway reads it
                       ▼
                   mini-kms  ◀── wraps the issuers' (and mini-ca's) signing keys
```

For the "what must start before what" ordering, see
[`run-the-whole-family.md`](run-the-whole-family.md).
