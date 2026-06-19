# How-to: configuration & secrets

> **How-to (task-oriented).** Where secrets come from, how to generate them, when to expose a service
> beyond loopback, and env-vs-file. The reflexes behind this are in
> [`concepts/secure-design-invariants.md`](../concepts/secure-design-invariants.md).

## Generate a token

Every admin/API token is opaque high-entropy bytes. The family's convention:

```bash
openssl rand -hex 32      # 256 bits, hex — the standard token
openssl rand -hex 24      # a demo passphrase (real use: a long, memorable, high-entropy one)
```

## Secrets come from env or file — never argv

Command-line args are world-visible (`ps`, `/proc/<pid>/cmdline`). The family **never** takes a secret
as a flag. Each service reads it from an environment variable, or — preferred — a file:

| Service | Env var | File flag |
| --- | --- | --- |
| mini-directory | `MINIDIR_ADMIN_TOKEN` | `--admin-token-file` |
| mini-idp | `MINIIDP_ADMIN_TOKEN` | `--admin-token-file` |
| mini-idp → directory | `MINIIDP_DIRECTORY_TOKEN` | `--directory-token-file` |
| mini-idp → kms | `MINIIDP_KMS_API_TOKEN` | `--kms-api-token-file` |
| mini-oidc | `MINIOIDC_ADMIN_TOKEN` | `--admin-token-file` |
| mini-oidc → directory | `MINIOIDC_DIRECTORY_TOKEN` | `--directory-token-file` |
| mini-kms | `MINIKMS_API_TOKEN`, `MINIKMS_ADMIN_TOKEN`, `MINIKMS_PASSPHRASE` | `--admin-token-file`, … |
| mini-gateway | *(none of its own — it validates the family's tokens/sessions)* | — |

**Files beat env vars** for long-lived deployments: env is inherited by child processes and can show
in a heap/process dump; a file with tight permissions (`0600`) is tighter. mini-kms reads its
passphrase with no echo from the TTY (`Console.readPassword`), falling back to `MINIKMS_PASSPHRASE`
only when there's no terminal.

```bash
# file pattern
install -m600 /dev/null /etc/mini-idp/admin-token
openssl rand -hex 32 > /etc/mini-idp/admin-token
mini-idp ... --admin-token-file /etc/mini-idp/admin-token
```

## Nothing secret is logged

Access logs are method/path/status only (`GET /health -> 200`). Tokens, secrets, keys, and bodies are
never logged. If you're adding logging, keep it that way.

## Ports & binding (loopback by default)

Everything binds `127.0.0.1` unless you set `--host`. Defaults:

| Service | Flag | Default port |
| --- | --- | --- |
| mini-directory | `--port` | 8466 |
| mini-idp | `--port` | 8455 |
| mini-oidc | `--port` | 8477 |
| mini-gateway | `--port` | 8488 |
| mini-kms | `--tcp-port` (+ a Unix socket) | 9123 |

## When (and how) to expose beyond loopback

Exposing past loopback is an **explicit decision** with a checklist:

- **Put it behind a TLS reverse proxy.** Don't expose the HTTP listeners directly.
- **mini-oidc / mini-gateway:** add `--secure-cookies` so the session cookie carries `Secure`. The
  cookie is already `HttpOnly` + `SameSite=Lax`.
- **mini-gateway** is reached by its proxy over the loopback/Docker network and is **never** exposed
  to clients directly; `/verify` must be reachable only by the trusted proxy.
- **mini-kms** loopback TCP is reachable by every local user (a known, documented open item) — keep it
  on a trusted host; prefer the Unix socket (`0600` in a `0700` dir) where you can.

## Persistence locations

State is JSON, written atomically at `0600`, under each service's `--data-dir` (or the specific
`--keystore` / `--sessions-file` / `--routes-file`). Back these up like the secrets they protect — a
stolen `keystore.json` is brute-forceable offline, so its entropy is your passphrase's entropy.
