# How-to: run the whole family

> **How-to (task-oriented).** For someone who already understands the pieces and wants them all
> running, in dependency order, with the env-var plumbing correct. If you're *learning* the concepts,
> start at [`TEACHING.md`](../TEACHING.md) instead. Closes the "no single chained walkthrough" gap.

## TL;DR — one script

The repo ships a runnable launcher that brings the family up in order and tears it down on Ctrl-C:

```bash
docs/examples/run-family.sh            # directory + idp + oidc + gateway
docs/examples/run-family.sh --with-kms # also mini-kms, with idp's signing keys wrapped
```

It builds the launchers, generates demo secrets, binds everything to loopback, and prints the URLs
(each service's `/docs`). Logs and data live under a printed temp dir. The rest of this page explains
what it does so you can adapt it.

## Dependency order (who must start before whom)

```
mini-kms (optional)            mini-directory  ── identity source of truth
   │ wraps signing keys             │
   ▼                                ▼
   └────────────▶ mini-idp   /   mini-oidc      ── issuers (read the directory)
                       │            │
                       └──── mini-gateway        ── reads mini-oidc's sessions + JWKS
```

- **mini-directory first** — both issuers resolve accounts from it; nothing works without it.
- **mini-kms before the issuers** *if* you want wrapped signing keys (the issuer connects at startup
  to unwrap).
- **mini-oidc before mini-gateway** — the gateway reads mini-oidc's `sessions.json` and `/jwks.json`.

## The env-var plumbing (the part that bites)

Secrets come from **env or file, never argv**. The cross-service calls each need a token:

| Variable | Used by | Must equal |
| --- | --- | --- |
| `MINIDIR_ADMIN_TOKEN` | mini-directory | (its own admin token) |
| `MINIIDP_ADMIN_TOKEN` | mini-idp | (its own admin token) |
| `MINIIDP_DIRECTORY_TOKEN` | mini-idp → directory | **`MINIDIR_ADMIN_TOKEN`** |
| `MINIOIDC_ADMIN_TOKEN` | mini-oidc | (its own admin token) |
| `MINIOIDC_DIRECTORY_TOKEN` | mini-oidc → directory | **`MINIDIR_ADMIN_TOKEN`** |
| `MINIKMS_API_TOKEN` | mini-kms data plane | (shared with issuers as `MINIIDP_KMS_API_TOKEN`) |
| `MINIKMS_ADMIN_TOKEN` | mini-kms control plane | (its own; for `kms-admin`) |
| `MINIKMS_PASSPHRASE` | mini-kms | (the keystore passphrase; no-TTY fallback) |

> **The two most common mistakes**, both of which fail fast at startup with a clear message:
> - Setting `--directory-url` on an issuer **without** its `*_DIRECTORY_TOKEN` →
>   *"a directory URL was set but no admin token."* Each issuer authenticates to the directory's admin
>   API, so it needs the directory's admin token.
> - Forgetting that `MINIIDP_DIRECTORY_TOKEN` / `MINIOIDC_DIRECTORY_TOKEN` must be the **directory's**
>   token, not the issuer's own.

## Manual bring-up (what the script runs)

```bash
./gradlew :services:mini-directory:installDist :services:mini-idp:server:installDist \
          :services:mini-oidc:installDist :services:mini-gateway:installDist

export MINIDIR_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MINIIDP_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MINIIDP_DIRECTORY_TOKEN="$MINIDIR_ADMIN_TOKEN"
export MINIOIDC_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MINIOIDC_DIRECTORY_TOKEN="$MINIDIR_ADMIN_TOKEN"

D=$(mktemp -d)
services/mini-directory/build/install/mini-directory/bin/mini-directory --port 8466 --data-dir "$D/dir" &
services/mini-idp/server/build/install/server/bin/server --port 8455 --data-dir "$D/idp" \
  --directory-url http://127.0.0.1:8466 &
services/mini-oidc/build/install/mini-oidc/bin/mini-oidc --port 8477 \
  --issuer http://127.0.0.1:8477 --rp-id 127.0.0.1 --rp-origin http://127.0.0.1:8477 \
  --directory-url http://127.0.0.1:8466 &
echo '{}' > "$D/sessions.json"
services/mini-gateway/build/install/mini-gateway/bin/mini-gateway --port 8488 \
  --sessions-file "$D/sessions.json" --routes-file services/mini-gateway/examples/routes.json \
  --login-url http://127.0.0.1:8477/authorize \
  --jwks-url http://127.0.0.1:8477/jwks.json --issuer http://127.0.0.1:8477 \
  --audience http://127.0.0.1:8477/userinfo &
```

Health-check each before using it: `curl -fsS http://127.0.0.1:<port>/health`.

### Adding mini-kms (wrapped signing keys)

```bash
export MINIKMS_PASSPHRASE="$(openssl rand -hex 24)"
export MINIKMS_API_TOKEN="$(openssl rand -hex 32)"
export MINIKMS_ADMIN_TOKEN="$(openssl rand -hex 32)"
services/mini-kms/server/build/install/server/bin/server --tcp-port 9123 --keystore "$D/keystore.json" &
services/mini-kms/client/build/install/client/bin/kms-admin --tcp 127.0.0.1:9123 create-key --key signing-keys

# then start mini-idp (and/or mini-oidc, mini-ca) with:
export MINIIDP_KMS_API_TOKEN="$MINIKMS_API_TOKEN"
#   …  --kms-tcp 127.0.0.1:9123 --kms-key-group signing-keys
```

See [lab 06](../tutorials/06-protect-the-signing-keys.md) for the wrap-on-save walkthrough.

## Ports (defaults)

| Service | Port | Docs |
| --- | --- | --- |
| mini-directory | 8466 | `/docs` |
| mini-idp | 8455 | `/docs` |
| mini-oidc | 8477 | `/docs` |
| mini-gateway | 8488 | `/verify` (no UI) |
| mini-kms | 9123 (TCP) | — (CLI client) |

## Notes

- **Loopback only.** Everything binds `127.0.0.1` by default. Exposing beyond loopback is an explicit
  decision — and mini-oidc/mini-gateway must then sit behind a TLS proxy with `--secure-cookies`. See
  [`configuration-and-secrets.md`](configuration-and-secrets.md).
- **Who calls whom / failure modes** are catalogued in
  [`wire-the-services-together.md`](wire-the-services-together.md) (e.g. directory unreachable → every
  token request fails with a generic `invalid_client`, [as lab 03 shows](../tutorials/03-machine-identity-end-to-end.md)).
- For an SSO-in-front-of-an-app recipe specifically, see
  [`sso-for-your-homelab.md`](sso-for-your-homelab.md).
