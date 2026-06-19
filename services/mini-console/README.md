# Mini Console

**mini-console** is the optional unified **admin console** over the whole `mini-` family — one place
to inspect mini-directory identities, rotate mini-token signing keys, review audit logs, and manage
mini-kms key groups, instead of curling each service's admin API by hand. It is also an **exercise
harness** for smoke-testing a deployment end to end. It adds **no new authority** — it is a client of
admin surfaces that already exist.

> **Status: Slice 1 — first live service (mini-directory).** A real, runnable server (loopback HTTP,
> a paste-the-token login that mints a session, a Dashboard) with the **first downstream client
> wired**: read-only **Identities** pages backed by `mini-directory-client`. The remaining five
> services are still honest placeholders — the Dashboard reports `n/a — client not wired yet` for
> each, calling nothing downstream. Later slices add their client libs + pages (keys, audit,
> certificates) and the exercise harness. The full design is in
> [`docs/design/mini-console.md`](../../docs/design/mini-console.md); the Slice 0 plan is in
> [`docs/design/mini-console-slice0.md`](../../docs/design/mini-console-slice0.md). A proper teaching
> README replaces this one once the screens exist.

## What's here

- A loopback `HttpServer` (one virtual thread per request), bound `127.0.0.1` by default.
- **Console login:** the operator pastes the bootstrap console token into a form; it is compared in
  constant time (never logged), and on success the console mints a **mini-token `SessionService`**
  session stored in an atomic-`0600` `console-sessions.json`. The session cookie is the
  console-specific `mini-console-session` (deliberately **not** the family SSO cookie, so the two
  never collide on a shared host). Every page but `/login` and `/health` requires a valid session.
- **CSRF** (double-submit cookie) on the login and logout POSTs.
- **Identities (read-only)** — when `--directory-url` is set, `/identities` lists principals, groups,
  and roles from mini-directory, and `/identities/{id}` shows one principal plus its **resolved**
  (fully-expanded) grants. Backed by `libs/mini-directory-client` over `libs/mini-client-common`'s
  no-oracle `HttpTransport`. Without a directory configured the page says so (an honest seam, not an
  error). No secret is ever rendered.
- A **Dashboard** with mini-directory's row **live** (real `health()`), the other five services
  still marked "client not wired yet" — it fabricates no data.

## Run it locally

The bootstrap console token comes from an env var or a file, **never a CLI arg, and is never
logged**. Loopback by default. To wire mini-directory, set `--directory-url` and a console-scoped
directory token (`MINICONSOLE_DIRECTORY_TOKEN` or `--directory-token-file`).

```bash
export MINICONSOLE_ADMIN_TOKEN="$(openssl rand -hex 32)"
export MINICONSOLE_DIRECTORY_TOKEN="$MINIDIR_ADMIN_TOKEN"   # the directory's admin token, held by the console
./gradlew :services:mini-console:installDist
services/mini-console/build/install/mini-console/bin/mini-console --port 8500 --data-dir ~/.mini-console \
  --directory-url http://127.0.0.1:8466
# Sign in at http://127.0.0.1:8500/login  (health: /health, identities: /identities)
```

## Building & testing

It participates in the one aggregator build like every other module:

```bash
./gradlew build                          # compiles mini-console + runs its tests (the CI gate)
./gradlew :services:mini-console:test    # just this module's tests
```

## Security model (Slice 0)

- **No new authority.** The console stores no identity, no grants, no keys — only its own
  login-session state. Every later action will equal an operator curling a downstream admin API.
- **Loopback bind by default;** any LAN exposure is an explicit operator decision behind a TLS
  reverse proxy with `--secure-cookies`.
- **No secrets in logs.** The console token travels only in the login POST body; the access log
  records method/path/status only. **No oracle:** a wrong token and a missing token are
  indistinguishable, and a CSRF failure collapses to one generic error.
