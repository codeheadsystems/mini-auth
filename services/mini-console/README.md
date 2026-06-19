# mini-console

**mini-console** is the optional unified **admin console** over the whole `mini-` family — one
loopback place to browse mini-directory identities, rotate signing keys, manage mini-kms key groups,
read audit/issuance logs, register OIDC clients, and **smoke-test the family end to end** — instead
of curling six admin APIs by hand. It has **two faces in one process**:

1. **Operator console** — server-rendered HTML pages that browse and mutate the surfaces the family
   services already expose (each backed by a per-service client library).
2. **Exercise harness** — scripted end-to-end flows that drive the family the way a real client
   would (issue an m2m token, run OIDC code+PKCE, mint/renew/revoke a cert, rotate a signing key, hit
   the gateway's forward-auth) and **verify the result offline** — a signature against the JWKS, a
   cert chain to the CA root, the gateway's allow/deny decision — reporting pass/fail/skip without
   ever logging a secret.

It adds **no new authority.** Every mutation it performs is one the operator could perform by curling
an admin API with the same downstream token; the console invents no new trust boundary and stores no
identity, grants, or keys of its own — only its login-session/CSRF state. The full design (and the
slice-by-slice history) lives in [`docs/design/mini-console.md`](../../docs/design/mini-console.md).

## Architecture

mini-console sits *above* every service as a pure client. Each downstream is reached through a thin
client library; the harness reuses `mini-token`'s offline verifiers and `mini-policy`'s decision
types so it re-implements no crypto.

```
   operator (browser, loopback) ──▶ mini-console (HttpServer, loopback, console token + session)
                                       ├─ pages/    operator HTML (CSRF on every POST)
                                       ├─ harness/  end-to-end flows + offline verify
                                       └─ /api      read-only JSON rollups (+ /docs OpenAPI)
        each downstream via one client library (console → *-client → mini-client-common):
          mini-directory-client  mini-idp-client  mini-oidc-client  mini-ca-client  mini-gateway-client
          mini-kms: the existing :services:mini-kms:client (socket-era exception, reused as-is)
```

The five HTTP client libraries share `libs/mini-client-common` (env/file token resolver, a loopback
`HttpClient`, JSON, and the **no-oracle error collapse**). mini-kms keeps its existing socket client.
Each client copies only the small wire records it needs — no client lib depends on a service module,
so the dependency graph is one-way and acyclic.

## Screens & routes (operator console)

Every page but `/login`, `/health`, and the public docs requires a valid console session; every
state-changing POST carries a double-submit **CSRF** token, verified before any downstream call.
Destructive actions (delete a principal, destroy a KMS version, revoke a cert) have a confirm step. A
service the operator did not wire reads "not configured" — never a fabricated row.

| Screen | Route(s) | Backed by |
| --- | --- | --- |
| Dashboard | `GET /` | `health()` across all six services |
| Identities | `GET /identities`, `GET /identities/{id}` | mini-directory: accounts/groups/roles + resolution |
| Identities — mutate | `POST /identities/...` | create/assign/delete (service-account secret shown **once**) |
| Clients (OIDC RPs) | `GET /clients`, `POST /clients` | mini-oidc: list + register (client secret shown **once**) |
| Keys | `GET /keys`, `POST /keys/...` | mini-kms key groups + mini-idp/mini-oidc signing-key rotation |
| Certificates | `GET /certificates`, `POST /certificates/...` | mini-ca: issuance log, revocations, issue/renew/revoke |
| Audit | `GET /audit` | mini-idp audit log |
| Harness | `GET /harness`, `POST /harness/...` | the exercises below |

## Exercise harness (what "pass" means)

Each flow returns a result whose **steps are secret-free by contract** (tokens/secrets become
`«redacted»`; only non-secret facts — a kid, sub, exp, serial, status — are shown). "Pass" is a
cryptographic/state assertion verified **offline**, not just an HTTP 200. A flow honestly reports
**SKIP** for a step it cannot drive (e.g. a headless passkey login), never a misleading PASS.

| Flow | Drives | Pass = (verified offline) | Needs |
| --- | --- | --- | --- |
| **Machine-to-machine token** | `idp.token` → `idp.jwks` | JWS verifies against the JWKS (`iss`/`exp`/`grants`) | `--idp-url` + client id/secret |
| **Signing-key rotation** | rotate → re-fetch JWKS | new kid present, retired kid retained, pre-rotation token still verifies | `--idp-url` + client id/secret |
| **Certificate lifecycle** | local CSR → `issue` → `renew` → `revoke` | leaf chains to the CA root; revoked serial appears in the list | `--ca-url` |
| **OIDC code + PKCE** | build `/authorize` (S256) → `exchangeCode` → `userinfo` → `refresh` | id_token verifies offline; refresh rotates (old refused). *Passkey login → SKIP unless a code is supplied.* | `--oidc-url` |
| **Gateway forward-auth** | `gateway.verify` with (a) no creds, (b) a bearer, (c) insufficient scope | (a) → 302/401, (b) → 200, (c) → 403 | `--gateway-url` (the bearer branches need an access token) |

The Harness page can **run all** the no-credential flows at once and show a `X passed, Y skipped, Z
failed` tally; the credential-needing token flows are reported SKIP (run those individually).

## The `/api` surface

A small **read-only JSON** surface, the programmatic twin of the Dashboard, guarded by the console
bootstrap token as `Authorization: Bearer <console token>`:

- `GET /api/health` — the per-service wiring/liveness rollup.
- `GET /api/harness` — the exercise catalog and whether each backend is wired.

It honors the family contract-test pattern: the spec is served at `/openapi.yaml` and `/openapi.json`,
browsable at `/docs` (vendored Swagger UI — fully offline), and `OpenApiContractTest` fails if a
documented path stops resolving.

## Run it locally

The bootstrap console token comes from an env var or a file, **never a CLI arg, never logged**.
Loopback by default. Wire only the services you have; each downstream URL takes a console-scoped admin
token (env `MINICONSOLE_<SVC>_TOKEN` or `--<svc>-token-file`) — except mini-gateway, which needs no
token (its `/verify` carries the caller's own credentials, and `/health` is public).

```bash
export MINICONSOLE_ADMIN_TOKEN="$(openssl rand -hex 32)"      # the console login token
export MINICONSOLE_DIRECTORY_TOKEN="$MINIDIR_ADMIN_TOKEN"     # held copies of each downstream admin token
export MINICONSOLE_IDP_TOKEN="$MINIIDP_ADMIN_TOKEN"
export MINICONSOLE_OIDC_TOKEN="$MINIOIDC_ADMIN_TOKEN"
export MINICONSOLE_CA_TOKEN="$MINICA_ADMIN_TOKEN"
export MINICONSOLE_KMS_API_TOKEN="$MINIKMS_API_TOKEN"
export MINICONSOLE_KMS_ADMIN_TOKEN="$MINIKMS_ADMIN_TOKEN"
./gradlew :services:mini-console:installDist
services/mini-console/build/install/mini-console/bin/mini-console \
  --port 8500 --data-dir ~/.mini-console \
  --directory-url http://127.0.0.1:8466 \
  --idp-url       http://127.0.0.1:8455 \
  --oidc-url      http://127.0.0.1:8477 \
  --ca-url        http://127.0.0.1:8499 \
  --kms-tcp       127.0.0.1:9123 \
  --gateway-url   http://127.0.0.1:8488
# Sign in at http://127.0.0.1:8500/login  (health: /health, API docs: /docs)
```

## Building & testing

```bash
./gradlew build                          # compiles mini-console + the client libs, runs all tests (the CI gate)
./gradlew :services:mini-console:test    # just this module's tests
```

## Security model

- **No new authority.** The console stores no identity, no grants, no keys — only its own
  login-session/CSRF state, in an atomic-`0600` `console-sessions.json`. Every action equals an
  operator curling a downstream admin API with the same token.
- **Console login.** The operator pastes the bootstrap token into the login form; it is compared in
  constant time (never logged), and on success the console mints a **mini-token `SessionService`**
  session with a console-specific cookie name (deliberately **not** the family SSO cookie, so the two
  never collide on a shared host).
- **The one new secret concentration.** To call six admin APIs the console holds up to six downstream
  admin/API tokens (plus its own). All are resolved from env/file (never argv), held in memory, and
  never logged. Running mini-console means concentrating these tokens in one loopback process — a
  deliberate operator trade-off, mitigated by the loopback-default bind. Any LAN exposure is an
  explicit decision, behind a TLS reverse proxy with `--secure-cookies`.
- **No oracles, no secrets in logs.** Client libraries collapse every failure to one
  `ClientException`; pages render a single generic error; the harness reports FAIL without leaking
  why. The once-only service-account / client secrets are shown exactly once at creation and never
  re-fetchable. Access logs record method/path/status only. **CSRF** guards every browser POST; the
  OIDC harness flow mandates **PKCE S256**. (The gateway client is the deliberate exception to the
  status-collapse: distinguishing `/verify`'s 200/302/401/403 is the proxy's whole job — but it reads
  no response body, so there is still no body oracle.)
