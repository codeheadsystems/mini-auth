# mini-console — Design Document

A design and module/API sketch for graduating `services/mini-console` from roadmap placeholder to a shipping, admin-only, optional **operator console + end-to-end exercise harness** over the mini- family. No working code here — interface sketches, layout, routes, and a slice-by-slice roadmap. Honest seams preserved throughout.

*Revised 2026-06-19 to fold in maintainer decisions — see [Resolved decisions](#resolved-decisions-confirmed-with-maintainer) at the end.*

## Decisions & assumptions

1. **Five new HTTP client libs under `libs/`; mini-kms reuses its existing `:services:mini-kms:client`.** The five new clients are HTTP/JSON (directory, idp, oidc, ca, gateway). mini-kms is the family's deliberate **socket-era exception**: its `KmsClient` + `KmsSigningKeyStore` already live in `:services:mini-kms:client` and are consumed by mini-idp/mini-oidc/mini-ca today. Relocating it into a `libs/mini-kms-client` was designed and independently reviewed — mechanically clean and behavior-preserving — but **declined** by the maintainer (cosmetic parity for real churn in three shipping services); the exception is now recorded in `docs/DIRECTION.md`. mini-console therefore depends on `:services:mini-kms:client` directly, exactly as the other consumers do. If a `libs/<svc>-client` convention later hardens, mini-kms's client is the first candidate to follow it. See §3.4.
2. **A shared `libs/mini-client-common` IS warranted.** All five HTTP clients need the same: env/file token resolver, a `java.net.http.HttpClient` builder bound to loopback, JSON (de)serialization via a shared `JsonMapper`, bearer-header injection, and the no-oracle error collapse. That is squarely the documented `mini-common` extraction shape. We introduce `libs/mini-client-common` rather than copy the plumbing five times. It depends on nothing in the family except the catalog Jackson.
3. **Client libs share model DTOs by COPYING, not by depending on a service's `server`.** Depending on `:services:mini-directory` (an application module) from a lib would couple a lib to a front door and risk cycles. Each client lib copies the handful of wire records it needs (`Account`, `Group`, `Role`, `GrantSpec`, `ResolvedPrincipal`, token responses, CA records) into its own `com.codeheadsystems.<svc>.client.model` package — the same "deliberate copy until mini-common exists" stance the family already takes for `JsonStore`/`AdminAuthenticator`. The records are small, stable, and Jackson-bound by parameter name. Dependency direction is strictly **console → client-libs → mini-client-common → (catalog)**; no client lib depends on any service module. Acyclic.
4. **mini-console binds loopback and holds downstream admin tokens in memory only.** It is a privileged aggregator: to call six admin APIs it must hold up to six downstream admin tokens (plus its own console token). All are resolved env/file, never argv, never logged, held as `char[]`/`byte[]` where the API allows, zeroed on shutdown. This is the one genuinely new concentration of secrets in the family and it is called out explicitly in §6.
5. **Server-rendered HTML, no JS toolchain; the `/api` OpenAPI surface is KEPT (confirmed).** mini-console's *operator UI* is HTML-only (no openapi.yaml for the HTML pages). A small read-only JSON `/api` surface (health rollups + harness results) **is included**, with an `openapi.yaml` + `OpenApiContractTest`, so the console honors the family contract-test pattern.
6. **mini-idp/mini-oidc/mini-ca currently ship NO client module** (confirmed) — each HTTP client is a fresh extraction. mini-directory and mini-gateway likewise. Only mini-kms has a client today.

---

## 1. Architecture overview

mini-console sits *above* every service as a pure client of surfaces that already exist. It introduces **no new authority** — every mutation it performs is one the operator could perform by curling an admin API with the same downstream admin token. It is a convenience and verification layer, never a source of truth, never a new trust boundary's holder of identity data.

Two faces, one process:

- **Operator console (read/mutate):** server-rendered HTML pages that browse and edit directory identities, trigger key rotations, read audit/issuance logs, and manage KMS key groups — each backed by a client lib call to the owning service's admin API.
- **Exercise harness (verify):** scripted end-to-end flows that drive the family the way a real client would (issue an m2m token, run OIDC code+PKCE, mint/renew/revoke a cert, hit gateway `/verify`, rotate a signing key) and **verify the result offline** (signature against JWKS, claim checks, chain validation), reporting pass/fail without ever logging a secret.

```
                            ┌────────────────────────────────────────────────┐
   operator (browser,       │                  mini-console                  │
   loopback only) ─────────▶│  server/  (HttpServer, loopback, console token)│
                            │  ├─ pages/   operator HTML (CSRF on POST)       │
                            │  ├─ harness/ end-to-end flows + offline verify  │
                            │  └─ config/  ConsoleConfig (env/file tokens)    │
                            └───┬─────┬─────┬─────┬─────┬─────┬───────────────┘
                                │     │     │     │     │     │   (each = one client lib)
                ┌───────────────┘     │     │     │     │     └───────────────┐
                ▼                     ▼     ▼     ▼     ▼                     ▼
        mini-directory-client  idp-client oidc-client  kms client    ca-client gateway-client
                │                     │     │     │   (existing, under │              │
                ▼                     ▼     ▼     ▼    services/)       ▼              ▼
          mini-directory        mini-idp  mini-oidc  mini-kms          mini-ca   mini-gateway
          (admin HTTP)          (HTTP)    (HTTP)     (socket)          (HTTP)    (HTTP /verify)

   five HTTP client libs ──depend on──▶ libs/mini-client-common (token resolver, HttpClient, JSON, no-oracle)
   mini-console reuses the existing :services:mini-kms:client (KmsClient + KmsSigningKeyStore) as-is
   dependency direction is one-way and acyclic:
       mini-console ─▶ {*-client} ─▶ mini-client-common | mini-token ─▶ (catalog)
       the HTTP clients copy their DTOs and depend on NO service module; mini-kms's client stays
       the documented socket-era exception under services/ (see docs/DIRECTION.md)
```

**Data flow (operator mutate example — assign a role to a service account):** browser GET `/identities/{id}` → console renders form with a CSRF token → operator POSTs `/identities/{id}/roles` (CSRF validated) → console calls `MiniDirectoryClient.assignRole(id, roleId)` with the *directory* admin token → directory mutates → console re-renders the resolved-principal preview by calling `resolve(id)`. mini-console persisted nothing.

**Data flow (harness verify example — m2m token):** operator clicks "Run: issue + verify m2m token" → harness calls `MiniIdpClient.token(clientId, secret)` → fetches JWKS via `MiniIdpClient.jwks()` → verifies the JWS signature **offline** with mini-token's `JwsClaimsVerifier`/`TokenVerifier` (reused, not re-implemented) → asserts `iss`/`aud`/`exp`/`grants` → renders a green/red result row. The secret used is never echoed back to the page or the log.

---

## 2. Module layout

### 2.1 The console module (`services/mini-console`, base package `com.codeheadsystems.miniconsole`)

Graduates to `miniauth.application-conventions`. Composition root in `server/`; I/O-free logic (harness verification, route policy) kept transport-free so it is unit-testable without a socket.

```
services/mini-console/
├── build.gradle.kts                 # application-conventions; mainClass = …miniconsole.ServerMain
└── src/main/java/com/codeheadsystems/miniconsole/
    ├── ServerMain.java              # entry point: parse config, build server, start
    ├── server/
    │   ├── ConsoleServer.java       # composition root: HttpServer (loopback), vthread executor, wires handlers + all 6 clients
    │   ├── ConsoleConfig.java       # --port/--data-dir + resolveConsoleToken + per-downstream URL/token resolution (env/file, never argv)
    │   ├── AdminAuthenticator.java  # bearer guard for the console-login token (constant-time, copied family pattern)
    │   ├── ConsoleSession.java      # mini-token SessionService over a JsonStore (own store + own cookie name); see §6
    │   ├── ConsoleHandlers.java     # the route table → page renderers / harness triggers
    │   ├── Cookies.java             # console session cookie helpers (distinct name, NOT the shared SSO cookie)
    │   ├── Csrf.java                # per-page CSRF token mint/verify, bound to the console session (mini-oidc pattern)
    │   ├── store/                   # JsonStore (atomic 0600) backing the console session store
    │   ├── http/                    # the reused Router/Route kit (copied family http/ package)
    │   └── openapi/                 # OpenApiDocument + SwaggerUiPage for the /api JSON surface (KEPT — see §7)
    ├── pages/                       # server-rendered HTML — hand-rolled, mini-oidc LoginPages style
    │   ├── Layout.java              # shared chrome (nav, escaping helpers); NEVER renders a secret
    │   ├── DashboardPage.java
    │   ├── IdentitiesPages.java     # list/detail/edit + resolution preview
    │   ├── KeysPages.java           # signing-key rotation (idp/oidc) + KMS key-group mgmt
    │   ├── AuditPages.java          # issuance/rotation/revocation logs
    │   ├── CertificatesPages.java   # mini-ca issuance log + revocation list + issue/renew/revoke
    │   └── HarnessPages.java        # the exercise harness screen + result rows
    └── harness/                     # I/O-free exercise/verify engine (transport-free core)
        ├── Exercise.java            # one named flow: run(clients) → ExerciseResult
        ├── ExerciseResult.java      # record(name, Status PASS|FAIL|SKIP, List<Step> steps, redactedDetail)
        ├── ExerciseRegistry.java    # the catalog of flows
        └── flows/                   # M2mTokenFlow, OidcCodePkceFlow, CertLifecycleFlow, GatewayVerifyFlow, KeyRotationFlow
```

### 2.2 The client libraries (under `libs/`)

```
libs/
├── mini-client-common/             # NEW — shared HTTP/token/JSON plumbing for all HTTP clients
│   └── …/client/common/            # base package com.codeheadsystems.miniclient.common
│       ├── TokenResolver.java       # env-var | file → char[] (the resolveToken mechanism, parameterized by var name)
│       ├── HttpTransport.java       # java.net.http.HttpClient bound to loopback, bearer injection, JSON in/out
│       ├── Json.java                # shared JsonMapper.builder()…build() (Jackson 3.x)
│       └── ClientException.java     # the single generic client-side error (no-oracle collapse)
├── mini-directory-client/          # NEW — com.codeheadsystems.minidirectory.client
├── mini-idp-client/                # NEW — com.codeheadsystems.miniidp.client
├── mini-oidc-client/               # NEW — com.codeheadsystems.minioidc.client
├── mini-ca-client/                 # NEW — com.codeheadsystems.minica.client
├── mini-gateway-client/            # NEW — com.codeheadsystems.minigateway.client
├── mini-token/                     # (existing — harness reuses its JwsClaimsVerifier/TokenVerifier/JWKS model)
└── mini-policy/                    # (existing)
```
mini-kms is **not** in this list: it keeps its existing `:services:mini-kms:client` (`KmsClient` + `KmsSigningKeyStore`) — the documented socket-era exception, consumed directly. See §3.4 and `docs/DIRECTION.md`.

Each HTTP client lib uses `miniauth.library-conventions`, depends on `:libs:mini-client-common` + `libs.jackson.databind`, and copies only the wire records it needs into its own `…client.model` subpackage.

### 2.3 settings.gradle.kts + catalog wiring

Add to `settings.gradle.kts` (the console line already exists; add the libs):

```kotlin
// --- Libraries (shared, no transport) ---
include("libs:mini-token")
include("libs:mini-policy")
include("libs:mini-client-common")
include("libs:mini-directory-client")
include("libs:mini-idp-client")
include("libs:mini-oidc-client")
include("libs:mini-ca-client")
include("libs:mini-gateway-client")
```
(mini-kms keeps its existing `include("services:mini-kms:client")` — not relocated.)

Move `services:mini-console` out of the "roadmap placeholders" comment block (mini-ca already shipped, so that comment is stale anyway — fix it in passing).

**Catalog:** no new versions needed. Everything resolves through existing `libs.jackson.databind`, `libs.jackson.yaml` (only if OpenAPI kept), `libs.bouncycastle-pkix` (harness chain validation for mini-ca). No inline versions anywhere.

mini-console's `build.gradle.kts`:

```kotlin
plugins { id("miniauth.application-conventions") }
dependencies {
    implementation(project(":libs:mini-directory-client"))
    implementation(project(":libs:mini-idp-client"))
    implementation(project(":libs:mini-oidc-client"))
    implementation(project(":libs:mini-ca-client"))
    implementation(project(":libs:mini-gateway-client"))
    implementation(project(":services:mini-kms:client"))   // existing KmsClient (+ KmsSigningKeyStore) — the socket-era exception, not relocated
    implementation(project(":libs:mini-token"))            // offline JWS/JWKS verify in the harness
    implementation(project(":libs:mini-policy"))           // render/check grant decisions
    implementation(libs.jackson.databind)
    implementation(libs.jackson.yaml)                      // only if /api openapi.yaml is kept
    implementation(libs.bouncycastle.pkix)                 // X.509 chain validation in CertLifecycleFlow
}
application { mainClass = "com.codeheadsystems.miniconsole.ServerMain" }
```

---

## 3. The client libraries — interface sketches

All clients: constructed from a base URL (loopback) + a token supplier; admin calls send `Authorization: Bearer <token>`; **every** failure collapses to a single `ClientException` (no status/body distinction surfaced to callers — no oracle); secrets passed as `char[]`/`byte[]` and never placed in exception messages or logs. Records are Jackson-bound by parameter name (`-parameters`).

### 3.1 `mini-directory-client` — `com.codeheadsystems.minidirectory.client`
Copies: `Account`, `Group`, `Role`, `GrantSpec`, `ResolvedPrincipal` (into `…client.model`). Admin bearer (`MINIDIR_ADMIN_TOKEN` held by console).

```java
public interface MiniDirectoryClient {
  // Accounts (HUMAN | SERVICE_ACCOUNT)
  Account createAccount(NewAccount spec);                 // returns secret ONCE for SERVICE_ACCOUNT (char[] in NewSecret)
  Account getAccount(String id);
  List<Account> listAccounts();
  Account updateAccount(String id, AccountPatch patch);
  void    deleteAccount(String id);
  // Groups / Roles CRUD
  Group createGroup(NewGroup g);   List<Group> listGroups();  void deleteGroup(String id);
  Role  createRole(NewRole r);     List<Role>  listRoles();   void deleteRole(String id);
  // Assignment
  void assignRoleToAccount(String accountId, String roleId);
  void removeRoleFromAccount(String accountId, String roleId);
  void addAccountToGroup(String accountId, String groupId);
  void removeAccountFromGroup(String accountId, String groupId);
  void assignRoleToGroup(String groupId, String roleId);
  // The defining call
  ResolvedPrincipal resolve(String accountId);            // GET /admin/principals/{id}/resolution
  // No-oracle credential check (service accounts)
  AuthOutcome authenticate(String accountId, char[] secret);   // PASS/FAIL only; secret zeroed by impl
}
```

### 3.2 `mini-idp-client` — `com.codeheadsystems.miniidp.client`
Copies: `TokenResponse` (`access_token`, `token_type`, `expires_in`), `Jwks` (reuse mini-token's JWKS model rather than copy — depend on `:libs:mini-token` for the model only). Token endpoint is **public** (client-credentials); admin/JWKS as applicable.

```java
public interface MiniIdpClient {
  TokenResponse token(String clientId, char[] clientSecret);   // POST /oauth/token (client_credentials)
  Jwks jwks();                                                  // GET the JWKS for offline verify
  RotationResult rotateSigningKey();                           // admin: POST /admin/keys/rotate → {activeKid} (endpoint EXISTS today)
  List<Revocation> revocations();   void revoke(String jti, String reason);  // admin: token denylist
  List<AuditEntry> audit();                                    // admin: GET /admin/audit
  HealthStatus health();                                        // GET /health
}
```

### 3.3 `mini-oidc-client` — `com.codeheadsystems.minioidc.client`
Copies: `DiscoveryDocument`, `TokenResponse` (id+access+refresh), `ClientRegistration`/`RegisteredClient`. Mix of public (discovery/jwks/token/userinfo) + admin (client registration).

```java
public interface MiniOidcClient {
  DiscoveryDocument discovery();                       // GET /.well-known/openid-configuration
  Jwks jwks();                                          // GET /jwks.json
  RegisteredClient registerClient(ClientRegistration r);// admin: register an OIDC client
  // Authorization-code + PKCE: the harness needs to construct /authorize URLs and exchange codes.
  URI authorizeUrl(AuthorizeRequest req);               // builds the /authorize URL incl. code_challenge(S256)
  TokenResponse exchangeCode(String code, String codeVerifier, String redirectUri, String clientId);
  TokenResponse refresh(String refreshToken, String clientId);
  UserInfo userInfo(String accessToken);                // GET /userinfo (bearer = the just-issued access token)
  RotationResult rotateSigningKey();                    // admin: POST /admin/keys/rotate (NEW endpoint — added to mini-oidc, mirrors mini-idp)
  HealthStatus health();
}
```
Note: the full browser passkey ceremony is **not** automatable headlessly from a pure HTTP client; the OIDC harness flow uses a pre-seeded test session/consent shortcut where available, and is otherwise marked SKIP with an honest reason (see §5). The client lib exposes the protocol calls; it does not embed pk-auth.

### 3.4 mini-kms — **reuse the existing `:services:mini-kms:client` as-is** (documented exception)
`KmsClient` already exposes both planes — data (`encrypt`/`decrypt`/`reEncrypt`/`generateDataKey`/`health`) and control (`createKeyGroup`/`rotateKeyGroup`/`listKeyGroups`/`disableVersion`/`enableVersion`/`destroyVersion`) — so mini-console consumes it directly; nothing is wrapped or re-implemented. Relocating `KmsClient` + `KmsSigningKeyStore` into a `libs/mini-kms-client` was designed and independently reviewed: it is mechanically clean and behavior-preserving, but the maintainer **declined** it — the benefit is cosmetic parity with a not-yet-built `libs/<svc>-client` convention, against real churn in three shipping services (mini-idp/mini-oidc/mini-ca) plus a split-package or import-rewrite cost. mini-kms's client is recorded as the deliberate **socket-era exception** in `docs/DIRECTION.md`, and is the first candidate to move *if* that convention later hardens.

```java
// the existing KmsClient API under :services:mini-kms:client — used as-is, nothing re-implemented
KmsClient connectTcp(String host, int port, String token);   // also connectUnix(Path, token)
boolean health();
// data plane (API token):     generateDataKey / encrypt / decrypt / reEncrypt
// control plane (admin token): createKeyGroup / rotateKeyGroup / listKeyGroups
//                              disableVersion / enableVersion / destroyVersion
```

The two mini-kms tokens (`MINIKMS_API_TOKEN` + `MINIKMS_ADMIN_TOKEN`) are resolved env/file by the console exactly as the CLI does.

### 3.5 `mini-ca-client` — `com.codeheadsystems.minica.client`
Copies: `IssueRequest` (CSR PEM), `Certificate` (leaf PEM), `RevocationEntry`, `IssuanceLogEntry`. Public: `/ca`, `/revocations`, `/health`. Admin: issue/renew/revoke/log.

```java
public interface MiniCaClient {
  String caCertificatePem();                       // GET /ca (public trust anchor)
  List<RevocationEntry> revocations();             // GET /revocations (public)
  Certificate issue(String csrPem, Duration ttl);  // admin: POST CSR → leaf
  Certificate renew(String csrPem);                // admin
  void revoke(String serial, String reason);       // admin
  List<IssuanceLogEntry> issuanceLog();            // admin
  HealthStatus health();
}
```

### 3.6 `mini-gateway-client` — `com.codeheadsystems.minigateway.client`
Copies: nothing material (header-driven). Public-ish `/verify` (the proxy calls it; console calls it as the proxy would, to exercise it).

```java
public interface MiniGatewayClient {
  VerifyOutcome verify(VerifyRequest req);   // sends X-Forwarded-Method/Uri + Cookie|Authorization
                                             // → 200(+X-Auth-Subject/Scope/Source) | 302 | 401 | 403
  HealthStatus health();
}
// VerifyOutcome maps the status to AUTHORIZED / REDIRECT_LOGIN / UNAUTHENTICATED / FORBIDDEN — no body oracle.
```

### 3.7 mini-common overlap & whether a shared client lib is warranted
**Warranted — yes.** The env/file token resolver and the loopback `HttpClient`/JSON plumbing are exactly two of the documented `mini-common` candidates (ServerConfig secret resolution; and HTTP plumbing is the natural client-side twin). Rather than copy them into five clients, `libs/mini-client-common` holds them once. This is the *client-side* counterpart to the still-deferred server-side `mini-common` — the doc updates note that when server-side `mini-common` lands, `TokenResolver` can be unified with `ServerConfig.resolveToken`. Dependency direction stays one-way (clients → client-common → catalog); no cycle.

---

## 4. Console pages (operator mode)

Server-rendered HTML, hand-rolled in the mini-oidc `LoginPages` spirit. **CSRF token on every state-changing POST** (minted per page render, validated on submit — mini-oidc's pattern). Loopback only, behind the console admin token (a session cookie set after the operator presents the token, OR the token on each request). All output HTML-escaped via a `Layout` helper; **no page ever renders a downstream secret** (the once-only service-account secret is shown exactly once at creation, with a copy-and-dismiss banner, never re-fetchable and never logged).

| Screen | Route(s) | Backing client call(s) |
| --- | --- | --- |
| Dashboard | `GET /` | health() across all six |
| Identities — list | `GET /identities` | `listAccounts/listGroups/listRoles` |
| Identities — detail + resolution preview | `GET /identities/{id}` | `getAccount` + `resolve(id)` |
| Identities — create/edit | `GET/POST /identities`, `POST /identities/{id}` | `createAccount/updateAccount` (secret shown once) |
| Identities — assignment | `POST /identities/{id}/roles`, `/groups` | assign/remove role/group |
| Identities — delete | `POST /identities/{id}/delete` | `deleteAccount` |
| Keys — signing keys | `GET /keys`, `POST /keys/{issuer}/rotate` | `rotateSigningKey()` on idp/oidc (`POST /admin/keys/rotate`) + JWKS readback to confirm new kid |
| Keys — KMS key groups | `GET /keys/kms`, `POST /keys/kms/{name}/{op}` | KmsClient control plane: create/rotate/disable/enable/destroy |
| Audit | `GET /audit` | issuance/rotation/revocation logs (idp/oidc/token) |
| Certificates | `GET /certificates` | `issuanceLog()` + `revocations()` |
| Certificates — issue/renew/revoke | `POST /certificates/...` | `issue/renew/revoke` |
| Harness | `GET /harness`, `POST /harness/{flow}/run` | see §5 |

All POST routes carry a hidden `_csrf` field; the handler rejects a missing/mismatched token with a generic 400 before any client call. Destructive ops (`destroy` key version, `delete` account, `revoke` cert) render a confirm step.

---

## 5. Exercise / test harness (test mode)

The harness is an **I/O-free engine** (`harness/`) given the wired clients; each flow returns an `ExerciseResult(name, Status, steps, redactedDetail)`. **"Pass" is defined per flow as a cryptographic/state assertion verified offline**, not just an HTTP 200. Results render as green/red rows with per-step detail; **no step ever records a secret** — tokens/secrets are replaced with `«redacted»` and only non-secret facts (kid, sub, exp, serial, status code) are shown.

| Flow | Drives | "Pass" = (verified offline) |
| --- | --- | --- |
| **M2mTokenFlow** | `idp.token(client,secret)` → `idp.jwks()` | JWS signature verifies against JWKS via mini-token's `TokenVerifier`; `iss`/`aud`/`exp` valid; `grants` matches directory `resolve()` |
| **OidcCodePkceFlow** | build `/authorize` (S256) → `exchangeCode(verifier)` → `userInfo` → `refresh` | id_token signature verifies against `/jwks.json`; `nonce`/`aud`/`auth_time` present; refresh rotates (old refused → no-oracle `invalid_grant`). *Passkey step is SKIP with reason "headless WebAuthn not driven" unless a test credential is seeded.* |
| **CertLifecycleFlow** | generate keypair+CSR locally → `ca.issue` → `ca.renew` → `ca.revoke` | issued leaf chains to `ca.caCertificatePem()` (Bc PKIX `CertPathValidator`); serial appears in `revocations()` after revoke |
| **GatewayVerifyFlow** | `gateway.verify` with (a) no creds, (b) valid bearer, (c) insufficient scope | (a) → 302/401, (b) → 200 + `X-Auth-Subject`, (c) → 403. Asserts all three branches |
| **KeyRotationFlow** | rotate a signing key → re-fetch JWKS | new `kid` present in JWKS; retired `kid` retained (in-flight tokens still verify); a token minted pre-rotation still verifies |

`ExerciseRegistry` lists them; the Harness page runs one or all and shows a summary line (`4 passed, 1 skipped, 0 failed`). The engine is unit-testable against in-memory fakes of the six clients (mirrors how the services test their SPIs), so the harness has real tests independent of a running family.

---

## 6. Security model

- **Adds no new authority.** Every action equals an operator curling a downstream admin API with the same token. mini-console stores **no identity, no grants, no keys** — only its own login-session/CSRF state, persisted in an atomic-`0600` `JsonStore` (`console-sessions.json`).
- **Console auth:** its own bootstrap token from `MINICONSOLE_ADMIN_TOKEN` env or `--admin-token-file` (never argv, never logged), validated constant-time (`MessageDigest.isEqual`) via the copied `AdminAuthenticator`. Loopback bind by default; any LAN exposure is an explicit operator decision behind TLS.
- **Console session (confirmed):** after the operator presents the console token once, mini-console establishes a login session using **mini-token's `SessionService` mechanism over its OWN `JsonStore`-backed store** (`console-sessions.json`, atomic `0600` in `--data-dir`) — a separate namespace from the family SSO session, with a **distinct cookie name** (not `SessionService.DEFAULT_COOKIE_NAME`, to avoid colliding with a mini-oidc cookie on a shared host). Session state persists across restarts; CSRF tokens are bound to the session.
- **Downstream tokens (the one new secret concentration):** mini-console must hold up to six downstream admin/API tokens to do its job. Each is resolved env/file (`MINIDIR_ADMIN_TOKEN`, `MINIIDP_ADMIN_TOKEN`, `MINIOIDC_ADMIN_TOKEN`, `MINIKMS_API_TOKEN`+`MINIKMS_ADMIN_TOKEN`, `MINICA_ADMIN_TOKEN`), held as `char[]`/`byte[]`, never argv, never logged, zeroed on shutdown. The README states plainly that running mini-console means concentrating these tokens in one loopback process — a deliberate operator trade-off, mitigated by loopback default.
- **No oracles anywhere:** client libs collapse all failures to one `ClientException`; the console renders a single generic error; the harness reports FAIL without distinguishing why in a way that leaks (it shows the *expected* assertion that failed, not downstream internals).
- **No secrets in logs, including fetched ones:** the once-only service-account secret and any minted token are shown in the UI exactly where needed and replaced with `«redacted»` everywhere else; access logs record method/path/status only (family rule).
- **CSRF** on every state-changing browser POST; **PKCE S256** mandatory in the OIDC harness flow.

---

## 7. Build & test plan

- **Convention change:** flip mini-console from `library-conventions` → `application-conventions`, add `mainClass`, add the client-lib deps. Each new `libs/*-client` uses `library-conventions`; `mini-client-common` likewise. mini-kms is consumed via its existing `:services:mini-kms:client` (not relocated — see §3.4).
- **mini-oidc rotation endpoint (new):** add `POST /admin/keys/rotate` to mini-oidc mirroring mini-idp's existing handler, plus an `openapi.yaml`/`OpenApiContractTest` entry and a unit test asserting the new kid appears in `/jwks.json` with the retired kid retained.
- **The trip-wire:** flip `MiniConsole.IMPLEMENTED = true` and **delete** `MiniConsoleTest` (the guard), replacing it with real tests. This is the designed trip-wire — the moment `IMPLEMENTED` flips, the old guard fails, forcing real tests in. Call this out in the first slice's PR.
- **Real tests:** (a) each client lib against an in-memory fake server or the real service booted in-test (mirrors mini-oidc's KMS-backed test that boots real mini-kms); (b) the harness engine against in-memory client fakes; (c) `ConsoleHandlers` route + CSRF tests against a live in-process `HttpServer`.
- **Contract test:** an `OpenApiContractTest` for the `/api` JSON surface, asserting documented paths resolve on the live console — same pattern as the other services.
- **Green gate:** `./gradlew build` from root must stay green. New modules compile + test under the one wrapper/catalog/conventions. No inline versions; Jackson 3.x (`tools.jackson.*`); `System.Logger`; `-parameters` (inherited).

---

## 8. Implementation roadmap (vertical slices, dependency order)

Each slice is independently shippable and leaves the build green. Recommended ordering — establish the shared plumbing, then land the simplest read-only vertical end-to-end (client lib + page + harness flow) before the mutating ones:

1. **Slice 0 — `mini-client-common` + console skeleton (server, config, http router, AdminAuthenticator, console-login session via mini-token `SessionService` over `JsonStore`, Layout, Dashboard page, console token).** Flip `IMPLEMENTED`, delete the guard test, add real skeleton tests. Dashboard shows `health()` of services that have a client yet (none → all "n/a"). Ships the trip-wire.
2. **Slice 1 — `mini-directory-client` + Identities pages (read-only: list + detail + resolution preview).** The richest, most-used surface; read-only first. Verifies the client/page/CSRF kit end to end.
3. **Slice 2 — Identities mutations (create/edit/assign/delete) + the once-only-secret banner.** Adds CSRF-guarded POSTs.
4. **Slice 3 — `mini-idp-client` + `mini-token` reuse + M2mTokenFlow (harness).** First exercise flow; proves offline JWS-vs-JWKS verification. Audit page (idp side) lands here.
5. **Slice 4 — mini-kms reuse (`:services:mini-kms:client`) + Keys page (KMS key groups + issuer signing-key rotation) + KeyRotationFlow.** Includes adding `POST /admin/keys/rotate` to mini-oidc (mini-idp already has it). Control-plane key-group mgmt + rotation verification.
6. **Slice 5 — `mini-ca-client` + Certificates page + CertLifecycleFlow.** Adds Bc PKIX chain validation.
7. **Slice 6 — `mini-oidc-client` + OidcCodePkceFlow (passkey step honestly SKIP) + client registration page.**
8. **Slice 7 — `mini-gateway-client` + GatewayVerifyFlow (200/401/403/302 branches).**
9. **Slice 8 — optional `/api` JSON surface + `OpenApiContractTest` + SwaggerUiPage; harness "run all" summary; README rewrite.**

**Recommended first slice: Slice 0 + Slice 1 together** — they prove the whole vertical (shared plumbing → client lib → server-rendered page) on the read-only directory surface, ship the `IMPLEMENTED` trip-wire honestly, and add zero mutation risk. Everything after is additive.

---

## 9. Documentation updates

- **`docs/DIRECTION.md`:** move mini-console out of "Future tracks (explicitly not scheduled)" into the roadmap as the active track; update the component-catalog row (Status: shipping/in-progress); add a short subsection describing the client-lib layer + `mini-client-common` and explicitly noting it adds no new authority. Update the `mini-common` section to note the client-side `TokenResolver`/HTTP plumbing now live in `mini-client-common` and should converge with server-side `mini-common` when that lands. Record the new mini-oidc rotation endpoint. (The mini-kms client relocation was considered and **declined** — the deliberate-exception note is already recorded in DIRECTION.md's signing-key-wrapping section; no change to mini-kms is needed.)
- **mini-oidc rotation endpoint:** document the new `POST /admin/keys/rotate` in mini-oidc's section + `openapi.yaml` (mirrors mini-idp's existing endpoint).
- **Root `CLAUDE.md`:** update the layout table (mini-console: service/shipping; add the five `libs/*-client` + `mini-client-common` rows), add a `# Service: mini-console` section mirroring the others (architecture, the page/harness split, the security model, the "no new authority" statement, the downstream-token concentration caveat), and update the `settings.gradle.kts` include list. Fix the stale "roadmap placeholders" comment (mini-ca already shipped). mini-kms's section is unchanged (its client stays put — the documented socket-era exception).
- **`services/mini-console/README.md`:** replace the placeholder doc with a real teaching README — the two faces (operator console + exercise harness), the screen/route list, the harness flows and what "pass" means, the security model (loopback, console token, downstream-token concentration, no-oracle/no-secret-logging), and runnable `installDist` instructions. Remove the "roadmap placeholder" framing.
- **`settings.gradle.kts` header comment:** update the layout map (mini-console no longer a placeholder; new libs listed).

---

## Resolved decisions (confirmed with maintainer)

1. **Token model:** held-token — mini-console holds its own console-login token plus each downstream admin/API token (env/file, never argv, never logged, zeroed on shutdown), with the loopback caveat stated plainly in the README. (Not per-downstream passthrough.)
2. **Console login session:** reuse mini-token's `SessionService` mechanism over the console's **own** `JsonStore`-backed store, with a **distinct cookie name** (not the shared SSO cookie) to avoid collision on a shared host. Console stays free of the family SSO session file.
3. **State persistence:** session/CSRF state persists in an atomic-`0600` `JsonStore` (`console-sessions.json`) under `--data-dir`.
4. **`/api` OpenAPI surface:** kept, with an `OpenApiContractTest` — the console honors the family contract-test pattern.
5. **Signing-key rotation endpoint:** there is an admin HTTP trigger. mini-idp already exposes `POST /admin/keys/rotate`; **mini-oidc gains the same endpoint** (a small, additive cross-service change), so `rotateSigningKey()` is callable on both issuers from the Keys page.
6. **mini-kms client relocation: declined — keep as-is.** `KmsClient` + `KmsSigningKeyStore` stay in `:services:mini-kms:client`; mini-console consumes that module directly, like mini-idp/mini-oidc/mini-ca. The relocation into `libs/mini-kms-client` was designed and independently reviewed (mechanically clean, behavior-preserving) but judged cosmetic-and-speculative against real churn in three shipping services. mini-kms's client is documented as the deliberate **socket-era exception** in `docs/DIRECTION.md`, and is the first candidate to follow a `libs/<svc>-client` convention *if* one ever hardens.

No open questions remain. Two follow-on notes to carry into implementation: (a) the console session cookie **must** use a name distinct from `SessionService.DEFAULT_COOKIE_NAME`; (b) the mini-oidc rotation endpoint is a genuine (if small) addition to another service — land it with its own contract-test + unit test in Slice 4.

**Recommended first slice: Slice 0 + Slice 1** (shared client plumbing + console skeleton with the `IMPLEMENTED` trip-wire and console-login session, then the read-only Identities vertical), landing one full client-lib → page path with zero mutation risk and a green `./gradlew build`.
