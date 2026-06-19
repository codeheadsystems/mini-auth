# Slice 0 — mini-console skeleton: implementation plan

Slice 0 is **pure server-rendered HTML** — no `/api`, no OpenAPI, no SwaggerUI, no client libs, no
mini-policy (those are Slice 1/8). It compiles, runs, serves a login + Dashboard behind a console
session, and ships the trip-wire.

**Confirmed decisions (maintainer):** default port **8500**; login error re-renders `/login` at
**200** (no oracle); short "runnable skeleton" README note now + full rewrite at Slice 8; CSRF via
**double-submit cookie**. `libs/mini-client-common` is **deferred to Slice 1**.

## Headline decision

**Defer `libs/mini-client-common` to Slice 1. Do NOT create it in Slice 0.** Slice 0 has **zero**
real downstream calls (no client lib exists; the Dashboard renders "n/a — client not wired yet").
Landing `mini-client-common` now means shipping an **unconsumed abstraction** whose API (token
resolver shape, HttpClient builder signature, error-collapse type) would be guessed rather than
driven by its first real consumer (the directory client in Slice 1) — the "scaffold that looks
finished" the family ethos forbids. Slice 0 needs only env/file **console-token** resolution, a
~12-line `resolveToken` copied from mini-oidc's `ServerMain`, local to the console module. When
Slice 1 writes `MiniDirectoryClient` and needs the same plumbing for the *downstream* token +
HttpClient, that is when `mini-client-common` is extracted, against a real caller.

## Assumptions

1. Console login uses a **paste-the-console-token-into-a-form** model (not a Bearer header) — the
   operator is a human in a browser; a form+session is the right UX and lets the rest of the console
   rely on a session cookie rather than re-presenting the token per request.
2. The console session reuses mini-token's `SessionService` over a `JsonStore`
   `DocumentStore<Sessions>`, with a **distinct cookie name** `mini-console-session` (mini-token's
   `DEFAULT_COOKIE_NAME` is `"mioidc_session"`, `SessionService.java:31` — the console must NOT share
   it, or it collides with a co-hosted mini-oidc SSO session).
3. CSRF: one state-changing POST pair matters in Slice 0 (`/login`, `/logout`). A minimal `Csrf`
   helper (double-submit cookie) is included now since `/login` genuinely needs it.
4. Console token env var `MINICONSOLE_ADMIN_TOKEN` + `--admin-token-file` (mirrors the family's
   `MINI*_ADMIN_TOKEN` + `--admin-token-file`).
5. Default port **8500** (one above mini-ca's 8499).

---

## 1. Module graduation — `services/mini-console/build.gradle.kts`

```kotlin
/*
 * mini-console - the optional unified admin console over the mini- family.
 *
 * Slice 0: the runnable skeleton — a loopback HTTP server, a console-login session, and a Dashboard
 * that honestly reports "client not wired yet" for each downstream service (no client libs exist
 * yet). It invents NO new authority; later slices add the per-service client libraries + pages.
 *
 * Graduates from library-conventions to application-conventions (it is now runnable).
 */

plugins {
    id("miniauth.application-conventions")
}

dependencies {
    // The shared browser-session mechanism (SessionService) + the DocumentStore SPI the copied
    // JsonStore implements. This is the ONLY family dependency Slice 0 genuinely needs.
    implementation(project(":libs:mini-token"))
    // JSON for the session store document (Sessions) and any future page DTOs.
    implementation(libs.jackson.databind)
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}

application {
    mainClass = "com.codeheadsystems.miniconsole.ServerMain"
}
```

**Not present in Slice 0:** no `libs.jackson.yaml` (no OpenAPI until Slice 8), no `:libs:mini-policy`,
no client libs, no bouncycastle. Only `mini-token` + `jackson.databind`.

---

## 2. File-by-file creation list — `src/main/java/com/codeheadsystems/miniconsole/`

Base package `com.codeheadsystems.miniconsole`. "Copy" = lift verbatim from the cited source, rename
package to `…miniconsole.*`, adjust imports. "Fresh" = new code.

### `ServerMain.java` — fresh (model: mini-oidc `ServerMain.java:41-113`)
- `main(String[] args)` → `run(args, System.getenv())`, catch + exit-1 on config error.
- `run`: `ConsoleConfig.resolve(args, env)`; `resolveToken(env.get("MINICONSOLE_ADMIN_TOKEN"),
  config.adminTokenFilePath(), …)`; `ConsoleServer.create(config, consoleToken, Clock.systemUTC())`;
  `start()`; await shutdown latch.
- `resolveToken(String fromEnv, Path file, String missing)` — copy verbatim from
  `ServerMain.java:101-113` (env → file → throw; trim/strip; never argv, never logged).

### `server/ConsoleConfig.java` — fresh, trimmed (model: mini-oidc `ServerConfig.java:42-245`)
- Fields: `host`, `port`, `dataDir`, `adminTokenFilePath`, `secureCookies`, `sessionTtl`. Drop all
  OIDC/KMS/argon knobs.
- `resolve(String[] args, Map<String,String> env)`: flags `--host/--port/--data-dir/--admin-token-file/--secure-cookies/--session-ttl-seconds`;
  envs `MINICONSOLE_HOST/PORT/DATA_DIR/ADMIN_TOKEN_FILE/SECURE_COOKIES/SESSION_TTL_SECONDS`.
  `DEFAULT_HOST="127.0.0.1"`, `DEFAULT_PORT=8500`, session TTL 12h (`43_200`), `defaultDataDir` →
  `$XDG_DATA_HOME/mini-console` or `~/.mini-console`.
- Copy helpers `requireValue`/`envInt`/`defaultDataDir`/port-range check from `ServerConfig.java`.

### `server/http/` kit — copy verbatim (package → `…miniconsole.server.http`)
| File | Source |
| --- | --- |
| `Router.java` | mini-oidc `server/http/Router.java` |
| `RequestContext.java` | `server/http/RequestContext.java` |
| `HttpResponse.java` | `server/http/HttpResponse.java` |
| `ApiException.java` | `server/http/ApiException.java` |
| `Json.java` | `server/http/Json.java` (required: `HttpResponse.json` references `Json.toBytes`) |

No `StaticResource.java` (Slice 0 serves no static assets).

### `server/AdminAuthenticator.java` — copy verbatim (mini-oidc `AdminAuthenticator.java:19-67`)
- Constant-time `MessageDigest.isEqual`. Add a `boolean matches(String presented)` for the
  form-login path alongside the existing `requireAdmin(authorizationHeader)`. Preserve the
  touch-the-buffer-on-null trick.

### `server/ConsoleSession.java` — fresh, thin wrapper over `SessionService`
- Construct as in `OidcServer.java:103-104`: `new SessionService(new JsonStore<>(dataDir.resolve("console-sessions.json"), Sessions.class), clock, sessionTtl)`.
- SessionService API: `String create(subject, authTime)`, `Optional<BrowserSession> lookup(id)`,
  `void destroy(id)`.
- Methods: `establish()` → `create("console-admin", now)`; `isValid(id)` → `lookup(id).isPresent()`;
  `end(id)` → `destroy(id)`.

### `server/Cookies.java` — copy + adapt (mini-oidc `Cookies.java:17-47`)
- **Critical change:** replace `SESSION = SessionService.DEFAULT_COOKIE_NAME` with
  `SESSION = "mini-console-session"`. Keep `session(value, maxAge)` + `clearSession()`.

### `server/Csrf.java` — fresh, minimal (double-submit)
- `GET /login` mints a random base64url token, set in a short-lived HttpOnly `mini-console-csrf`
  cookie and embedded in the form; `POST /login` requires `cookie == form field` (constant-time).
- Methods: `String mint()`, `boolean verify(String expected, String presented)`.

### `store/JsonStore.java` — copy verbatim (mini-oidc `store/JsonStore.java:34-105`)
- Atomic temp-file → `ATOMIC_MOVE` → `0600` `DocumentStore<T>`. Backs `console-sessions.json`.

### `pages/Layout.java` — fresh
- `page(String title, String bodyHtml)` wrapping `<!DOCTYPE html>…<nav>` (Dashboard, Logout). Copy
  the `escape(String)` entity-escaper from `LoginPages.java:109-115`. Never renders a secret.

### `pages/LoginPage.java` — fresh (model: `LoginPages.login`, simplified — no WebAuthn JS)
- `render(String csrf, boolean error)` → `<form method="post" action="/login">` with a hidden `csrf`
  field + `<input type="password" name="token">` + submit. On error, one generic "Sign-in failed."

### `pages/DashboardPage.java` — fresh (see §4)
- `render(...)` → console self-status + the six-service placeholder grid ("n/a — client not wired
  yet — Slice N").

### `server/ConsoleHandlers.java` — fresh (model: `OidcHandlers` → `Router` assembly)
- Holds `ConsoleSession`, `AdminAuthenticator`, `Cookies`, `Csrf`, `Clock`. `Router router()`
  registers the §3 route table. Private `requireSession(ctx)` → redirect to `/login` if invalid.

### `server/ConsoleServer.java` — fresh (composition root; model: `OidcServer.create` + bind)
- `create(ConsoleConfig, String consoleToken, Clock)`: build the pieces, then bind exactly like
  mini-oidc: `HttpServer.create(new InetSocketAddress(host, port), 0)`; `createContext("/", router)`;
  `setExecutor(Executors.newVirtualThreadPerTaskExecutor())`. `start()/stop()/address()`.

### Delete: `MiniConsole.java` — see §5.

---

## 3. Console-login flow + route table

Paste-into-form + session (not token-per-request): the operator is a human in a browser. The console
token is the bootstrap credential (constant-time compared, never logged), presented in a **password
field over a POST body** (not URL, not header — never lands in access logs); the HttpOnly session
cookie is the carry-forward.

| Method | Path | Auth | Behavior / response |
| --- | --- | --- | --- |
| `GET` | `/login` | none | Render `LoginPage` + fresh CSRF (set `mini-console-csrf`). 200 HTML. |
| `POST` | `/login` | CSRF | Verify CSRF (else 400). Constant-time token compare. Match → `establish()` → `Set-Cookie: mini-console-session` → **302 → `/`**. Mismatch → re-render `/login` with generic error, **200** (no oracle). |
| `GET` | `/` | valid session | Dashboard. 200 HTML. Else 302 → `/login`. |
| `GET` | `/health` | none | `200 {"status":"ok"}` — liveness, no client calls. |
| `POST` | `/logout` | session + CSRF | `end(id)` → clear cookie → 302 → `/login`. |
| (any) | unmatched | — | 404; wrong method on known path → 405. |

No-oracle throughout: bad/missing token and CSRF failure collapse to a single generic outcome.

---

## 4. Dashboard with no clients yet (honest, not faked)

- **Console self-status:** "mini-console — running" + bound address + session principal
  ("console-admin") + a CSRF-protected Logout button.
- **Placeholder service grid** — one row per service, rendered literally as
  `mini-directory — n/a (client not wired yet — Slice 1)` etc., with the slice number where it lands.
  Calls **nothing** downstream and fabricates no health — the honest seam. Each later slice flips its
  row from "n/a" to a real `health()` result.

---

## 5. The trip-wire

- `MiniConsole.IMPLEMENTED` is referenced **only** by `MiniConsoleTest` (no production caller) →
  **delete `MiniConsole.java` entirely** rather than flip the flag to `true` (a `true` constant
  nobody reads is dead code).
- **Delete `MiniConsoleTest.java`** (the guard) — its job ("fail the moment real work begins") is
  fulfilled; deleting it alongside the class, replaced by the §6 tests, is the trip-wire firing.
- Replace the README's "flip `IMPLEMENTED`" framing with a short "Slice 0: runnable skeleton" note.

---

## 6. Tests — `src/test/java/com/codeheadsystems/miniconsole/`

All against an in-process `ConsoleServer` on an **ephemeral port** (`--port 0`, read back via
`address().getPort()`), driven with `java.net.http.HttpClient`. No OpenApiContractTest (Slice 8).

1. **`ConsoleServerTest`**: `health_isPublic`; `dashboard_requiresSession` (302→/login);
   `login_happyPath` (GET /login → capture CSRF → POST /login correct token+CSRF → 302→/, session
   cookie set → GET / → 200 "mini-console"); `login_wrongToken_noOracle` (no session, generic);
   `login_csrfReject` (400); `logout_clearsSession`; `dashboard_isHonest` (body contains "client not
   wired yet").
2. **`ConsoleConfigTest`**: resolve precedence (flag > env > default), port-range rejection,
   data-dir resolution, unknown-flag rejection.
3. **(optional) `CsrfTest`**: mint/verify round-trip + reject.

The secret is never asserted by value; tests pass the token in the request body only.

---

## 7. settings.gradle.kts / catalog

- `include("services:mini-console")` **already exists** — no include change. **Fix the stale
  comment** that still calls mini-ca *and* mini-console "roadmap placeholder" (mini-ca shipped).
- `gradle/libs.versions.toml`: **no version additions** — only `jackson` + `junit-jupiter`, both
  present.

---

## 8. Verification

```bash
./gradlew build                              # full family CI gate, stays green
./gradlew :services:mini-console:test        # module tests
./gradlew :services:mini-console:installDist
export MINICONSOLE_ADMIN_TOKEN="$(openssl rand -hex 32)"
services/mini-console/build/install/mini-console/bin/mini-console --port 8500 --data-dir /tmp/mini-console &
curl -s http://127.0.0.1:8500/health         # -> {"status":"ok"}
curl -s -i http://127.0.0.1:8500/             # -> 302 Location: /login
```

**Done:** `./gradlew build` green family-wide with no regressions; `MiniConsole.java` +
`MiniConsoleTest.java` gone, replaced by the §6 tests; `installDist` yields a `bin/mini-console`
launcher binding loopback:8500, `/health` public, `/` → 302→/login without a session, and after a
correct token paste an authenticated Dashboard that honestly says "client not wired yet." No secret
in any log line.

---

## 9. PR framing

> **Slice 0 graduates mini-console from roadmap placeholder to a runnable skeleton.** It **fires the
> trip-wire by design:** deletes `MiniConsole.IMPLEMENTED` (referenced only by the guard test) and
> `MiniConsoleTest`, replacing them with real `ConsoleServer`/`ConsoleConfig`/CSRF tests. Here: a
> loopback HTTP server (virtual-thread-per-request), a paste-the-console-token login minting a
> mini-token `SessionService` session under a **distinct** `mini-console-session` cookie, and a
> Dashboard. **Deliberately NOT here (honest seams):** the Dashboard calls nothing downstream —
> "n/a — client not wired yet (Slice N)" for each service. `libs/mini-client-common` is intentionally
> deferred to Slice 1 (driven by its first real consumer). No OpenAPI/SwaggerUI (Slice 8). The
> console adds **no new authority** — Slice 0 holds only its own bootstrap console token (env/file,
> never argv, never logged).
