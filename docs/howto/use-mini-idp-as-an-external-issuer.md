# How-to: use mini-idp as the token issuer for another project

> **How-to (task-oriented).** Make a service *outside* the mini- family (a "relying party") accept
> mini-idp's machine tokens, in production and in that project's CI (with `TestIdp` from Maven
> Central). The worked example is
> **config-server** (`~/projects/config`, `com.codeheadsystems:config-*`), but every step applies to
> any JOSE-based verifier (Nimbus, jose4j, Spring Security's resource server, `go-jose`, `jose` in
> Node, ...). Reference: [`services/mini-idp/README.md`](../../services/mini-idp/README.md).
> Concept: [`what-a-token-is.md`](../concepts/what-a-token-is.md).

## What mini-idp offers a relying party

| Need | What mini-idp provides |
| --- | --- |
| Find the keys | Discovery at `<issuer>/.well-known/openid-configuration` (also `/.well-known/oauth-authorization-server` and the original `/.well-known/idp-configuration`, all identical) naming `issuer` and `jwks_uri`. |
| A token meant for *you* | The client asks for your audience with RFC 8707 `resource=<aud>` (or `audience=<aud>`). mini-idp issues it only if that client is allowlisted for the audience; otherwise `400 invalid_target`. |
| An algorithm your stack accepts | Tokens for the default audience are EdDSA (Ed25519). The operator can map any audience to **ES256** (P-256, raw 64-byte `R‖S`), which every mainstream JOSE library verifies. |
| Key rotation without coordination | Each algorithm has its own key set. The **next** key is published before it signs anything, so the kid used after a rotation is already in a verifier's cached JWKS; retired keys stay for 2x the token TTL. A verifier whose JWKS refetch is rate-limited (config-server's Nimbus source: twice per 30 s) therefore never meets an unknown kid after a single rotation. |
| A stable caller identity | `sub` is the service account's client id, fixed for the account's lifetime. |
| Something to run in CI | `TestIdp` (Maven Central: `com.codeheadsystems:mini-idp-testkit`): the real issuer in-process, with service accounts added from the test (no mini-directory needed). |

The token is a compact JWS with header `{"alg":"ES256","typ":"JWT","kid":"..."}` and claims
`iss`, `sub`, `aud` (a single string), `iat`, `nbf`, `exp` (default TTL 300 s), `jti`, plus mini-idp's
`grants` claim (ignore it if you don't use it).

## Step 1: choose the audience and the algorithm

Pick one audience string per relying party, normally its own name (`config-server`). Tokens for one
audience are refused by a verifier expecting another, so a caller of both mini-kms and config-server
asks for two tokens.

Check which algorithms your verifier accepts. config-server accepts RS/PS/ES 256/384/512 and **not
EdDSA**, so its audience is mapped to ES256. If your stack accepts EdDSA (Ed25519), you can leave the
audience unmapped and skip the mapping below.

## Step 2: configure mini-idp (production)

```bash
export MINIIDP_ADMIN_TOKEN="$(openssl rand -hex 32)"
# --issuer: the exact URL the relying party will trust
# --audience-algorithm: repeatable; or MINIIDP_AUDIENCE_ALGORITHMS=config-server=ES256
services/mini-idp/server/build/install/server/bin/server \
  --issuer https://idp.example \
  --audience-algorithm config-server=ES256 \
  --directory-url http://127.0.0.1:8466 \
  --data-dir ~/.mini-idp
```

- `--issuer` must be exactly what the relying party is configured with, character for character
  (scheme, host, port, no trailing slash). It becomes `iss` and the base of `jwks_uri`. Most verifiers
  require `https` except on loopback; put mini-idp behind a TLS reverse proxy and set `--issuer` to
  the public `https` URL.
- Mapping an audience to ES256 creates a second key set, `signing-keys-es256.json`, with the same
  `0600` / mini-kms wrapping (`--kms-*`) as the Ed25519 keys. With no ES256 mapping, mini-idp publishes
  only Ed25519 keys and discovery lists only `EdDSA`.

## Step 3: allowlist the audience for each calling service account

In mini-directory, add a `token:audience` grant whose resource is the audience:

```bash
curl -s -X POST http://127.0.0.1:8466/admin/service-accounts \
  -H "Authorization: Bearer $MINIDIR_ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"id":"billing","grants":[{"action":"token:audience","resource":"config-server"}]}'
# -> { "id": "billing", "secret": "...", ... }   (the secret is shown once)
```

A wildcard resource (`*`) is not honored; each audience is named explicitly. These grants are read
only as the allowlist and never appear in the `grants` claim.

## Step 4: configure the relying party

For config-server, add mini-idp as a trusted issuer:

| config-server setting | Value |
| --- | --- |
| issuer | mini-idp's `--issuer`, exactly (e.g. `https://idp.example`) |
| audience | `config-server` |
| subjects to authorize | client ids of the calling service accounts (e.g. `billing`) |

config-server finds the keys through discovery, so there is no JWKS URL to configure. For another
verifier, the equivalent settings are usually: issuer (or discovery URL), expected audience,
allowed algorithms (`ES256`), and a JWKS cache that refetches on an unknown `kid`. Authorize on the
pair **(issuer, sub)**, not on `sub` alone, if you trust more than one issuer.

## Step 5: callers get a token

```bash
TOKEN=$(curl -fsS https://idp.example/oauth/token \
  -d grant_type=client_credentials -d client_id=billing -d client_secret="$BILLING_SECRET" \
  -d resource=config-server | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -H "Authorization: Bearer $TOKEN" https://config.example/...
```

HTTP Basic client authentication works too. Cache the token until shortly before `expires_in` runs
out rather than fetching one per request.

## Step 6: test it in the relying party's CI

Use **`TestIdp`** from the `mini-idp-testkit` artifact on Maven Central. It starts the real mini-idp
server inside the test's JVM on an ephemeral loopback port, with an in-memory service-account
directory (no mini-directory) and a throwaway data directory. Tokens come from the real
`/oauth/token` endpoint over HTTP, so a test exercises exactly what a deployed issuer does.

**Coordinates:** `com.codeheadsystems:mini-idp-testkit:<version>`. It pulls in, at runtime only,
`mini-idp-server`, `mini-idp-core`, `mini-token`, `mini-kms-client`, `mini-kms-core` and
`mini-policy` (same group, same version), plus Jackson and Bouncy Castle. Its public API uses only
JDK types, so none of them is on your compile classpath. It needs Java 21 or later.

```kotlin
// Gradle
dependencies {
    testImplementation("com.codeheadsystems:mini-idp-testkit:0.1.0")
}
```

```xml
<!-- Maven -->
<dependency>
  <groupId>com.codeheadsystems</groupId>
  <artifactId>mini-idp-testkit</artifactId>
  <version>0.1.0</version>
  <scope>test</scope>
</dependency>
```

The examples use `0.1.0`; substitute the version you pin. No version has been released yet. Until
one is, try a local build: `./gradlew -Pversion=0.1.0 nmcpZipAggregation` in mini-auth, unzip
`build/nmcp/zip/aggregation.zip` into a directory, and add that directory as a `maven` repository
ahead of Maven Central (see `RELEASING.md`, "Checking locally").

```java
try (TestIdp idp = TestIdp.builder().audienceAlgorithm("config-server", "ES256").start()) {
  idp.addServiceAccount("billing", "s3cret", "config-server");     // works after start, too
  String token = idp.token("billing", "s3cret", "config-server");  // ES256, aud=config-server, sub=billing
  String issuer = idp.issuer();                                    // http://127.0.0.1:<port>
  // configure the relying party: trusted issuer = issuer, audience = "config-server"
  Map<String, String> kids = idp.rotateKeys();                     // {EdDSA=..., ES256=...}
}
```

The issuer is derived from the bound port, so discovery, `jwks_uri` and every token's `iss` name the
address the verifier actually fetches from; there is nothing to map. The API:

| Call | Does |
| --- | --- |
| `TestIdp.start()` | Defaults: audience `mini-kms`, EdDSA only. |
| `TestIdp.builder()` `.audienceAlgorithm(aud, "ES256")` `.defaultAudience(aud)` `.tokenTtlSeconds(n)` `.start()` | A customized issuer. |
| `addServiceAccount(clientId, secret, audiences...)` | Add or replace an account; `clientId` is the token's `sub`; `audiences` is its allowlist. |
| `token(clientId, secret[, audience])` | A token through the client-credentials grant (`resource=audience`). A refusal throws `IllegalStateException` carrying the OAuth error (`invalid_target`, `invalid_client`). |
| `rotateKeys()` | Rotate every key set; returns the new active kid per algorithm. |
| `issuer()`, `port()`, `defaultAudience()` | For configuring the verifier. |
| `close()` | Stop the server and delete its data directory. |

Start one `TestIdp` per test class (for example in `@BeforeAll`), and point the relying party's
trusted-issuer configuration at `idp.issuer()` before it starts. Inside mini-auth itself, depend on
it with `testImplementation(project(":services:mini-idp:testkit"))`.

### What the relying party's tests should cover

The same cases mini-idp's own
[`ConfigServerCompatibilityTest`](../../services/mini-idp/testkit/src/test/java/com/codeheadsystems/miniidp/testkit/ConfigServerCompatibilityTest.java)
checks with a verifier built the way config-server builds one:

1. A token for your audience is accepted, and `sub` is the client id.
2. A token for another audience (for example the default `mini-kms` one) is refused.
3. A client that is not allowlisted for your audience gets `400 invalid_target` from mini-idp.
4. After a rotation (`idp.rotateKeys()`), a new token (new `kid`) is accepted without a JWKS refetch,
   because that kid was pre-published, and a token issued before the rotation still verifies.
5. After two quick rotations, the new kid is unknown to the cached JWKS and is found by refetching it.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `invalid_target` from `/oauth/token` | The client is not allowlisted for that audience (`token:audience` grant, `audiences` in the seed, or the `audiences` of `TestIdp.addServiceAccount`), or `resource` and `audience` were both sent with different values. |
| `invalid_client` | Wrong client id or secret (deliberately one generic error). |
| Verifier: "issuer mismatch" or discovery names a different issuer | `--issuer` / `MINIIDP_ISSUER` differs from the relying party's configured issuer (trailing slash, or `127.0.0.1` vs `localhost`; with `TestIdp`, use `idp.issuer()` verbatim). |
| Verifier: "insecure jwks_uri" | The issuer is `http` on a non-loopback host. Use `https` via a reverse proxy. |
| Verifier: unsupported or unexpected algorithm | The token is EdDSA because its audience is not mapped. Add `--audience-algorithm <aud>=ES256` and restart. |
| Verifier: audience rejected | The client asked for no audience (got `mini-kms`) or a different one. Send `resource=<your audience>`. |
| Verifier: no key for `kid` right after a rotation | Two rotations happened within the verifier's cache period (the second activates a key published after the cache was filled) and its refetch is rate-limited, or it does not refetch on an unknown `kid` at all. Space rotations out by more than the verifier's JWKS cache lifetime. |
