/*
 * Aggregator build for mini-auth — the umbrella for the "mini-" family of small,
 * single-responsibility auth/identity services and libraries.
 *
 * This is a single MONOREPO build. mini-kms and mini-idp now live HERE, as nested module
 * groups, so one `./gradlew build` compiles and tests the whole family. (Earlier this was a
 * Gradle composite that `includeBuild`-referenced the sibling repos; the source was pulled in
 * and the family standardized on one toolchain + Jackson 3.x — see docs/DIRECTION.md.)
 *
 * The Gradle project paths:
 *
 *   Existing services, vendored in (base packages com.codeheadsystems.minikms / .miniidp):
 *     :mini-kms:core / :mini-kms:server / :mini-kms:client
 *     :mini-idp:core / :mini-idp:server
 *
 *   New shared libraries (java-library):
 *     :mini-token      token plane (JWS/JWKS/rotation/revocation/audit) shared by oidc + idp
 *     :mini-policy     generalized principal/resource/action -> allow/deny decision function
 *
 *   New deployable services (application):
 *     :mini-oidc       human SSO / OpenID Provider (auth-code + PKCE); embeds pk-auth passkeys
 *     :mini-gateway    forward-auth endpoint for a reverse proxy (Traefik/Caddy/nginx)
 *     :mini-directory  identity source of truth: users, groups, roles, service accounts, grants
 *
 *   Roadmap placeholders (no logic yet — scaffold only):
 *     :mini-ca         internal CA for mTLS / workload identity
 *     :mini-console    optional unified admin UI
 *
 * `include("mini-kms:core")` maps to the directory mini-kms/core relative to this root, and
 * auto-creates the (empty) parent project :mini-kms. Leaf names may repeat across groups
 * (:mini-kms:core and :mini-idp:core) — Gradle keys on the full path, so that is fine.
 */

plugins {
    // Apply the foojay-resolver plugin to allow automatic download of JDKs (matches the siblings).
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "mini-auth"

// --- Existing services, vendored in as nested modules ----------------------------------
include("mini-kms:core")
include("mini-kms:server")
include("mini-kms:client")
include("mini-idp:core")
include("mini-idp:server")

// --- New shared libraries --------------------------------------------------------------
include("mini-token")
include("mini-policy")

// --- New deployable services -----------------------------------------------------------
include("mini-oidc")
include("mini-gateway")
include("mini-directory")

// --- Roadmap placeholders (documented now; no real logic) ------------------------------
include("mini-ca")
include("mini-console")
