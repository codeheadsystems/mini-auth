/*
 * Aggregator build for mini-auth — the umbrella for the "mini-" family of small,
 * single-responsibility auth/identity services and libraries.
 *
 * This is a single MONOREPO build. mini-kms and mini-idp now live HERE, as nested module
 * groups, so one `./gradlew build` compiles and tests the whole family. (Earlier these were two
 * independent Gradle builds with their own wrappers/settings; the sources were pulled in and the
 * family standardized on ONE wrapper, ONE version catalog, ONE set of convention plugins, and
 * Jackson 3.x — see docs/DIRECTION.md.)
 *
 * Layout — modules are grouped by ROLE, and the Gradle project path follows the directory:
 *
 *   services/  — deployable front doors (base packages com.codeheadsystems.mini<name>):
 *     :services:mini-kms:core / :services:mini-kms:server / :services:mini-kms:client
 *     :services:mini-idp:core / :services:mini-idp:server
 *     :services:mini-oidc       human SSO / OpenID Provider (auth-code + PKCE); embeds pk-auth
 *     :services:mini-gateway    forward-auth endpoint for a reverse proxy (Traefik/Caddy/nginx)
 *     :services:mini-directory  identity source of truth: users, groups, roles, service accounts
 *     :services:mini-ca         internal CA for mTLS / workload identity  (roadmap placeholder)
 *     :services:mini-console    optional unified admin UI                 (roadmap placeholder)
 *
 *   libs/      — shared libraries (no transport):
 *     :libs:mini-token   token plane (JWS/JWKS/rotation/revocation/audit) shared by oidc + idp
 *     :libs:mini-policy  generalized principal/resource/action -> allow/deny decision function
 *
 * `include("services:mini-kms:core")` maps to the directory services/mini-kms/core and
 * auto-creates the (empty, inert) grouping projects :services and :services:mini-kms. Leaf names
 * repeat across groups (:services:mini-kms:core and :services:mini-idp:core) — Gradle keys on the
 * full path, so that is fine.
 *
 * The shared Java conventions (JDK 21 toolchain, JUnit 5, `-parameters`) live in the `build-logic`
 * included build below and are applied per-module by id, instead of a root `subprojects {}` block.
 */

pluginManagement {
    // The family's convention plugins (miniauth.java-conventions, .library-conventions,
    // .application-conventions) are produced by this included build.
    includeBuild("build-logic")
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

plugins {
    // Apply the foojay-resolver plugin to allow automatic download of JDKs (matches the siblings).
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "mini-auth"

// --- Services (deployable front doors) -------------------------------------------------
include("services:mini-kms:core")
include("services:mini-kms:server")
include("services:mini-kms:client")
include("services:mini-idp:core")
include("services:mini-idp:server")
include("services:mini-oidc")
include("services:mini-gateway")
include("services:mini-directory")

// --- Services: roadmap placeholders (documented now; no real logic) --------------------
include("services:mini-ca")
include("services:mini-console")

// --- Libraries (shared, no transport) --------------------------------------------------
include("libs:mini-token")
include("libs:mini-policy")
