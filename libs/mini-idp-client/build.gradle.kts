/*
 * mini-idp-client - a thin client for mini-idp's OAuth token endpoint, JWKS, discovery, and audit log.
 *
 * The second of the family's HTTP client libraries (Slice 3 of mini-console). It speaks two surfaces:
 * the PUBLIC OAuth/discovery/JWKS endpoints (no bearer) and the ADMIN audit endpoint (admin bearer),
 * so it holds two `mini-client-common` transports internally.
 *
 * It REUSES mini-token's published models rather than copying them: `JwkSet`/`Jwk` (the JWKS shape)
 * and `AuditEntry` (the audit record) are mini-token types the idp serializes from, so a console can
 * feed the JWKS straight into mini-token's `TokenVerifier`. Only the idp-specific wire records that
 * do NOT live in mini-token (`TokenResponse`, `DiscoveryDocument`, `HealthStatus`) are in this lib's
 * `…client.model` package.
 *
 * Library only — no transport of its own.
 */

plugins {
    id("miniauth.library-conventions")
}

dependencies {
    // The shared transport + error model. `api` because ClientException is part of this client's
    // surface (consumers catch it) and consumers construct clients via the static factory.
    api(project(":libs:mini-client-common"))
    // mini-token's JWKS + audit models are part of this client's surface (returned to callers), so
    // expose them transitively: a consumer that calls jwks()/audit() needs these types.
    api(project(":libs:mini-token"))
    // The copied idp-specific wire records are Jackson-bound.
    implementation(libs.jackson.databind)

    // The strongest behavior proof: boot the REAL mini-idp in-test (with an in-memory service-account
    // source) and read its token/jwks/audit/health back over HTTP.
    testImplementation(project(":services:mini-idp:server"))
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}
