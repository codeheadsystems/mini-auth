/*
 * mini-oidc-client - a thin client for mini-oidc (the human SSO / OpenID Provider).
 *
 * Speaks mini-oidc's public OIDC surface (discovery, JWKS, token, userinfo) and its admin surface
 * (client registration, signing-key rotation) over mini-client-common's no-oracle HTTP transport.
 * Reuses mini-token's JwkSet so a verifier can feed the JWKS straight into mini-token's verifier.
 *
 * A LIBRARY (no transport of its own beyond the shared HTTP client). Consumed by mini-console.
 */

plugins {
    id("miniauth.library-conventions")
}

dependencies {
    // The shared HTTP/JSON/token plumbing (no-oracle collapse). `api` so callers can catch
    // ClientException without an extra dependency.
    api(project(":libs:mini-client-common"))
    // Reuse mini-token's published JWKS model (so the OIDC id_token verifies against it directly).
    api(project(":libs:mini-token"))
    // Jackson for the copied wire DTOs.
    implementation(libs.jackson.databind)

    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
    // The integration test boots a REAL mini-oidc.
    testImplementation(project(":services:mini-oidc"))
}
