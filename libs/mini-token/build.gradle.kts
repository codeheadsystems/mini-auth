/*
 * mini-token - the shared TOKEN PLANE library.
 *
 * The home for the JWS/JWKS/signing-key-lifecycle/rotation/revocation/audit machinery that
 * mini-idp already implements by hand and that mini-oidc needs too. The intent is to EXTRACT
 * that machinery here (out of mini-idp's `core/token`, `core/jwks`, `core/service`) so both
 * issuers share one audited implementation instead of two.
 *
 * Library only — no transport, no HTTP, no CLI (mirrors the siblings' I/O-free `core`).
 * This is a SCAFFOLD: it defines the seams (interfaces + value types) and is deliberately
 * free of real crypto. See the TODOs in the sources. Jackson is on the api classpath because
 * the eventual JWKS/claim DTOs will (de)serialize through it, exactly as in mini-idp.
 */

plugins {
    id("miniauth.library-conventions")
}

dependencies {
    // The JWKS document and JWT claim records will be Jackson-bound, like mini-idp's.
    api(libs.jackson.databind)
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}
