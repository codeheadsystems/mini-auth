/*
 * mini-token - the shared TOKEN PLANE library.
 *
 * The home for the JWS/JWKS/signing-key-lifecycle/rotation/revocation/audit machinery EXTRACTED
 * from mini-idp (its `core/token`, `core/jwks`, `core/service`, `core/crypto`) so both issuers —
 * mini-idp (machine client-credentials) and the future mini-oidc (human SSO) — share one
 * implementation instead of two. It owns: the Ed25519 keys, the hand-rolled compact JWS/JWT, the
 * JWKS model, the published `grants` claim contract, the signing-key lifecycle + rotation, the
 * revocation denylist, the audit log, and a small persistence SPI (`store/DocumentStore`) the
 * consuming service backs however it likes.
 *
 * Library only — no transport, no HTTP, no CLI (mirrors the siblings' I/O-free `core`). Crypto is
 * the JDK's Ed25519 only (no third-party crypto dependency). Jackson is on the api classpath
 * because the JWKS/claim records (de)serialize through it, exactly as in mini-idp.
 */

plugins {
    id("miniauth.library-conventions")
}

dependencies {
    // The JWKS document and JWT claim records are Jackson-bound, like mini-idp's.
    api(libs.jackson.databind)
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}
