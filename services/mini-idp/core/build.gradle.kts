/*
 * core - the IDP-specific identity model, client-secret hashing, and file persistence.
 *
 * Deliberately free of any HTTP/transport/CLI code so it stays reusable and testable in
 * isolation (mirrors mini-kms's I/O-free `core`). The token plane — Ed25519 keys, JWS/JWT, JWKS,
 * the `grants` claim contract, signing-key rotation, revocation, and audit — was EXTRACTED into
 * `:libs:mini-token`; this core now owns only what is IDP-specific:
 *   - the client registry model (ClientRecord) and ClientService;
 *   - Argon2id client-secret hashing + constant-time verification;
 *   - the atomic 0600 JSON file store (JsonStore), which implements mini-token's DocumentStore SPI.
 */

plugins {
    id("miniauth.library-conventions")
}

// Unique jar name so this `core` and mini-kms's `core` (both `core.jar` by default) can coexist in
// one service distribution — mini-idp:server now bundles mini-kms:core for the KMS key wrapping.
base { archivesName = "mini-idp-core" }

dependencies {
    // The shared token plane (JWS/JWKS/rotation/revocation/audit + the auth model and store SPI).
    // `api` so the server module sees mini-token's types transitively, as it did when they lived here.
    api(project(":libs:mini-token"))
    // Argon2id KDF for client-secret hashing.
    api(libs.bouncycastle)
    // JSON for claims, stores, and DTOs.
    api(libs.jackson.databind)
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}
