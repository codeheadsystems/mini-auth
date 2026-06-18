/*
 * core - the IDP-specific file persistence.
 *
 * Deliberately free of any HTTP/transport/CLI code (mirrors mini-kms's I/O-free `core`). The token
 * plane was extracted into `:libs:mini-token`, and the client registry + Argon2 client-secret
 * hashing moved to mini-directory (the single source of service-account identity). What remains here
 * is the atomic 0600 JSON file store (`JsonStore`), which implements mini-token's DocumentStore SPI
 * and backs the signing-key / revocation / audit documents the server wires.
 */

plugins {
    id("miniauth.library-conventions")
}

// Unique jar name so this `core` and mini-kms's `core` (both `core.jar` by default) can coexist in
// one service distribution — mini-idp:server now bundles mini-kms:core for the KMS key wrapping.
base { archivesName = "mini-idp-core" }

dependencies {
    // The shared token plane: the DocumentStore SPI JsonStore implements, plus the token types.
    // `api` so the server module sees mini-token's types transitively, as it did when they lived here.
    api(project(":libs:mini-token"))
    // JSON for the persisted documents.
    api(libs.jackson.databind)
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}
