/*
 * core - the identity model, crypto, and token machinery.
 *
 * Deliberately free of any HTTP/transport/CLI code so it stays reusable and testable in
 * isolation (mirrors mini-kms's I/O-free `core`). It owns:
 *   - the authorization model (Principal, KeyOperation, Grant) that token claims map onto;
 *   - Argon2id client-secret hashing + constant-time verification;
 *   - Ed25519 signing keys, hand-rolled compact JWS/JWT issuance + verification, and JWKS;
 *   - the JSON file stores (atomic temp-file + ATOMIC_MOVE + 0600) and the services built on them.
 */

plugins {
    id("miniauth.library-conventions")
}

dependencies {
    // Argon2id KDF for client-secret hashing.
    api(libs.bouncycastle)
    // JSON for claims, stores, and DTOs.
    api(libs.jackson.databind)
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}
