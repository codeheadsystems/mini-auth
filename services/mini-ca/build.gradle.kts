/*
 * mini-ca - a small internal certificate authority for the homelab.
 *
 * Issues and renews short-lived X.509 certificates for mTLS between the minis and for homelab
 * services, keeps an issuance log + a revocation list, and protects its own CA private key by
 * wrapping it under mini-kms (the recursive integration from the KMS-backed key store) — or
 * plaintext-at-0600 by default, so the educational path runs without mini-kms.
 *
 * Educational, NOT a full PKI (see README for scope + non-goals): one self-signed root, no
 * intermediates, a JSON revocation list rather than a signed DER CRL, loopback + admin-token guarded.
 */

plugins {
    id("miniauth.application-conventions")
}

dependencies {
    // The mini-kms client + KmsSigningKeyStore: wrap the CA key under mini-kms (Prompt 6's store).
    implementation(project(":services:mini-kms:client"))
    // SigningKeys/DocumentStore (the CA key is persisted as a one-record SigningKeys document).
    implementation(project(":libs:mini-token"))
    // BouncyCastle: the crypto provider plus the PKIX cert/CSR builders.
    implementation(libs.bouncycastle)
    implementation(libs.bouncycastle.pkix)
    // JSON for the stores, DTOs, and the served OpenAPI spec.
    implementation(libs.jackson.databind)
    implementation(libs.jackson.yaml)

    // Boot a real mini-kms in the KMS-backed CA-key test.
    testImplementation(project(":services:mini-kms:server"))
    testImplementation(project(":services:mini-kms:core"))
    testImplementation(project(":libs:mini-policy"))
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}

application {
    mainClass = "com.codeheadsystems.minica.ServerMain"
}
