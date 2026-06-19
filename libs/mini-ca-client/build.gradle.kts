/*
 * mini-ca-client - a thin client for mini-ca's certificate authority API.
 *
 * The fourth of the family's HTTP client libraries (Slice 5 of mini-console). It speaks two surfaces:
 * the PUBLIC trust-anchor / revocation / health endpoints (no bearer) and the ADMIN issuance / renewal
 * / revocation / log endpoints (admin bearer), so it holds two `mini-client-common` transports.
 *
 * Certificates and CSRs cross the wire as PEM text (public material — no secret concerns); the only
 * secret the client holds is the CA admin token, which is never logged. The trust anchor endpoint
 * (`GET /ca`) returns PEM rather than JSON, read via `HttpTransport.getText`.
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
    // The copied wire records are Jackson-bound.
    implementation(libs.jackson.databind)
    // Generating a PKCS#10 CSR (the Csr helper) needs BouncyCastle's PKCS10 builder; the JDK has no
    // CSR API. A CA client producing CSRs is a natural client concern, and keeping it here lets both
    // the console's certificate-lifecycle exercise and this lib's test reuse one generator (and the
    // console's chain validation can then stay pure-JDK).
    implementation(libs.bouncycastle)
    implementation(libs.bouncycastle.pkix)

    // The strongest behavior proof: boot the REAL mini-ca in-test (plaintext-key mode) and drive a
    // full issue/renew/revoke lifecycle over HTTP.
    testImplementation(project(":services:mini-ca"))
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}
