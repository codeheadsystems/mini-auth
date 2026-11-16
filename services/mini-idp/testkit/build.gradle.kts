/*
 * testkit - an embeddable mini-idp for other projects' tests.
 *
 * TestIdp starts the real mini-idp server in-process on an ephemeral loopback port, with an
 * in-memory service-account directory (no mini-directory) and a temp data dir, derives the issuer
 * from the bound port, and offers addServiceAccount / token / rotateKeys. It also holds the
 * config-server compatibility test (Nimbus JOSE+JWT, test scope only).
 */

plugins {
    id("miniauth.library-conventions")
}

// Unique jar name: three modules in the family are leaf-named after their role.
base { archivesName = "mini-idp-testkit" }

dependencies {
    implementation(project(":services:mini-idp:server"))
    implementation(project(":services:mini-idp:core"))
    implementation(libs.jackson.databind)

    // The compatibility test verifies tokens the way config-server does (Nimbus), and the default
    // EdDSA path with mini-token's own verifier.
    testImplementation(libs.nimbus.jose.jwt)
    testImplementation(project(":libs:mini-token"))
    testImplementation(libs.jackson.databind)
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}
