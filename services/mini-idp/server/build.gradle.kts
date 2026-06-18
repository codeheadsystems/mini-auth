/*
 * server - the HTTP daemon.
 *
 * Binds a loopback-only HTTP server (com.sun.net.httpserver.HttpServer), exposes the OAuth
 * client-credentials token endpoint, the JWKS + discovery documents, the admin API, and serves
 * the OpenAPI spec + bundled Swagger UI. Delegates all crypto/identity logic to core. Runnable.
 */

plugins {
    id("miniauth.application-conventions")
}

dependencies {
    implementation(project(":services:mini-idp:core"))
    // The mini-kms client + KmsSigningKeyStore: optionally wrap signing keys under mini-kms.
    implementation(project(":services:mini-kms:client"))
    implementation(libs.jackson.databind)
    // Used to parse the checked-in openapi.yaml so /openapi.json can be served from the same source.
    implementation(libs.jackson.yaml)

    testImplementation(project(":services:mini-idp:core"))
    testImplementation(project(":services:mini-kms:client"))
    testImplementation(project(":services:mini-kms:server"))
    testImplementation(project(":services:mini-kms:core"))
    testImplementation(project(":libs:mini-policy"))
    testImplementation(libs.jackson.databind)
    testImplementation(libs.jackson.yaml)
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}

application {
    mainClass = "com.codeheadsystems.miniidp.server.ServerMain"
}
