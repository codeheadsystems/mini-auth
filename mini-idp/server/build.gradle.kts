/*
 * server - the HTTP daemon.
 *
 * Binds a loopback-only HTTP server (com.sun.net.httpserver.HttpServer), exposes the OAuth
 * client-credentials token endpoint, the JWKS + discovery documents, the admin API, and serves
 * the OpenAPI spec + bundled Swagger UI. Delegates all crypto/identity logic to core. Runnable.
 */

plugins {
    application
}

dependencies {
    implementation(project(":mini-idp:core"))
    implementation(libs.jackson.databind)
    // Used to parse the checked-in openapi.yaml so /openapi.json can be served from the same source.
    implementation(libs.jackson.yaml)

    testImplementation(project(":mini-idp:core"))
    testImplementation(libs.jackson.databind)
    testImplementation(libs.jackson.yaml)
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    mainClass = "com.codeheadsystems.miniidp.server.ServerMain"
}
