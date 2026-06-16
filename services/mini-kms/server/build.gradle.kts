/*
 * server - the socket daemon.
 *
 * Binds a loopback-only TCP socket and a Unix domain socket, speaks the
 * newline-delimited JSON protocol, authenticates with a shared API token,
 * and delegates all crypto to core. Has a runnable main entry point.
 */

plugins {
    id("miniauth.application-conventions")
}

dependencies {
    implementation(project(":services:mini-kms:core"))

    testImplementation(project(":services:mini-kms:core"))
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}

application {
    mainClass = "com.codeheadsystems.minikms.server.ServerMain"
}
