/*
 * mini-gateway - forward-auth endpoint for a reverse proxy (SCAFFOLD).
 *
 * A tiny service a reverse proxy calls before forwarding a request: Traefik ForwardAuth,
 * Caddy forward_auth, or nginx auth_request all hit a single endpoint that returns 2xx (allow)
 * or 401/403 (deny). It lets you put authentication in front of apps that have none of their own.
 *
 * Composition: it verifies the caller's token via mini-token and makes the allow/deny call via
 * mini-policy. This module is a scaffold: a runnable entry point and a health check; the actual
 * forward-auth HTTP endpoint and verification are clearly-marked TODOs.
 */

plugins {
    application
}

dependencies {
    implementation(project(":mini-token"))
    implementation(project(":mini-policy"))

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    mainClass = "com.codeheadsystems.minigateway.ServerMain"
}
