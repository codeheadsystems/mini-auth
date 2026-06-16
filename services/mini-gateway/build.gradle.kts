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
    id("miniauth.application-conventions")
}

dependencies {
    implementation(project(":libs:mini-token"))
    implementation(project(":libs:mini-policy"))
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}

application {
    mainClass = "com.codeheadsystems.minigateway.ServerMain"
}
