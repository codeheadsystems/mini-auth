/*
 * mini-gateway - forward-auth endpoint for a reverse proxy.
 *
 * A tiny service a reverse proxy calls before forwarding a request (Traefik ForwardAuth, Caddy
 * forward_auth, nginx auth_request): given the proxied request's headers/cookies it validates the
 * caller — the shared mini-oidc SSO session, or a bearer access token — evaluates the target route
 * through mini-policy, and answers 200 (+ identity headers) to allow, 401 / 403 to deny an API
 * caller, or 302-to-login to send an unauthenticated browser to mini-oidc. It puts authentication
 * in front of upstreams that have none of their own.
 *
 * Composition, not reinvention:
 *   - mini-token provides BOTH the shared SSO session store (so this and mini-oidc see the same
 *     sessions) and the JWS verification used for bearer tokens — no second session mechanism.
 *   - mini-policy makes the per-route allow/deny decision; the route rules are config-driven.
 */

plugins {
    id("miniauth.application-conventions")
}

dependencies {
    // The shared session store + JWS verification, and the per-route decision function.
    implementation(project(":libs:mini-token"))
    implementation(project(":libs:mini-policy"))
    // JSON for the routes config, the session store, and fetching/parsing the JWKS.
    implementation(libs.jackson.databind)
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}

application {
    mainClass = "com.codeheadsystems.minigateway.ServerMain"
}
