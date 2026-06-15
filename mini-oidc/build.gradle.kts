/*
 * mini-oidc - human SSO / OpenID Provider (SCAFFOLD).
 *
 * The human-facing front door of the family: authorization-code + PKCE, ID + access tokens,
 * browser SSO sessions, and a login/consent UI. Where mini-idp authenticates MACHINES
 * (client-credentials), mini-oidc authenticates PEOPLE.
 *
 * Composition, not reinvention:
 *   - pk-auth-core (Maven Central, NOT vendored) provides the passkeys-first credential layer
 *     the login/registration ceremonies are built on.
 *   - mini-token will mint the ID/access tokens and publish the JWKS (shared with mini-idp).
 *   - mini-policy evaluates consent/scope authorization decisions.
 *
 * This module is a scaffold: a runnable entry point and a health check, with the real OIDC
 * protocol and crypto left as clearly-marked TODOs. No half-built auth.
 */

plugins {
    application
}

dependencies {
    // The passkey credential layer (external dependency, consumed from Maven Central).
    implementation(libs.pk.auth.core)
    // Shared family libraries.
    implementation(project(":mini-token"))
    implementation(project(":mini-policy"))

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    mainClass = "com.codeheadsystems.minioidc.ServerMain"
}
