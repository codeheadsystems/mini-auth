/*
 * mini-console - the optional unified admin console over the mini- family.
 *
 * A loopback HTTP server with a console-login session and server-rendered admin pages. It invents NO
 * new authority — it is a client of admin surfaces that already exist. Slice 0 was the skeleton;
 * Slice 1 wires the first real client (mini-directory) and the read-only Identities pages. Each later
 * slice adds another per-service client library + its pages.
 *
 * Uses application-conventions (it is runnable).
 */

plugins {
    id("miniauth.application-conventions")
}

dependencies {
    // The shared browser-session mechanism (SessionService) + the DocumentStore SPI the copied
    // JsonStore implements.
    implementation(project(":libs:mini-token"))
    // The first downstream client: read mini-directory identities/groups/roles + resolution. Brings
    // mini-client-common (HttpTransport + ClientException) transitively on its `api` edge.
    implementation(project(":libs:mini-directory-client"))
    // Slice 3: the mini-idp client (token/JWKS/discovery/audit) for the Audit page and the exercise
    // harness. Brings mini-token (JwkSet/AuditEntry/TokenVerifier) transitively on its `api` edge.
    implementation(project(":libs:mini-idp-client"))
    // JSON for the session store document (Sessions) and the /health body.
    implementation(libs.jackson.databind)
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}

application {
    mainClass = "com.codeheadsystems.miniconsole.ServerMain"
}
