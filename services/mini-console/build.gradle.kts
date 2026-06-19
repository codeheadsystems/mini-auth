/*
 * mini-console - the optional unified admin console over the mini- family.
 *
 * Slice 0: the runnable skeleton — a loopback HTTP server, a console-login session, and a Dashboard
 * that honestly reports "client not wired yet" for each downstream service (no client libs exist
 * yet). It invents NO new authority; later slices add the per-service client libraries + pages.
 *
 * Graduates from library-conventions to application-conventions (it is now runnable).
 */

plugins {
    id("miniauth.application-conventions")
}

dependencies {
    // The shared browser-session mechanism (SessionService) + the DocumentStore SPI the copied
    // JsonStore implements. This is the ONLY family dependency Slice 0 genuinely needs.
    implementation(project(":libs:mini-token"))
    // JSON for the session store document (Sessions) and the /health body.
    implementation(libs.jackson.databind)
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}

application {
    mainClass = "com.codeheadsystems.miniconsole.ServerMain"
}
