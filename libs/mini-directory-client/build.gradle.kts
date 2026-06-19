/*
 * mini-directory-client - a thin, read-capable client for mini-directory's admin/resolution API.
 *
 * The first of the family's HTTP client libraries (Slice 1 of mini-console). It speaks the directory's
 * REST surface over `mini-client-common`'s HttpTransport and exposes the read methods a console needs:
 * list principals/groups/roles, read one principal, and resolve a principal to its expanded grants.
 * Mutations are added in a later slice.
 *
 * It copies the handful of wire records it needs into its own `…client.model` package rather than
 * depending on `:services:mini-directory` (an application module) — the same "deliberate copy until
 * a shared model exists" stance the family takes elsewhere, and it keeps the dependency one-way and
 * acyclic (a lib never depends on a service front door).
 *
 * Library only — no transport of its own.
 */

plugins {
    id("miniauth.library-conventions")
}

dependencies {
    // The shared transport + error model. `api` because ClientException is part of this client's
    // surface (consumers catch it) and consumers construct clients via the static factory.
    api(project(":libs:mini-client-common"))
    // The copied wire records are Jackson-bound (annotations + (de)serialization).
    implementation(libs.jackson.databind)

    // The strongest behavior proof: boot the REAL mini-directory in-test and read it back.
    testImplementation(project(":services:mini-directory"))
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}
