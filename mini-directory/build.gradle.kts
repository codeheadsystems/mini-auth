/*
 * mini-directory - the identity source of truth (SCAFFOLD).
 *
 * One place that owns users, groups, roles, and service accounts, plus their grant mappings.
 * mini-oidc (humans) and mini-idp (machines) READ identities and grants from here instead of
 * each keeping a private registry; mini-policy decisions are ultimately backed by the grants
 * stored here.
 *
 * Composition: it exposes the grant model that mini-policy evaluates and that the issuers read.
 * This module is a scaffold: a runnable entry point and a health check; the directory model and
 * storage are clearly-marked TODOs. Jackson is present because the eventual JSON stores mirror
 * the siblings' atomic-write JSON stores.
 */

plugins {
    application
}

dependencies {
    implementation(project(":mini-policy"))
    implementation(libs.jackson.databind)

    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    mainClass = "com.codeheadsystems.minidirectory.ServerMain"
}
