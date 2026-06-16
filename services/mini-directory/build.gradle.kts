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
    id("miniauth.application-conventions")
}

dependencies {
    implementation(project(":libs:mini-policy"))
    implementation(libs.jackson.databind)
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}

application {
    mainClass = "com.codeheadsystems.minidirectory.ServerMain"
}
