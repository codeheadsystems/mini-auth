/*
 * mini-directory - the identity source of truth.
 *
 * One place that owns humans, groups, roles, and service accounts, plus their grant mappings. Each
 * stored identity resolves to a mini-policy Principal with fully-expanded grants (roles and group
 * memberships expand to grants), so a directory record maps directly onto a mini-policy decision.
 *
 * It exposes a small loopback admin API following the family's conventions (admin bearer token,
 * atomic 0600 JSON store, no secrets in logs) and ships an OpenAPI spec + vendored Swagger UI like
 * mini-idp. mini-idp reads service accounts from here today (it has no local client registry —
 * every token request authenticates against this service); mini-oidc resolves humans from here
 * when started with --directory-url (optional, in-memory fallback otherwise).
 */

plugins {
    id("miniauth.application-conventions")
}

dependencies {
    // The shared decision model the directory resolves identities into (Principal / Grant / engine).
    implementation(project(":libs:mini-policy"))
    // Argon2id KDF for service-account secret hashing (same coordinate the siblings use).
    implementation(libs.bouncycastle)
    // JSON for the directory store and the admin DTOs.
    implementation(libs.jackson.databind)
    // Parses the checked-in openapi.yaml so /openapi.json can be served from the same source.
    implementation(libs.jackson.yaml)
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}

application {
    mainClass = "com.codeheadsystems.minidirectory.ServerMain"
}
