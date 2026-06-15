/*
 * mini-policy - the generalized authorization decision function.
 *
 * A small, dependency-light library that answers one question for every service in the family:
 * may THIS principal perform THIS action on THIS resource? It is the generalization of
 * mini-kms's `KeyAuthorizationPolicy` (which answers it only for `KeyOperation` against a key
 * group) and of the per-group grant checks a verifier runs over a mini-idp token.
 *
 * Library only — no transport, no HTTP, no CLI. This is a SCAFFOLD: it ships the decision
 * types, the engine seam, and a SAFE deny-by-default engine. Real rule evaluation (roles,
 * grant mappings from mini-directory, scope checks) is TODO.
 */

plugins {
    `java-library`
}

dependencies {
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
