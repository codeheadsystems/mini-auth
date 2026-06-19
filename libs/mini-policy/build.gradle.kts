/*
 * mini-policy - the generalized authorization decision function.
 *
 * A small, dependency-light library that answers one question for every service in the family:
 * may THIS principal perform THIS action on THIS resource? It generalizes mini-kms's former
 * per-key-group key-authorization policy (which answered it only for `KeyOperation` against a key
 * group) and the per-group grant checks a verifier runs over a mini-idp token.
 *
 * Library only — no transport, no HTTP, no CLI. It ships the decision types (Principal, Action,
 * Resource, Grant, Decision), the PolicyEngine seam, and three engines: a SAFE deny-by-default,
 * an allow-all (the documented test/seam), and the grant-based engine consumed in production by
 * mini-directory, mini-oidc, mini-gateway, and mini-kms. It is deliberately minimal — it evaluates
 * the grants it is given. Sourcing those grants family-wide (mini-directory resolution feeding the
 * issuers; the token -> mini-kms authorization path) is integration work that lives in those
 * services, tracked in docs/DIRECTION.md — not a gap in this library.
 */

plugins {
    id("miniauth.library-conventions")
}

dependencies {
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}
