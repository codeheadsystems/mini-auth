/*
 * mini-oidc - human SSO / OpenID Provider.
 *
 * The human-facing front door of the family: authorization-code + PKCE, ID + access tokens, a
 * /userinfo endpoint, browser SSO sessions, refresh tokens, single logout, and a minimal
 * login/consent UI. Where mini-idp authenticates MACHINES (client-credentials), mini-oidc
 * authenticates PEOPLE.
 *
 * Composition, not reinvention:
 *   - pk-auth-core (Maven Central, NOT vendored) runs the WebAuthn passkey ceremony; pk-auth's
 *     alt-flow modules (backup-codes here; magic-link / otp share the same recovery seam) back
 *     account recovery.
 *   - mini-token mints the ID/access tokens and publishes the JWKS + signing-key rotation — the
 *     token plane is REUSED, never re-implemented here.
 *   - mini-policy authorizes the requested OIDC scopes against the user's grants.
 *   - the authenticated human is resolved to a Principal "via mini-directory" through a small
 *     UserDirectory SPI (an HTTP client to mini-directory's resolution endpoint in production).
 */

plugins {
    id("miniauth.application-conventions")
}

dependencies {
    // The passkey credential layer + a recovery alt-flow (external, from Maven Central).
    implementation(libs.pk.auth.core)
    implementation(libs.pk.auth.backup.codes)
    // Shared family libraries: the token plane and the decision function.
    implementation(project(":libs:mini-token"))
    implementation(project(":libs:mini-policy"))
    // The mini-kms client + KmsSigningKeyStore: optionally wrap signing keys under mini-kms.
    implementation(project(":services:mini-kms:client"))
    // Argon2id for confidential-client secret hashing (same pattern as the siblings).
    implementation(libs.bouncycastle)
    // JSON for tokens, stores, DTOs, and (de)serializing pk-auth's ceremony DTOs.
    implementation(libs.jackson.databind)
    // Parses the checked-in openapi.yaml so /openapi.json can be served from the same source.
    implementation(libs.jackson.yaml)

    // pk-auth's in-memory SPI implementations: they back the standalone server's passkey store
    // (the documented swap point for a persistent CredentialRepository/UserLookup/ChallengeStore),
    // and the test classpath also uses the testkit's FakeAuthenticator to drive a real WebAuthn
    // ceremony without a browser. pk-auth sanctions the testkit on the main classpath for this.
    implementation(libs.pk.auth.testkit)
    // Boot a real mini-kms in the KMS-backed signing-key test.
    testImplementation(project(":services:mini-kms:server"))
    testImplementation(project(":services:mini-kms:core"))
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}

application {
    mainClass = "com.codeheadsystems.minioidc.ServerMain"
}
