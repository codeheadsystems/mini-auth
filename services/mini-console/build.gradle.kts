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
    // Slice 4: reuse the existing mini-kms socket client (KmsClient) for the Keys page's key-group
    // control plane — the documented socket-era exception, NOT relocated (see docs/DIRECTION.md). Its
    // dep on mini-kms:core is `implementation`, so we declare core directly for the KeyGroupView DTO.
    implementation(project(":services:mini-kms:client"))
    implementation(project(":services:mini-kms:core"))
    // Slice 5: the mini-ca client (issue/renew/revoke/log + the Csr generator) for the Certificates
    // page and the certificate-lifecycle exercise. Brings mini-client-common transitively. CSR
    // generation lives in the client lib, so the console's chain validation stays pure-JDK (no
    // BouncyCastle dependency here).
    implementation(project(":libs:mini-ca-client"))
    // Slice 6: the mini-oidc client (discovery/JWKS/token/userinfo + client registration + key
    // rotation) for the Clients page and the OIDC code+PKCE exercise. Brings mini-token + the PKCE
    // helper + JwsClaimsVerifier (for offline id_token verification) transitively.
    implementation(project(":libs:mini-oidc-client"))
    // Slice 7: the mini-gateway client (forward-auth /verify + health) for the gateway exercise. It
    // holds no downstream token (/verify carries the caller's own credentials, /health is public) and
    // brings mini-client-common transitively.
    implementation(project(":libs:mini-gateway-client"))
    // JSON for the session store document (Sessions), the /health body, and the /api JSON surface.
    implementation(libs.jackson.databind)
    // Slice 8: the /api OpenAPI spec is parsed from its YAML resource and re-emitted as JSON.
    implementation(libs.jackson.yaml)

    // The certificate-lifecycle exercise test boots a REAL mini-ca (plaintext-key mode) and proves the
    // flow issues a leaf that genuinely chains to the CA root.
    testImplementation(project(":services:mini-ca"))
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}

application {
    mainClass = "com.codeheadsystems.miniconsole.ServerMain"
}
