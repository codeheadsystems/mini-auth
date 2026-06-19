/*
 * mini-gateway-client - a thin client for mini-gateway's forward-auth endpoint.
 *
 * The fifth (and last) of the family's HTTP client libraries (Slice 7 of mini-console). Unlike the
 * other clients it holds NO downstream admin token: mini-gateway's `/verify` is called the way a
 * reverse proxy calls it — carrying the *client's own* credentials (a bearer access token or the
 * shared SSO session cookie) in the request, not an operator credential — and `/health` is public.
 *
 * It is also the family's deliberate exception to the no-oracle status collapse: the whole job of
 * `/verify` is to answer a reverse proxy with DISTINCT statuses (200 / 302 / 401 / 403), so this
 * client MAPS those statuses to a `VerifyOutcome` rather than collapsing them. No response BODY is
 * ever read, so there is still no body oracle. `health()` uses mini-client-common's normal collapse.
 *
 * Library only — no transport of its own beyond the shared HTTP client.
 */

plugins {
    id("miniauth.library-conventions")
}

dependencies {
    // The shared transport + error model. `api` because ClientException is part of this client's
    // surface (consumers catch it) and consumers construct clients via the static factory.
    api(project(":libs:mini-client-common"))
    // The copied wire records (HealthStatus) are Jackson-bound.
    implementation(libs.jackson.databind)

    // The strongest behavior proof: boot the REAL mini-gateway in-test and drive every /verify
    // branch (allow / 401 / 403 / 302) over HTTP, minting bearer tokens through mini-token.
    testImplementation(project(":services:mini-gateway"))
    testImplementation(project(":libs:mini-token"))
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}
