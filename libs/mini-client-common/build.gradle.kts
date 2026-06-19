/*
 * mini-client-common - shared plumbing for the family's HTTP client libraries.
 *
 * The client-side counterpart to the (still-deferred) server-side `mini-common`: the bits every
 * `libs/<svc>-client` needs and would otherwise copy — a shared immutable Jackson mapper, an
 * env/file token resolver, a loopback-friendly `HttpTransport` over `java.net.http.HttpClient`, and
 * the single generic `ClientException` (the no-oracle error collapse). It depends on nothing in the
 * family — only the Jackson catalog.
 *
 * Introduced in Slice 1 of mini-console, DRIVEN BY its first real consumer (mini-directory-client) —
 * not landed speculatively. See docs/design/mini-console.md.
 *
 * Library only — no transport of its own, no HTTP server, no CLI.
 */

plugins {
    id("miniauth.library-conventions")
}

dependencies {
    // The shared JsonMapper (de)serializes responses; Jackson is an internal detail (no Jackson
    // type appears in this module's public API), so it stays `implementation`.
    implementation(libs.jackson.databind)
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}
