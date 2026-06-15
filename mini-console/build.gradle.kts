/*
 * mini-console - unified admin UI (ROADMAP PLACEHOLDER).
 *
 * Reserved for an optional single admin UI over the family: inspect mini-directory identities,
 * rotate mini-token signing keys, review audit logs, manage mini-kms key groups. There is NO
 * logic here yet — this module only claims the name and package. See docs/DIRECTION.md.
 *
 * A plain library (no `application` plugin) precisely because there is nothing to run.
 */

plugins {
    `java-library`
}

dependencies {
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
