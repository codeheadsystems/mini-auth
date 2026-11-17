/*
 * Root build for the mini-auth monorepo.
 *
 * The shared Java conventions (Maven Central, a pinned Java 21 toolchain, JUnit 5, the common
 * test stack, and the `-parameters` flag that Jackson record binding relies on) no longer live
 * here in a `subprojects {}` block — they are convention plugins in the `build-logic` included
 * build (miniauth.java-conventions / .library-conventions / .application-conventions), applied
 * per-module by id. This keeps the empty grouping projects (:services, :libs) inert and makes
 * each module's contract (library vs. application) explicit in its own build file.
 *
 * Because this is a single build (not a composite), `./gradlew build` already runs every
 * subproject's `build`/`check`; no cross-build task wiring is needed.
 *
 * Jackson note: the whole family is on Jackson 3.x (tools.jackson.*), matching pk-auth's
 * transitive Jackson and standardizing the family on one major version.
 *
 * The `base` plugin gives the root project the standard lifecycle tasks (build/check/clean).
 */

plugins {
    base
}

// Maven Central aggregation (the nmcp settings plugin applies it here; see settings.gradle.kts and
// RELEASING.md). Leaf project names repeat (core, server, client), which nmcp refuses by default
// because projects with the same Gradle group AND name collide in dependency resolution. That
// cannot happen here: projects keep their default, path-derived groups (see gradle.properties), and
// every publication has an explicit, unique artifactId (miniPublish).
// nmcp resolves its task runtime (com.gradleup.nmcp:nmcp-tasks) from the root project.
repositories {
    mavenCentral()
}

extensions.configure<nmcp.NmcpAggregationExtension> {
    allowDuplicateProjectNames.set(true)
}
