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
