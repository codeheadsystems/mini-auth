/*
 * Root build for the mini-auth monorepo.
 *
 * Applies the shared Java conventions to EVERY module in the family — the vendored
 * mini-kms / mini-idp modules and the new mini-auth modules alike — identical to the
 * conventions the two minis used in their own root builds (Maven Central, a pinned Java 21
 * toolchain, JUnit 5, and the `-parameters` flag that Jackson record binding relies on).
 *
 * Because this is now a single build (not a composite), `./gradlew build` already runs every
 * subproject's `build`/`check`; no cross-build task wiring is needed.
 *
 * Jackson note: the whole family is on Jackson 3.x (tools.jackson.*), matching pk-auth's
 * transitive Jackson and standardizing the family on one major version. The `-parameters`
 * requirement is unchanged — Jackson still binds records by constructor parameter name.
 *
 * The `base` plugin gives the root project the standard lifecycle tasks (build/check/clean).
 */

plugins {
    base
}

subprojects {
    apply(plugin = "java")

    repositories {
        mavenCentral()
    }

    extensions.configure<JavaPluginExtension> {
        toolchain {
            languageVersion = JavaLanguageVersion.of(21)
        }
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
        testLogging {
            events("passed", "skipped", "failed")
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        // Required family-wide for the same reason the minis required it: Jackson binds records
        // (protocol/keystore/store/claim DTOs) by constructor parameter name.
        options.compilerArgs.add("-parameters")
    }
}
