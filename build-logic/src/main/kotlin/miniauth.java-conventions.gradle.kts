/*
 * Shared Java conventions for EVERY module in the mini-auth family (the vendored mini-kms /
 * mini-idp modules and the new modules alike). This is the single home for what used to live in
 * the root build's subprojects block:
 *
 *   - a pinned JDK 21 toolchain (foojay can auto-download it; configured in the root settings),
 *   - Maven Central,
 *   - JUnit 5 as the test platform + the common test stack (jupiter + launcher),
 *   - the -parameters compiler flag that Jackson record binding relies on family-wide.
 *
 * Library and application modules layer their plugin (java-library / application) on top via
 * miniauth.library-conventions / miniauth.application-conventions.
 *
 * NOTE on "lint": the family deliberately ships NO separate linter/formatter -- the command
 * gradlew build is the full gate (see the root CLAUDE.md / docs/DIRECTION.md). This is the seam
 * where a Spotless/Checkstyle convention would be added if that ever changes; it is intentionally
 * left out so the green build is not gated on un-formatted pre-existing code.
 */

import org.gradle.api.artifacts.VersionCatalogsExtension

plugins {
    java
}

repositories {
    mavenCentral()
}

java {
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
    // Required family-wide: Jackson binds records (protocol/keystore/store/claim DTOs) by
    // constructor parameter name, which only survives compilation with -parameters.
    options.compilerArgs.add("-parameters")
}

// The common test stack, pinned through the shared version catalog. Read the catalog off the
// project being configured (it is registered by the root build's settings from
// gradle/libs.versions.toml) rather than via a generated accessor, which precompiled script
// plugins do not expose.
val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")
dependencies {
    "testImplementation"(libs.findLibrary("junit-jupiter").get())
    "testRuntimeOnly"("org.junit.platform:junit-platform-launcher")
}
