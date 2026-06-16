/*
 * Builds the family's convention plugins as precompiled Kotlin-DSL script plugins.
 * The kotlin-dsl plugin compiles every src/main/kotlin convention script into a plugin
 * whose id is the file name minus its .gradle.kts suffix (miniauth.java-conventions, etc.).
 *
 * (Avoid backticks in this header: Gradle's lightweight prescan of the plugins block can be
 * derailed by backtick-quoted text in a comment that precedes it.)
 */

plugins {
    `kotlin-dsl`
}

repositories {
    gradlePluginPortal()
    mavenCentral()
}
