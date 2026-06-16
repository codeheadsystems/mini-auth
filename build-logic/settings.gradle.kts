/*
 * Settings for the `build-logic` included build.
 *
 * `build-logic` is a tiny, self-contained Gradle build whose only job is to host the family's
 * shared convention plugins (see src/main/kotlin/miniauth.*-conventions.gradle.kts). The root
 * build pulls it in via `pluginManagement { includeBuild("build-logic") }` so every module can
 * apply those plugins by id. Keeping the conventions here (rather than in the root build's
 * `subprojects {}` block) means each module opts in explicitly and the empty grouping projects
 * (:services, :libs) stay inert.
 *
 * The convention plugins read the shared version catalog (gradle/libs.versions.toml) at the point
 * they are APPLIED, off the consuming module via VersionCatalogsExtension — so no catalog wiring
 * is needed here.
 */

dependencyResolutionManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

rootProject.name = "build-logic"
