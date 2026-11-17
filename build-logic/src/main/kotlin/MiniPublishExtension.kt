import org.gradle.api.provider.Property

/**
 * Per-module settings for miniauth.publish-conventions.
 *
 * artifactId is required and must be unique across the build. It is set explicitly, never derived
 * from the Gradle project name: the leaf names repeat (services:mini-idp:core and
 * services:mini-kms:core are both "core"), and the Maven artifactId defaults to the project name,
 * not to base.archivesName, so two modules would otherwise publish the same coordinates.
 */
abstract class MiniPublishExtension {
    /** The Maven artifactId, e.g. "mini-idp-server". Also used as the jar's base name. */
    abstract val artifactId: Property<String>
}
