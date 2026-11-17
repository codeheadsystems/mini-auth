/*
 * Maven Central publication for one module, adapted from the config project's
 * buildlogic.publish-conventions (which follows hofmann-elimination).
 *
 * Applied per module, on top of library- or application-conventions: publishing is a decision
 * about an artifact, not a property of being in this build. A module that applies it must set
 *
 *     miniPublish { artifactId = "mini-idp-server" }
 *
 * which also becomes the jar's base name. The upload itself is owned by the nmcp settings plugin
 * (root settings.gradle.kts), which aggregates every publishing module into ONE Central Portal
 * deployment. The groupId (mavenGroup) and version are shared: gradle.properties, or a vX.Y.Z tag
 * on HEAD for the version. The Gradle project group is left alone; see gradle.properties.
 *
 * (No backticks in this header: Gradle's prescan of the plugins block can trip over them.)
 */
plugins {
    java
    `maven-publish`
    signing
}

val miniPublish = extensions.create<MiniPublishExtension>("miniPublish")
val mavenGroup = providers.gradleProperty("mavenGroup").get()

// Unique jar names too (services:mini-idp:core and services:mini-kms:core would both be core.jar).
base.archivesName.set(miniPublish.artifactId.orElse(project.name))

// Maven Central requires a sources jar and a javadoc jar next to every main jar.
java {
    withSourcesJar()
    withJavadocJar()
}

tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).apply {
        encoding = "UTF-8"
        // The family's comments are written for readers of the source, not as a javadoc site:
        // keep the HTML/reference checks, skip "missing comment" warnings.
        addStringOption("Xdoclint:all,-missing", "-quiet")
    }
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            groupId = mavenGroup
            version = project.version.toString()

            pom {
                // Providers: the module's miniPublish and description lines run after this applies.
                name.set(miniPublish.artifactId)
                description.set(provider {
                    project.description ?: "Part of mini-auth, a small educational auth/identity family"
                })
                url.set("https://github.com/codeheadsystems/mini-auth")

                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }

                developers {
                    developer {
                        id.set("wolpert")
                        name.set("Ned Wolpert")
                        email.set("ned.wolpert@gmail.com")
                    }
                }

                scm {
                    connection.set("scm:git:git://github.com/codeheadsystems/mini-auth.git")
                    developerConnection.set("scm:git:ssh://git@github.com:codeheadsystems/mini-auth.git")
                    url.set("https://github.com/codeheadsystems/mini-auth")
                }
            }
        }
    }
    // No repositories block: nmcp owns the upload to the Central Portal.
}

val publication = publishing.publications.named<MavenPublication>("mavenJava")

// MavenPublication.artifactId is a plain String, so it is copied once the build script has run.
afterEvaluate {
    check(miniPublish.artifactId.isPresent) {
        "${project.path} applies miniauth.publish-conventions but sets no miniPublish.artifactId"
    }
    publication.configure { artifactId = miniPublish.artifactId.get() }
}

signing {
    // Required only for a real (non-SNAPSHOT) release on a machine that has a key.
    val credentialsPresent = project.hasProperty("signing.gnupg.keyName")
        || System.getenv("GPG_KEY_ID") != null
    isRequired = credentialsPresent && !version.toString().endsWith("SNAPSHOT")
    useGpgCmd()
    sign(publishing.publications["mavenJava"])
}

// isRequired=false still runs gpg with useGpgCmd(); skip the task so keyless local publishes work.
tasks.withType<Sign>().configureEach {
    val required = signing.isRequired
    onlyIf { required }
}

tasks.register("verifyPublishConfig") {
    val coordinates = miniPublish.artifactId.map { "$mavenGroup:$it:${project.version}" }
    val snapshot = project.version.toString().endsWith("SNAPSHOT")
    val signed = signing.isRequired
    doLast {
        println("${coordinates.get()}  snapshot=$snapshot signed=$signed")
    }
}
