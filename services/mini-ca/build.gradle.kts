/*
 * mini-ca - internal certificate authority (ROADMAP PLACEHOLDER).
 *
 * Reserved for a small internal CA: issuing short-lived certificates for mTLS between the minis
 * and for workload identity in the homelab. There is NO logic here yet — this module exists only
 * to claim the name, reserve the package, and keep the umbrella build aware of it. See the
 * roadmap in docs/DIRECTION.md.
 *
 * A plain library (no `application` plugin) precisely because there is nothing to run.
 */

plugins {
    id("miniauth.library-conventions")
}

dependencies {
    // JUnit 5 (jupiter + launcher) is supplied by the convention plugin.
}
