/*
 * Conventions for a shared LIBRARY module (mini-token, mini-policy, the I/O-free cores, and the
 * roadmap placeholders mini-ca / mini-console that have nothing to run yet).
 *
 * Just the shared Java conventions plus java-library (so the module can expose an api classpath).
 * No transport, no main entry point.
 */

plugins {
    id("miniauth.java-conventions")
    `java-library`
}
