/*
 * Conventions for a shared LIBRARY module: mini-token, mini-policy, mini-client-common, the five
 * per-service client libs (mini-directory/idp/oidc/ca/gateway-client), and the I/O-free cores.
 *
 * Just the shared Java conventions plus java-library (so the module can expose an api classpath).
 * No transport, no main entry point. (Runnable services, including mini-ca and mini-console, use
 * the application-conventions plugin instead.)
 */

plugins {
    id("miniauth.java-conventions")
    `java-library`
}
