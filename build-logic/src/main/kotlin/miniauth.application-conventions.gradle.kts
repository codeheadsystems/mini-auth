/*
 * Conventions for a runnable SERVICE module (the mini-kms / mini-idp servers + clients, and the
 * mini-oidc / mini-gateway / mini-directory front doors).
 *
 * The shared Java conventions plus the application plugin (which provides installDist and the
 * launcher scripts). Each module still declares its own mainClass.
 */

plugins {
    id("miniauth.java-conventions")
    application
}
