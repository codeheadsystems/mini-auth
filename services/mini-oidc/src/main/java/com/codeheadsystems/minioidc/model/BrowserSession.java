package com.codeheadsystems.minioidc.model;

/**
 * A browser SSO session: the record that a particular browser has an authenticated human behind it,
 * so subsequent {@code /authorize} requests need no re-authentication until the session expires.
 *
 * <p>The session id the browser holds (in a secure, HttpOnly, SameSite cookie) is never stored in
 * the clear — only its SHA-256 hash is kept here, so a dump of the session store cannot be replayed
 * as a live cookie. The session lifetime is deliberately <b>independent of any token TTL</b>: tokens
 * are short-lived and refreshed, while the SSO session governs how long the human stays signed in to
 * the OP itself.
 *
 * @param idHash    SHA-256 of the cookie's session id (the lookup key).
 * @param subject   the authenticated principal id.
 * @param authTime  when the human authenticated (epoch seconds).
 * @param expiresAt session expiry (epoch seconds).
 */
public record BrowserSession(String idHash, String subject, long authTime, long expiresAt) {
}
