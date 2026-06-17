package com.codeheadsystems.minitoken.session;

/**
 * A browser SSO session: the record that a particular browser has an authenticated human behind it.
 *
 * <p>This is the <b>shared</b> session record for the family — mini-oidc creates these on login, and
 * any forward-auth gateway validates them — so there is one session mechanism, not two. The id the
 * browser holds (in a cookie) is never stored in the clear; only its SHA-256 hash is kept, so a dump
 * of the session store cannot be replayed as a live cookie. The lifetime is deliberately independent
 * of any token TTL: it governs how long the human stays signed in, not how long a token is valid.
 *
 * @param idHash    SHA-256 (base64url) of the cookie's session id — the lookup key.
 * @param subject   the authenticated principal id.
 * @param authTime  when the human authenticated (epoch seconds).
 * @param expiresAt session expiry (epoch seconds).
 */
public record BrowserSession(String idHash, String subject, long authTime, long expiresAt) {
}
