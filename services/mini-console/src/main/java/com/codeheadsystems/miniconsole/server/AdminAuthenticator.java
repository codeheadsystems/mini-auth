package com.codeheadsystems.miniconsole.server;

import com.codeheadsystems.miniconsole.server.http.ApiException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Guards the console with a single bootstrap console credential (a token), validated in constant
 * time.
 *
 * <p>This mirrors the family's {@code AdminAuthenticator}: the expected token is resolved once at
 * startup from an env var or a file (never a CLI flag, never logged), and presented tokens are
 * compared with {@link MessageDigest#isEqual} so a match can't be recovered byte-by-byte via timing.
 *
 * <p>The console is a human-in-a-browser tool, so the token is presented by being <b>pasted into the
 * login form</b> rather than sent as a {@code Authorization: Bearer} header — {@link #matches} is the
 * form-login path. {@link #requireAdmin} is kept for any future header-guarded endpoint. After a
 * successful paste the console mints a {@code SessionService} session, and the session cookie (not
 * the token) authorizes subsequent requests.
 */
public final class AdminAuthenticator {

  private final byte[] expectedToken;

  /**
   * @param expectedToken the console token a login must present; must be non-empty.
   */
  public AdminAuthenticator(final String expectedToken) {
    if (expectedToken == null || expectedToken.isEmpty()) {
      throw new IllegalArgumentException("console token must not be empty");
    }
    this.expectedToken = expectedToken.getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Constant-time compare a presented token (e.g. pasted into the login form) against the expected
   * console token.
   *
   * @param presented the token the operator supplied (may be null/blank).
   * @return true iff it matches the expected token.
   */
  public boolean matches(final String presented) {
    if (presented == null || presented.isEmpty()) {
      // Constant-time-ish: still touch the expected buffer so a missing token is not faster.
      MessageDigest.isEqual(expectedToken, new byte[expectedToken.length]);
      return false;
    }
    return MessageDigest.isEqual(expectedToken, presented.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Require a valid console bearer token on the request, or throw 401. Unused by Slice 0's
   * form-login flow, but kept so a future header-guarded endpoint follows the family pattern.
   *
   * @param authorizationHeader the raw {@code Authorization} header value (may be null).
   * @throws ApiException 401 if the header is missing, malformed, or the token does not match.
   */
  public void requireAdmin(final String authorizationHeader) {
    if (!matches(bearerToken(authorizationHeader))) {
      throw ApiException.unauthorized();
    }
  }

  private static String bearerToken(final String authorizationHeader) {
    if (authorizationHeader == null) {
      return null;
    }
    final String prefix = "Bearer ";
    if (authorizationHeader.length() <= prefix.length()
        || !authorizationHeader.regionMatches(true, 0, prefix, 0, prefix.length())) {
      return null;
    }
    final String token = authorizationHeader.substring(prefix.length()).trim();
    return token.isEmpty() ? null : token;
  }
}
