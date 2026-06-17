package com.codeheadsystems.minioidc.server;

import com.codeheadsystems.minioidc.server.http.ApiException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Guards the admin API with a single bootstrap admin credential (a bearer token), validated in
 * constant time.
 *
 * <p>This mirrors mini-kms's {@code ApiTokenAuthenticator}: the expected token is resolved once at
 * startup from an env var or a file (never a CLI flag, never logged), and presented tokens are
 * compared with {@link MessageDigest#isEqual} so a match can't be recovered byte-by-byte via
 * timing. The admin presents it as {@code Authorization: Bearer <token>}.
 *
 * <p>It is the bootstrap credential that lets an operator register OIDC relying-party clients before
 * any exist; it guards only the {@code /admin/**} API, never the browser SSO flows.
 */
public final class AdminAuthenticator {

  private final byte[] expectedToken;

  /**
   * @param expectedToken the admin token every admin request must present; must be non-empty.
   */
  public AdminAuthenticator(final String expectedToken) {
    if (expectedToken == null || expectedToken.isEmpty()) {
      throw new IllegalArgumentException("admin token must not be empty");
    }
    this.expectedToken = expectedToken.getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Require a valid admin bearer token on the request, or throw 401.
   *
   * @param authorizationHeader the raw {@code Authorization} header value (may be null).
   * @throws ApiException 401 if the header is missing, malformed, or the token does not match.
   */
  public void requireAdmin(final String authorizationHeader) {
    if (!isValid(authorizationHeader)) {
      throw ApiException.unauthorized();
    }
  }

  private boolean isValid(final String authorizationHeader) {
    final String presented = bearerToken(authorizationHeader);
    if (presented == null) {
      // Constant-time-ish: still touch the expected buffer so a missing header is not faster.
      MessageDigest.isEqual(expectedToken, new byte[expectedToken.length]);
      return false;
    }
    return MessageDigest.isEqual(expectedToken, presented.getBytes(StandardCharsets.UTF_8));
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
