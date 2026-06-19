package com.codeheadsystems.miniconsole.server;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Minimal stateless CSRF protection using the <b>double-submit cookie</b> pattern.
 *
 * <p>On a form render the console mints a random token, sets it in a short-lived HttpOnly
 * {@code mini-console-csrf} cookie ({@link Cookies#csrf}) and embeds the same value in a hidden form
 * field. On the matching POST the handler requires the cookie value and the form field to be equal
 * (compared in constant time). Because a cross-site attacker can neither read nor set the cookie for
 * the console's origin, they cannot forge a request whose field matches the cookie.
 *
 * <p>Stateless (no server-side store) is sufficient and simplest for a loopback admin tool; a
 * server-side pending-token store would be the heavier alternative. Slice 0 protects exactly the
 * {@code /login} and {@code /logout} POSTs; the same helper carries forward to Slice 2's mutations.
 */
public final class Csrf {

  private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

  private final SecureRandom secureRandom = new SecureRandom();

  /** @return a fresh 256-bit base64url CSRF token. */
  public String mint() {
    final byte[] bytes = new byte[32];
    secureRandom.nextBytes(bytes);
    return BASE64URL.encodeToString(bytes);
  }

  /**
   * Constant-time equality of the cookie value and the submitted form field.
   *
   * @param expected  the value from the {@code mini-console-csrf} cookie (may be null).
   * @param presented the value from the hidden form field (may be null).
   * @return true iff both are present and equal.
   */
  public boolean verify(final String expected, final String presented) {
    if (expected == null || expected.isEmpty() || presented == null || presented.isEmpty()) {
      return false;
    }
    return MessageDigest.isEqual(
        expected.getBytes(StandardCharsets.UTF_8), presented.getBytes(StandardCharsets.UTF_8));
  }
}
