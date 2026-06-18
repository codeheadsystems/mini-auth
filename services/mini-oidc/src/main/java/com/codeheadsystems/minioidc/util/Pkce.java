package com.codeheadsystems.minioidc.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * PKCE (RFC 7636) code-challenge verification — the defense that binds an authorization code to the
 * client instance that started the flow, so a stolen code is useless without the matching verifier.
 *
 * <p>At {@code /authorize} the client sends a {@code code_challenge} (and method). At {@code /token}
 * it sends the {@code code_verifier}; this recomputes the challenge from the verifier and compares
 * in constant time. mini-oidc requires PKCE with {@code S256} ({@code base64url(SHA-256(verifier))})
 * for every authorization-code request (public and confidential clients alike). The legacy {@code
 * plain} method is deliberately NOT accepted: with {@code plain} the challenge equals the verifier,
 * so anyone who can observe the authorization request can satisfy PKCE — it gives no protection
 * against code interception, the very threat PKCE exists for (OAuth 2.1 / current BCP require S256).
 */
public final class Pkce {

  /** The SHA-256 challenge method (RFC 7636 §4.2) — the only method mini-oidc accepts. */
  public static final String METHOD_S256 = "S256";

  private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

  private Pkce() {
  }

  /** @return whether {@code method} is one mini-oidc accepts (only {@code S256}). */
  public static boolean isSupportedMethod(final String method) {
    return METHOD_S256.equals(method);
  }

  /**
   * Verify a presented {@code code_verifier} against the stored {@code code_challenge}.
   *
   * @param method    the challenge method recorded at {@code /authorize} (must be {@code S256}).
   * @param challenge the stored {@code code_challenge}.
   * @param verifier  the {@code code_verifier} presented at {@code /token}.
   * @return whether the verifier satisfies the challenge (constant-time comparison).
   */
  public static boolean verify(final String method, final String challenge, final String verifier) {
    // Fail closed on anything but S256 — never fall back to comparing the verifier verbatim (the
    // `plain` behavior), which would silently defeat PKCE.
    if (challenge == null || verifier == null || !METHOD_S256.equals(method)) {
      return false;
    }
    final String computed = s256(verifier);
    return MessageDigest.isEqual(
        challenge.getBytes(StandardCharsets.US_ASCII), computed.getBytes(StandardCharsets.US_ASCII));
  }

  private static String s256(final String verifier) {
    try {
      final byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(verifier.getBytes(StandardCharsets.US_ASCII));
      return BASE64URL.encodeToString(digest);
    } catch (final NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }
}
