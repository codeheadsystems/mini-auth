package com.codeheadsystems.minioidc.client;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Client-side PKCE (RFC 7636) helper for the authorization-code flow. Generates a high-entropy
 * {@code code_verifier} and the matching {@code S256} {@code code_challenge}
 * ({@code base64url(SHA-256(verifier))}) — the only method mini-oidc accepts.
 *
 * <p>The verifier is the secret bound to the code; the challenge is sent at {@code /authorize} and the
 * verifier at {@code /token}. Keep the verifier private until the exchange.
 */
public final class Pkce {

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Base64.Encoder URL = Base64.getUrlEncoder().withoutPadding();

  private Pkce() {
  }

  /**
   * @return a fresh verifier/challenge pair (32 bytes of entropy, S256 challenge).
   */
  public static Pair generate() {
    final byte[] entropy = new byte[32];
    RANDOM.nextBytes(entropy);
    final String verifier = URL.encodeToString(entropy);
    return new Pair(verifier, challenge(verifier));
  }

  /**
   * @param verifier the {@code code_verifier}.
   * @return the {@code S256} challenge for {@code verifier}.
   */
  public static String challenge(final String verifier) {
    try {
      final byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(verifier.getBytes(StandardCharsets.US_ASCII));
      return URL.encodeToString(digest);
    } catch (final NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  /**
   * A PKCE verifier/challenge pair.
   *
   * @param verifier  the secret {@code code_verifier} (sent at {@code /token}).
   * @param challenge the {@code S256} {@code code_challenge} (sent at {@code /authorize}).
   */
  public record Pair(String verifier, String challenge) {
  }
}
