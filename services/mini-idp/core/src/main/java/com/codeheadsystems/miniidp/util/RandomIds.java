package com.codeheadsystems.miniidp.util;

import com.codeheadsystems.miniidp.token.Base64Url;
import java.security.SecureRandom;

/**
 * Generates unguessable identifiers and secrets from a {@link SecureRandom}.
 *
 * <p>Client ids, client secrets, signing-key ids ({@code kid}), and token ids ({@code jti}) are
 * all high-entropy random strings — never sequential or derived from caller input — so they can't
 * be guessed or enumerated. We render them base64url so they are safe in URLs, headers, and JSON.
 */
public final class RandomIds {

  private final SecureRandom secureRandom = new SecureRandom();

  /** A short id (96 bits) for a client, prefixed for readability. */
  public String newClientId() {
    return "client_" + randomBase64Url(12);
  }

  /** A 256-bit client secret. This is the only time the raw secret exists; it is shown once. */
  public char[] newClientSecret() {
    return randomBase64Url(32).toCharArray();
  }

  /** A short signing-key id (64 bits). */
  public String newKid() {
    return "k_" + randomBase64Url(8);
  }

  /** A unique token id (128 bits) for the {@code jti} claim. */
  public String newJti() {
    return randomBase64Url(16);
  }

  private String randomBase64Url(final int byteCount) {
    final byte[] bytes = new byte[byteCount];
    secureRandom.nextBytes(bytes);
    return Base64Url.encode(bytes);
  }
}
