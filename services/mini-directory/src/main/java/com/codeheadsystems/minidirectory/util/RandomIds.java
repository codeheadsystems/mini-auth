package com.codeheadsystems.minidirectory.util;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generates unguessable identifiers and secrets from a {@link SecureRandom}.
 *
 * <p>Mirrors the family's id generation (mini-idp / mini-token {@code RandomIds}): service-account
 * ids and their secrets are high-entropy random strings — never sequential or derived from caller
 * input — rendered base64url so they are safe in URLs, headers, and JSON. (Human ids are operator-
 * chosen, so they are not minted here.)
 */
public final class RandomIds {

  private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

  private final SecureRandom secureRandom = new SecureRandom();

  /** A short service-account id (96 bits), prefixed for readability. */
  public String newServiceAccountId() {
    return "svc_" + randomBase64Url(12);
  }

  /** A 256-bit service-account secret. This is the only time the raw secret exists; shown once. */
  public char[] newSecret() {
    return randomBase64Url(32).toCharArray();
  }

  private String randomBase64Url(final int byteCount) {
    final byte[] bytes = new byte[byteCount];
    secureRandom.nextBytes(bytes);
    return BASE64URL.encodeToString(bytes);
  }
}
