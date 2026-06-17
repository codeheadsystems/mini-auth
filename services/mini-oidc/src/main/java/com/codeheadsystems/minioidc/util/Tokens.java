package com.codeheadsystems.minioidc.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Secure-random identifier/secret generation and the one-way hashing used for at-rest values.
 *
 * <p>Authorization codes, session ids, CSRF tokens, request ids, and refresh-token secrets are all
 * high-entropy random strings rendered base64url so they are safe in URLs, headers, cookies, and
 * JSON. Refresh-token secrets and session ids are stored only as their SHA-256 hash, so a leak of
 * the at-rest store does not yield usable bearer values — mirroring the family's "never store a
 * recoverable secret" rule (here SHA-256 is adequate because the inputs are already 256-bit random,
 * unlike low-entropy passwords, which use Argon2id via {@code secret/Argon2SecretHasher}).
 */
public final class Tokens {

  private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();
  private final SecureRandom secureRandom = new SecureRandom();

  /** A short client id (96 bits), prefixed for readability. */
  public String newClientId() {
    return "client_" + random(12);
  }

  /** A 256-bit client secret for a confidential client (shown once, then Argon2id-hashed). */
  public char[] newClientSecret() {
    return random(32).toCharArray();
  }

  /** A 256-bit opaque authorization code. */
  public String newCode() {
    return random(32);
  }

  /** A 256-bit opaque browser-session id (stored hashed). */
  public String newSessionId() {
    return random(32);
  }

  /** A 256-bit CSRF token bound to a pending authorization. */
  public String newCsrfToken() {
    return random(32);
  }

  /** A 128-bit id for a pending authorization / login attempt. */
  public String newRequestId() {
    return random(16);
  }

  /** A 256-bit refresh-token secret (stored hashed; the wire value is {@code id.secret}). */
  public String newRefreshSecret() {
    return random(32);
  }

  /** A 128-bit refresh-token id (the family/rotation handle; stored in clear). */
  public String newRefreshId() {
    return random(16);
  }

  private String random(final int byteCount) {
    final byte[] bytes = new byte[byteCount];
    secureRandom.nextBytes(bytes);
    return BASE64URL.encodeToString(bytes);
  }

  /** @return the unpadded base64url SHA-256 of {@code value} (the at-rest form of a bearer value). */
  public static String sha256(final String value) {
    try {
      final byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(value.getBytes(StandardCharsets.UTF_8));
      return BASE64URL.encodeToString(digest);
    } catch (final NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  /** Constant-time comparison of two strings (for CSRF / opaque-token checks). */
  public static boolean constantTimeEquals(final String a, final String b) {
    if (a == null || b == null) {
      return false;
    }
    return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
  }
}
