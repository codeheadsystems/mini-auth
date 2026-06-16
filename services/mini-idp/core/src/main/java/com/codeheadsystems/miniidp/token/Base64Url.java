package com.codeheadsystems.miniidp.token;

import java.util.Base64;

/**
 * base64url (RFC 4648 §5) without padding — the encoding JOSE uses for every segment of a
 * compact JWS and for the {@code x} coordinate in a JWK.
 *
 * <p>We hand-roll this (rather than pull in a JOSE library) the same way mini-kms hand-rolls its
 * envelope encodings: a JWS is just {@code base64url(header) "." base64url(payload) "."
 * base64url(signature)}, and the only fiddly part is using the URL-safe alphabet and stripping
 * the {@code =} padding. Keeping it explicit makes the token format auditable end to end.
 */
public final class Base64Url {

  private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

  private Base64Url() {
  }

  /** Encode bytes to an unpadded base64url string. */
  public static String encode(final byte[] bytes) {
    return ENCODER.encodeToString(bytes);
  }

  /** Decode an unpadded (or padded) base64url string to bytes. */
  public static byte[] decode(final String text) {
    return DECODER.decode(text);
  }
}
