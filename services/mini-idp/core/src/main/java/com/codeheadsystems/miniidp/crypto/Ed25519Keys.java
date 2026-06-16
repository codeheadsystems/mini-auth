package com.codeheadsystems.miniidp.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Ed25519 key generation and (de)serialization, using only the JDK's built-in provider.
 *
 * <p>Ed25519 (EdDSA over Curve25519) is the signature algorithm for our tokens: small keys,
 * small signatures, fast verification, and no parameter choices to get wrong. The JDK has had
 * first-class support since 15 ({@code KeyPairGenerator}/{@code Signature} algorithm
 * {@code "Ed25519"}), so we need no third-party crypto for signing.
 *
 * <h2>On-disk / on-the-wire encodings</h2>
 * <ul>
 *   <li><b>Private key</b> — stored as its standard PKCS#8 DER ({@code PrivateKey.getEncoded()}),
 *       base64. Reloaded via {@link PKCS8EncodedKeySpec}. The file holding it is 0600.</li>
 *   <li><b>Public key</b> — stored as its X.509 {@code SubjectPublicKeyInfo} DER, base64, and
 *       reloaded via {@link X509EncodedKeySpec}.</li>
 *   <li><b>Raw public key</b> — JWK needs the bare 32-byte Ed25519 public key (the {@code x}
 *       parameter). For Ed25519 the SPKI structure is a fixed 12-byte prefix followed by exactly
 *       those 32 bytes, so {@link #rawPublicKey} simply takes the trailing 32 bytes. This avoids
 *       reaching into the JDK's {@code EdECPoint} representation (little-endian y plus a sign bit),
 *       which is more error-prone to assemble by hand.</li>
 * </ul>
 */
public final class Ed25519Keys {

  /** JCA algorithm name for Ed25519 (RFC 8032 / JDK 15+). */
  public static final String ALGORITHM = "Ed25519";

  /** Length of a raw Ed25519 public key in bytes. */
  public static final int RAW_PUBLIC_KEY_BYTES = 32;

  private Ed25519Keys() {
  }

  /** Generate a fresh Ed25519 key pair. */
  public static KeyPair generate() {
    try {
      return KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair();
    } catch (final GeneralSecurityException e) {
      // Ed25519 is mandated in the JDK from 15 onward; absence is a broken runtime, not a
      // recoverable condition.
      throw new IllegalStateException("Ed25519 not available in this JDK", e);
    }
  }

  /** @return the PKCS#8-encoded private key, base64. */
  public static String encodePrivate(final PrivateKey privateKey) {
    return Base64.getEncoder().encodeToString(privateKey.getEncoded());
  }

  /** @return the X.509 (SubjectPublicKeyInfo) encoded public key, base64. */
  public static String encodePublic(final PublicKey publicKey) {
    return Base64.getEncoder().encodeToString(publicKey.getEncoded());
  }

  /** Reload a private key from its base64 PKCS#8 encoding. */
  public static PrivateKey decodePrivate(final String base64Pkcs8) {
    try {
      final byte[] der = Base64.getDecoder().decode(base64Pkcs8);
      return KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(der));
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("failed to decode Ed25519 private key", e);
    }
  }

  /** Reload a public key from its base64 X.509 encoding. */
  public static PublicKey decodePublic(final String base64Spki) {
    try {
      final byte[] der = Base64.getDecoder().decode(base64Spki);
      return KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(der));
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("failed to decode Ed25519 public key", e);
    }
  }

  /**
   * Extract the bare 32-byte Ed25519 public key (the JWK {@code x} parameter) from a public key.
   *
   * <p>The SPKI DER for an Ed25519 key is always {@code 12 prefix bytes + 32 key bytes}, so the
   * raw key is the trailing 32 bytes of {@code getEncoded()}.
   */
  public static byte[] rawPublicKey(final PublicKey publicKey) {
    final byte[] spki = publicKey.getEncoded();
    if (spki.length < RAW_PUBLIC_KEY_BYTES) {
      throw new IllegalStateException("unexpected Ed25519 SPKI length: " + spki.length);
    }
    return Arrays.copyOfRange(spki, spki.length - RAW_PUBLIC_KEY_BYTES, spki.length);
  }
}
