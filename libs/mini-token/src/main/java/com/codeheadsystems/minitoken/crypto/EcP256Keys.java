package com.codeheadsystems.minitoken.crypto;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * EC P-256 ({@code secp256r1}) key generation and (de)serialization for ES256, using only the JDK.
 *
 * <p>Same at-rest encodings as {@link Ed25519Keys} — PKCS#8 for the private key, X.509 SPKI for the
 * public key, both base64 — so an ES256 key fits the existing {@code SigningKeyRecord} unchanged and
 * is wrapped under mini-kms exactly like an Ed25519 one.
 *
 * <p><b>JWK coordinates.</b> An EC JWK (RFC 7518 §6.2.1) carries the public point as {@code x} and
 * {@code y}: each the big-endian, <em>fixed-width</em> 32-byte encoding of the coordinate. Java's
 * {@link BigInteger#toByteArray()} is minimal two's-complement, so it can be 33 bytes (a leading
 * sign byte) or shorter than 32 (leading zeros dropped); {@link #coordinate} normalizes to exactly
 * 32. Getting this wrong fails roughly 1 key in 128, which is why it is spelled out here.
 */
public final class EcP256Keys {

  /** JCA key algorithm. */
  public static final String ALGORITHM = "EC";

  /** The standard name of the P-256 curve. */
  public static final String CURVE = "secp256r1";

  /** Byte length of one P-256 field element (a JWK coordinate). */
  public static final int COORDINATE_BYTES = 32;

  private EcP256Keys() {
  }

  /** Generate a fresh P-256 key pair. */
  public static KeyPair generate() {
    try {
      final KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
      generator.initialize(new ECGenParameterSpec(CURVE));
      return generator.generateKeyPair();
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("EC P-256 not available in this JDK", e);
    }
  }

  /** Reload a private key from its base64 PKCS#8 encoding. */
  public static PrivateKey decodePrivate(final String base64Pkcs8) {
    try {
      final byte[] der = Base64.getDecoder().decode(base64Pkcs8);
      return KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(der));
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("failed to decode EC private key", e);
    }
  }

  /** Reload a public key from its base64 X.509 encoding. */
  public static PublicKey decodePublic(final String base64Spki) {
    try {
      final byte[] der = Base64.getDecoder().decode(base64Spki);
      return KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(der));
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("failed to decode EC public key", e);
    }
  }

  /** @return the 32-byte big-endian {@code x} coordinate of a P-256 public key. */
  public static byte[] x(final PublicKey publicKey) {
    return coordinate(((ECPublicKey) publicKey).getW().getAffineX());
  }

  /** @return the 32-byte big-endian {@code y} coordinate of a P-256 public key. */
  public static byte[] y(final PublicKey publicKey) {
    return coordinate(((ECPublicKey) publicKey).getW().getAffineY());
  }

  /**
   * Rebuild a P-256 public key from its JWK coordinates (used by verifiers/tests).
   *
   * @param x the 32-byte {@code x} coordinate.
   * @param y the 32-byte {@code y} coordinate.
   * @return the public key.
   */
  public static PublicKey fromCoordinates(final byte[] x, final byte[] y) {
    try {
      final AlgorithmParameters params = AlgorithmParameters.getInstance(ALGORITHM);
      params.init(new ECGenParameterSpec(CURVE));
      final ECParameterSpec spec = params.getParameterSpec(ECParameterSpec.class);
      final ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
      return KeyFactory.getInstance(ALGORITHM).generatePublic(new ECPublicKeySpec(point, spec));
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("invalid EC P-256 public key", e);
    }
  }

  /** Encode a coordinate as exactly {@value #COORDINATE_BYTES} big-endian bytes. */
  static byte[] coordinate(final BigInteger value) {
    final byte[] minimal = value.toByteArray();
    if (minimal.length == COORDINATE_BYTES) {
      return minimal;
    }
    if (minimal.length > COORDINATE_BYTES) {
      // Only a leading 0x00 sign byte may be dropped; anything longer is not a P-256 coordinate.
      if (minimal.length != COORDINATE_BYTES + 1 || minimal[0] != 0) {
        throw new IllegalStateException("not a P-256 coordinate");
      }
      return Arrays.copyOfRange(minimal, 1, minimal.length);
    }
    final byte[] padded = new byte[COORDINATE_BYTES];
    System.arraycopy(minimal, 0, padded, COORDINATE_BYTES - minimal.length, minimal.length);
    return padded;
  }
}
