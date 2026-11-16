package com.codeheadsystems.minitoken.crypto;

import com.codeheadsystems.minitoken.jwks.Jwk;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Locale;

/**
 * The JWS signature algorithms the token plane can sign with, and everything that differs between
 * them: how a key pair is generated and (de)serialized, the JCA {@code Signature} name, and the JWK
 * that publishes the public half.
 *
 * <ul>
 *   <li>{@link #EDDSA} — Ed25519 (RFC 8037). <b>The family default</b>: every issuer signs with it
 *       unless told otherwise, and mini-token's own verifiers accept only it.</li>
 *   <li>{@link #ES256} — ECDSA on P-256 with SHA-256 (RFC 7518 §3.4). Added for relying parties whose
 *       JOSE stack does not accept EdDSA (config-server). mini-idp signs with it only for the
 *       audiences an operator maps to it.</li>
 * </ul>
 *
 * <p><b>The ES256 signature format.</b> JWS wants the raw, fixed-width {@code R || S} (64 bytes for
 * P-256), not the ASN.1 DER {@code SEQUENCE { INTEGER r, INTEGER s }} that the JDK's
 * {@code SHA256withECDSA} produces. The JDK ships the JWS form as {@code SHA256withECDSAinP1363Format}
 * (IEEE P1363 is exactly that concatenation), so we use it and never hand-convert DER.
 */
public enum SigningAlgorithm {

  /** Ed25519 / EdDSA — the family default. */
  EDDSA("EdDSA", "Ed25519") {
    @Override
    public KeyPair generate() {
      return Ed25519Keys.generate();
    }

    @Override
    public PrivateKey decodePrivate(final String base64Pkcs8) {
      return Ed25519Keys.decodePrivate(base64Pkcs8);
    }

    @Override
    public PublicKey decodePublic(final String base64Spki) {
      return Ed25519Keys.decodePublic(base64Spki);
    }

    @Override
    public Jwk jwk(final String kid, final PublicKey publicKey) {
      return Jwk.forEd25519(kid, publicKey);
    }
  },

  /** ECDSA P-256 / SHA-256, raw {@code R || S} signatures. */
  ES256("ES256", "SHA256withECDSAinP1363Format") {
    @Override
    public KeyPair generate() {
      return EcP256Keys.generate();
    }

    @Override
    public PrivateKey decodePrivate(final String base64Pkcs8) {
      return EcP256Keys.decodePrivate(base64Pkcs8);
    }

    @Override
    public PublicKey decodePublic(final String base64Spki) {
      return EcP256Keys.decodePublic(base64Spki);
    }

    @Override
    public Jwk jwk(final String kid, final PublicKey publicKey) {
      return Jwk.forEcP256(kid, publicKey);
    }
  };

  private final String jwsName;
  private final String jcaSignature;

  SigningAlgorithm(final String jwsName, final String jcaSignature) {
    this.jwsName = jwsName;
    this.jcaSignature = jcaSignature;
  }

  /** @return the JOSE {@code alg} name ({@code "EdDSA"} / {@code "ES256"}). */
  public String jwsName() {
    return jwsName;
  }

  /** @return the JCA {@code Signature} algorithm that produces the JWS signature bytes directly. */
  public String jcaSignature() {
    return jcaSignature;
  }

  /** @return a fresh key pair for this algorithm. */
  public abstract KeyPair generate();

  /** @return the private key from its base64 PKCS#8 encoding. */
  public abstract PrivateKey decodePrivate(String base64Pkcs8);

  /** @return the public key from its base64 X.509 SPKI encoding. */
  public abstract PublicKey decodePublic(String base64Spki);

  /** @return the public JWK publishing {@code publicKey} under {@code kid}. */
  public abstract Jwk jwk(String kid, PublicKey publicKey);

  /**
   * Look an algorithm up by its JOSE name (case-insensitive, so {@code es256} works in config).
   *
   * @param name the JOSE {@code alg} name.
   * @return the algorithm.
   * @throws IllegalArgumentException if it is not one this token plane signs with.
   */
  public static SigningAlgorithm fromJwsName(final String name) {
    if (name != null) {
      for (final SigningAlgorithm alg : values()) {
        if (alg.jwsName.toLowerCase(Locale.ROOT).equals(name.trim().toLowerCase(Locale.ROOT))) {
          return alg;
        }
      }
    }
    throw new IllegalArgumentException("unsupported signing algorithm: " + name
        + " (supported: EdDSA, ES256)");
  }
}
