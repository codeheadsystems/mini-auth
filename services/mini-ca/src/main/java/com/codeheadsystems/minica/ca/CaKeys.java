package com.codeheadsystems.minica.ca;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Generates the CA's EC P-256 key pair and its self-signed root certificate, and (de)serializes the
 * key for at-rest storage.
 *
 * <p>The root is a minimal v3 CA cert: {@code CA:true} with {@code pathLen 0} (no intermediates —
 * one flat level, the educational simplification), {@code keyCertSign + cRLSign} usage, a subject
 * key identifier, and a long validity (the leaves are the short-lived ones). EC P-256 +
 * {@code SHA256withECDSA} is the broadly-interoperable choice for mTLS.
 */
public final class CaKeys {

  /** The signature algorithm the CA uses for the root and every leaf. */
  public static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

  private CaKeys() {
  }

  /** Generate a fresh EC P-256 key pair (JDK provider). */
  public static KeyPair generate() {
    try {
      final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
      return generator.generateKeyPair();
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("EC P-256 unavailable in this JDK", e);
    }
  }

  /**
   * Build the self-signed CA root certificate.
   *
   * @param caKeyPair  the CA key pair.
   * @param subjectDn  the CA distinguished name (e.g. {@code "CN=mini-ca"}).
   * @param validity   how long the root is valid.
   * @param clock      the clock for the validity window.
   * @return the self-signed root certificate.
   */
  public static X509Certificate selfSignedRoot(final KeyPair caKeyPair, final String subjectDn,
                                               final Duration validity, final Clock clock) {
    try {
      final X500Name name = new X500Name(subjectDn);
      final Date notBefore = Date.from(clock.instant());
      final Date notAfter = Date.from(clock.instant().plus(validity));
      final JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
      final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
          name, randomSerial(), notBefore, notAfter, name, caKeyPair.getPublic())
          .addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
          .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
          .addExtension(Extension.subjectKeyIdentifier, false,
              ext.createSubjectKeyIdentifier(caKeyPair.getPublic()));
      final ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
          .build(caKeyPair.getPrivate());
      return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    } catch (final GeneralSecurityException | OperatorCreationException | java.io.IOException e) {
      throw new IllegalStateException("failed to build the CA root certificate", e);
    }
  }

  /** @return a random positive 128-bit serial number. */
  public static BigInteger randomSerial() {
    return new BigInteger(128, new SecureRandom()).add(BigInteger.ONE);
  }

  /** @return the EC private key as base64 PKCS#8. */
  public static String encodePrivate(final PrivateKey key) {
    return Base64.getEncoder().encodeToString(key.getEncoded());
  }

  /** @return the EC public key as base64 X.509 SubjectPublicKeyInfo. */
  public static String encodePublic(final PublicKey key) {
    return Base64.getEncoder().encodeToString(key.getEncoded());
  }

  /** Reload the EC private key from base64 PKCS#8. */
  public static PrivateKey decodePrivate(final String base64Pkcs8) {
    try {
      return KeyFactory.getInstance("EC")
          .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64Pkcs8)));
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("failed to decode the CA private key", e);
    }
  }

  /** Reload the EC public key from base64 X.509 SPKI. */
  public static PublicKey decodePublic(final String base64Spki) {
    try {
      return KeyFactory.getInstance("EC")
          .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64Spki)));
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("failed to decode the CA public key", e);
    }
  }
}
