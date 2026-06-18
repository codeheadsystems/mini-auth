package com.codeheadsystems.minica.ca;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * The issuing engine: signs short-lived leaf certificates from PKCS#10 CSRs with the CA key.
 *
 * <p>The requester keeps its own private key and submits a CSR; the CA verifies the CSR's
 * proof-of-possession (its self-signature), then mints a leaf carrying the CSR's subject and public
 * key, an {@code mTLS}-shaped extension set ({@code CA:false}, {@code digitalSignature +
 * keyEncipherment}, EKU {@code clientAuth + serverAuth}, authority/subject key identifiers), the
 * requested SANs, and a fresh random serial. A {@link CaIssuanceException} (one generic message) is
 * thrown for any malformed/invalid CSR — never an oracle for which check failed.
 */
public final class CertificateAuthority {

  private final X509Certificate caCertificate;
  private final PrivateKey caPrivateKey;
  private final X500Name issuer;

  /**
   * @param caCertificate the self-signed CA root.
   * @param caPrivateKey  the CA private key (unwrapped in memory; from the KMS-backed store).
   */
  public CertificateAuthority(final X509Certificate caCertificate, final PrivateKey caPrivateKey) {
    this.caCertificate = caCertificate;
    this.caPrivateKey = caPrivateKey;
    try {
      this.issuer = new JcaX509CertificateHolder(caCertificate).getSubject();
    } catch (final java.security.cert.CertificateEncodingException e) {
      throw new IllegalStateException("unreadable CA certificate", e);
    }
  }

  /** @return the CA root certificate (the public trust anchor). */
  public X509Certificate caCertificate() {
    return caCertificate;
  }

  /**
   * Issue a leaf certificate from a CSR.
   *
   * @param csrPem the PKCS#10 CSR in PEM.
   * @param sans   subject alternative names (DNS names or IPv4 addresses); may be empty.
   * @param ttl    the leaf's lifetime (kept short).
   * @param clock  the clock for the validity window.
   * @return the issued leaf certificate.
   * @throws CaIssuanceException if the CSR is malformed or its proof-of-possession fails.
   */
  public X509Certificate issueFromCsr(final String csrPem, final List<String> sans,
                                      final Duration ttl, final Clock clock) {
    try {
      final PKCS10CertificationRequest csr = new PKCS10CertificationRequest(Pem.decode(csrPem));
      // Proof-of-possession: the CSR must be validly self-signed by its own public key.
      if (!csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(csr.getSubjectPublicKeyInfo()))) {
        throw new CaIssuanceException("CSR signature is invalid");
      }
      final PublicKey subjectPublicKey = new JcaPEMKeyConverter().getPublicKey(csr.getSubjectPublicKeyInfo());
      final BigInteger serial = CaKeys.randomSerial();
      final Date notBefore = Date.from(clock.instant());
      final Date notAfter = Date.from(clock.instant().plus(ttl));
      final JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();

      final X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
          issuer, serial, notBefore, notAfter, csr.getSubject(), subjectPublicKey)
          .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
          .addExtension(Extension.keyUsage, true,
              new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment))
          .addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeId[] {
              KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth}))
          .addExtension(Extension.authorityKeyIdentifier, false,
              ext.createAuthorityKeyIdentifier(caCertificate.getPublicKey()))
          .addExtension(Extension.subjectKeyIdentifier, false,
              ext.createSubjectKeyIdentifier(subjectPublicKey));
      final GeneralNames altNames = subjectAlternativeNames(sans);
      if (altNames != null) {
        builder.addExtension(Extension.subjectAlternativeName, false, altNames);
      }

      final ContentSigner signer = new JcaContentSignerBuilder(CaKeys.SIGNATURE_ALGORITHM)
          .build(caPrivateKey);
      return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    } catch (final CaIssuanceException e) {
      throw e;
    } catch (final GeneralSecurityException | OperatorCreationException | IOException
                   | org.bouncycastle.pkcs.PKCSException | IllegalArgumentException e) {
      // One generic failure for any malformed/invalid request — no oracle.
      throw new CaIssuanceException("the certificate request could not be processed");
    }
  }

  private static GeneralNames subjectAlternativeNames(final List<String> sans) {
    if (sans == null || sans.isEmpty()) {
      return null;
    }
    final List<GeneralName> names = new ArrayList<>();
    for (final String san : sans) {
      if (san == null || san.isBlank()) {
        continue;
      }
      final int type = san.matches("\\d{1,3}(\\.\\d{1,3}){3}")
          ? GeneralName.iPAddress : GeneralName.dNSName;
      names.add(new GeneralName(type, san.trim()));
    }
    return names.isEmpty() ? null : new GeneralNames(names.toArray(new GeneralName[0]));
  }

  /** Thrown when a CSR cannot be turned into a certificate; carries a single generic message. */
  public static final class CaIssuanceException extends RuntimeException {
    public CaIssuanceException(final String message) {
      super(message);
    }
  }
}
