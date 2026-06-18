package com.codeheadsystems.minica.service;

import com.codeheadsystems.minica.ca.CaKeys;
import com.codeheadsystems.minica.ca.CertificateAuthority;
import com.codeheadsystems.minica.ca.Pem;
import com.codeheadsystems.minica.model.IssuedCertificate;
import com.codeheadsystems.minica.model.Revocation;
import com.codeheadsystems.minica.store.CaDocuments.CaCertificate;
import com.codeheadsystems.minica.store.CaDocuments.IssuanceLog;
import com.codeheadsystems.minica.store.CaDocuments.RevocationList;
import com.codeheadsystems.minitoken.model.SigningKeyRecord;
import com.codeheadsystems.minitoken.store.DocumentStore;
import com.codeheadsystems.minitoken.store.TokenStoreDocuments.SigningKeys;
import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The CA application service: bootstraps (or loads) the CA, issues/renews leaf certs, and maintains
 * the issuance log + revocation list.
 *
 * <p>The CA <b>private key</b> is persisted as a one-record mini-token {@code SigningKeys} document
 * through the injected {@link DocumentStore} — which is the mini-kms-backed
 * {@code KmsSigningKeyStore} when wrapping is configured, so the key is envelope-encrypted at rest,
 * or a plaintext-{@code 0600} JSON store by default. The public bits — the root certificate, the
 * issuance log, the revocation list — are plaintext JSON. The key is unwrapped into memory once at
 * bootstrap and held by the {@link CertificateAuthority}.
 *
 * <p>All methods are {@code synchronized}; the CA is the sole writer of its files.
 */
public final class CaService {

  /** The kid the single CA key is stored under in the SigningKeys document. */
  private static final String CA_KID = "ca";

  private final DocumentStore<SigningKeys> caKeyStore;
  private final DocumentStore<CaCertificate> caCertStore;
  private final DocumentStore<IssuanceLog> logStore;
  private final DocumentStore<RevocationList> revocationStore;
  private final Clock clock;

  private final CertificateAuthority ca;
  private final List<IssuedCertificate> issuanceLog = new ArrayList<>();
  private final Map<String, Revocation> revocations = new LinkedHashMap<>();

  /**
   * @param caKeyStore      the CA-key store (KMS-backed or plaintext) holding the private key.
   * @param caCertStore     the root-certificate store.
   * @param logStore        the issuance-log store.
   * @param revocationStore the revocation-list store.
   * @param caSubjectDn      the CA subject DN used when bootstrapping a fresh root (e.g. {@code "CN=mini-ca"}).
   * @param caValidity      the root validity used when bootstrapping.
   * @param clock           the clock for validity windows and timestamps.
   */
  public CaService(final DocumentStore<SigningKeys> caKeyStore,
                   final DocumentStore<CaCertificate> caCertStore,
                   final DocumentStore<IssuanceLog> logStore,
                   final DocumentStore<RevocationList> revocationStore,
                   final String caSubjectDn, final Duration caValidity, final Clock clock) {
    this.caKeyStore = caKeyStore;
    this.caCertStore = caCertStore;
    this.logStore = logStore;
    this.revocationStore = revocationStore;
    this.clock = clock;
    this.ca = bootstrap(caSubjectDn, caValidity);
    if (logStore.exists()) {
      issuanceLog.addAll(logStore.load().entries());
    }
    if (revocationStore.exists()) {
      for (final Revocation revocation : revocationStore.load().revocations()) {
        revocations.put(revocation.serial(), revocation);
      }
    }
  }

  private CertificateAuthority bootstrap(final String caSubjectDn, final Duration caValidity) {
    if (caKeyStore.exists() && caCertStore.exists()) {
      final PrivateKey caKey = CaKeys.decodePrivate(caKeyStore.load().keys().get(0).privatePkcs8Base64());
      return new CertificateAuthority(parse(caCertStore.load().caCertificatePem()), caKey);
    }
    // First run: mint the root, store the (wrapped) key and the (public) cert.
    final KeyPair keyPair = CaKeys.generate();
    final X509Certificate root = CaKeys.selfSignedRoot(keyPair, caSubjectDn, caValidity, clock);
    final long now = clock.instant().getEpochSecond();
    caKeyStore.save(new SigningKeys(CA_KID, List.of(new SigningKeyRecord(
        CA_KID, CaKeys.encodePrivate(keyPair.getPrivate()), CaKeys.encodePublic(keyPair.getPublic()),
        true, now, null))));
    caCertStore.save(new CaCertificate(Pem.encode(Pem.CERTIFICATE, der(root)), now));
    return new CertificateAuthority(root, keyPair.getPrivate());
  }

  /** Issue a leaf certificate from a CSR, recording it in the issuance log. */
  public synchronized X509Certificate issue(final String csrPem, final List<String> sans,
                                            final Duration ttl) {
    return record(ca.issueFromCsr(csrPem, sans, ttl, clock), null);
  }

  /**
   * Renew: issue a fresh leaf from a CSR and, if a prior serial is given, revoke it (rotation).
   *
   * @param previousSerial the serial of the cert being replaced, or null.
   */
  public synchronized X509Certificate renew(final String csrPem, final List<String> sans,
                                            final Duration ttl, final String previousSerial) {
    final X509Certificate cert = record(ca.issueFromCsr(csrPem, sans, ttl, clock), previousSerial);
    if (previousSerial != null && !previousSerial.isBlank()) {
      revokeInternal(previousSerial, "superseded by renewal");
    }
    return cert;
  }

  /** Revoke a certificate by serial. Idempotent. */
  public synchronized void revoke(final String serial, final String reason) {
    revokeInternal(serial, reason);
  }

  /** @return whether the given serial is currently revoked. */
  public synchronized boolean isRevoked(final String serial) {
    return revocations.containsKey(serial);
  }

  /** @return the issuance log, oldest first. */
  public synchronized List<IssuedCertificate> issuanceLog() {
    return new ArrayList<>(issuanceLog);
  }

  /** @return the current revocation list. */
  public synchronized List<Revocation> revocations() {
    return new ArrayList<>(revocations.values());
  }

  /** @return the CA root certificate in PEM (the public trust anchor). */
  public synchronized String caCertificatePem() {
    return Pem.encode(Pem.CERTIFICATE, der(ca.caCertificate()));
  }

  /** @return the CA root certificate. */
  public X509Certificate caCertificate() {
    return ca.caCertificate();
  }

  private X509Certificate record(final X509Certificate cert, final String renewedFrom) {
    final String serial = serialOf(cert);
    issuanceLog.add(new IssuedCertificate(serial, cert.getSubjectX500Principal().getName(),
        cert.getNotBefore().toInstant().getEpochSecond(),
        cert.getNotAfter().toInstant().getEpochSecond(),
        clock.instant().getEpochSecond(), renewedFrom));
    logStore.save(new IssuanceLog(new ArrayList<>(issuanceLog)));
    return cert;
  }

  private void revokeInternal(final String serial, final String reason) {
    if (revocations.containsKey(serial)) {
      return;
    }
    revocations.put(serial, new Revocation(serial, clock.instant().getEpochSecond(), reason));
    revocationStore.save(new RevocationList(new ArrayList<>(revocations.values())));
  }

  /** Serial as lowercase hex — the stable handle the log and revocation list key on. */
  public static String serialOf(final X509Certificate cert) {
    return cert.getSerialNumber().toString(16);
  }

  private static byte[] der(final X509Certificate cert) {
    try {
      return cert.getEncoded();
    } catch (final java.security.cert.CertificateEncodingException e) {
      throw new IllegalStateException("failed to encode certificate", e);
    }
  }

  private static X509Certificate parse(final String pem) {
    try {
      return (X509Certificate) CertificateFactory.getInstance("X.509")
          .generateCertificate(new ByteArrayInputStream(Pem.decode(pem)));
    } catch (final CertificateException e) {
      throw new IllegalStateException("failed to parse the CA certificate", e);
    }
  }
}
