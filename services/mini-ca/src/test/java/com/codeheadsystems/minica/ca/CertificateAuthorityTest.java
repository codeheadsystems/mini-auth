package com.codeheadsystems.minica.ca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.codeheadsystems.minica.ca.CertificateAuthority.CaIssuanceException;
import com.codeheadsystems.minica.support.TestCsr;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Exercises the CA crypto directly: self-signed root, issuance from a CSR, and CSR rejection. */
class CertificateAuthorityTest {

  private CertificateAuthority ca;

  @BeforeEach
  void setUp() {
    final KeyPair caKeyPair = CaKeys.generate();
    final X509Certificate root = CaKeys.selfSignedRoot(
        caKeyPair, "CN=mini-ca-test", Duration.ofDays(3650), Clock.systemUTC());
    ca = new CertificateAuthority(root, caKeyPair.getPrivate());
  }

  @Test
  void issuesALeafThatChainsToTheCaAndCarriesTheCsrIdentity() throws Exception {
    final TestCsr.CsrAndKey request = TestCsr.create("worker.svc");
    final X509Certificate leaf = ca.issueFromCsr(
        request.csrPem(), List.of("worker.svc", "127.0.0.1"), Duration.ofHours(24), Clock.systemUTC());

    // The leaf is signed by the CA (chains to the trust anchor) ...
    leaf.verify(ca.caCertificate().getPublicKey());
    // ... carries the requester's public key and subject ...
    assertArrayEquals(request.keyPair().getPublic().getEncoded(), leaf.getPublicKey().getEncoded());
    assertTrue(leaf.getSubjectX500Principal().getName().contains("worker.svc"));
    // ... is a non-CA mTLS leaf (clientAuth + serverAuth) ...
    assertTrue(leaf.getBasicConstraints() < 0, "leaf must not be a CA");
    assertTrue(leaf.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.2"), "clientAuth EKU");
    assertTrue(leaf.getExtendedKeyUsage().contains("1.3.6.1.5.5.7.3.1"), "serverAuth EKU");
    // ... with the requested SANs.
    final List<?> sans = leaf.getSubjectAlternativeNames().stream().map(s -> s.get(1)).toList();
    assertTrue(sans.contains("worker.svc"));
    assertTrue(sans.contains("127.0.0.1"));
  }

  @Test
  void shortTtlIsHonored() {
    final TestCsr.CsrAndKey request = TestCsr.create("short.svc");
    final X509Certificate leaf = ca.issueFromCsr(request.csrPem(), List.of(), Duration.ofMinutes(10), Clock.systemUTC());
    final long lifetimeSeconds =
        (leaf.getNotAfter().getTime() - leaf.getNotBefore().getTime()) / 1000;
    assertEquals(600, lifetimeSeconds, 2);
  }

  @Test
  void aMalformedCsrIsRejectedWithoutAnOracle() {
    assertThrows(CaIssuanceException.class,
        () -> ca.issueFromCsr("-----BEGIN CERTIFICATE REQUEST-----\nbm90LWEtY3Ny\n-----END CERTIFICATE REQUEST-----",
            List.of(), Duration.ofHours(1), Clock.systemUTC()));
  }
}
