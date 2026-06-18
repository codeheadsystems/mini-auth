package com.codeheadsystems.minica.support;

import com.codeheadsystems.minica.ca.CaKeys;
import com.codeheadsystems.minica.ca.Pem;
import java.security.KeyPair;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/** Builds a real EC key pair + PKCS#10 CSR for tests — the client side of issuance. */
public final class TestCsr {

  private TestCsr() {
  }

  /**
   * @param commonName the CSR subject CN.
   * @return a fresh key pair and its CSR (PEM), self-signed for proof-of-possession.
   */
  public static CsrAndKey create(final String commonName) {
    try {
      final KeyPair keyPair = CaKeys.generate();
      final ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
      final PKCS10CertificationRequest csr = new JcaPKCS10CertificationRequestBuilder(
          new X500Name("CN=" + commonName), keyPair.getPublic()).build(signer);
      return new CsrAndKey(keyPair, Pem.encode(Pem.CSR, csr.getEncoded()));
    } catch (final Exception e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * @param keyPair the requester's key pair (its public key ends up in the issued cert).
   * @param csrPem  the CSR in PEM.
   */
  public record CsrAndKey(KeyPair keyPair, String csrPem) {
  }
}
