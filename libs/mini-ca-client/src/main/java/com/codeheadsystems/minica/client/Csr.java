package com.codeheadsystems.minica.client;

import com.codeheadsystems.miniclient.common.ClientException;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.nio.charset.StandardCharsets;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * Generates a self-contained PKCS#10 certificate signing request for a subject. A CA client commonly
 * needs to produce a CSR (the JDK has no CSR API, so this uses BouncyCastle's builder) — the console's
 * certificate-lifecycle exercise uses it to drive a real issue against mini-ca.
 *
 * <p>An EC P-256 key pair is generated, the CSR is signed with {@code SHA256withECDSA} (the algorithm
 * mini-ca issues under), and the result is returned as PEM. The <b>private key is generated locally
 * and discarded</b> — it never leaves this method, is never returned, and is never logged. The CA
 * never sees it; only the public CSR crosses the wire. The PEM output (a CSR) is public material.
 */
public final class Csr {

  private Csr() {
  }

  /**
   * Generate a fresh EC P-256 key pair and a PKCS#10 CSR for the given subject.
   *
   * @param subjectCn the subject common name (e.g. {@code "console-smoke-test"}).
   * @return the CSR, PEM-encoded.
   * @throws ClientException if CSR generation fails (collapsed like any other client failure).
   */
  public static String generate(final String subjectCn) {
    try {
      final KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
      generator.initialize(new ECGenParameterSpec("secp256r1"));
      final KeyPair keyPair = generator.generateKeyPair();
      final ContentSigner signer =
          new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
      final PKCS10CertificationRequest csr =
          new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=" + subjectCn), keyPair.getPublic())
              .build(signer);
      return pem(csr.getEncoded());
    } catch (final java.security.GeneralSecurityException | OperatorCreationException
                   | IOException e) {
      throw new ClientException("could not generate a CSR", e);
    }
  }

  /** Wrap DER bytes in a {@code CERTIFICATE REQUEST} PEM envelope (64-char lines). */
  private static String pem(final byte[] der) {
    final String body =
        Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
    return "-----BEGIN CERTIFICATE REQUEST-----\n" + body + "\n-----END CERTIFICATE REQUEST-----\n";
  }
}
