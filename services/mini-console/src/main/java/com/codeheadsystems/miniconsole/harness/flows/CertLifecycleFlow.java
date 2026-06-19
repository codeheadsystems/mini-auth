package com.codeheadsystems.miniconsole.harness.flows;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.miniconsole.harness.Exercise;
import com.codeheadsystems.miniconsole.harness.ExerciseResult;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Status;
import com.codeheadsystems.miniconsole.harness.ExerciseResult.Step;
import com.codeheadsystems.minica.client.Csr;
import com.codeheadsystems.minica.client.MiniCaClient;
import com.codeheadsystems.minica.client.model.Certificate;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * The certificate-lifecycle exercise: prove that mini-ca issues a leaf certificate that genuinely
 * chains to its published root, renews it, and revokes it — exactly the round trip a homelab workload
 * makes for its mTLS identity.
 *
 * <p>Steps: generate an EC P-256 key pair + PKCS#10 CSR locally → issue a leaf → <b>validate the leaf
 * chains to the CA root</b> with the JDK's PKIX {@link CertPathValidator} (the headline assertion) →
 * renew (revoking the original) → revoke the renewal → confirm the serial appears on the revocation
 * list.
 *
 * <p><b>No secrets involved.</b> Certificates and CSRs are public material; the generated private key
 * stays inside {@link Csr#generate} and is discarded. Steps report only non-secret facts (serials,
 * the subject, expiry, the chain-valid outcome).
 *
 * <p><b>This exercise mutates real CA state</b> — it issues and revokes real certificates. The Harness
 * page warns the operator before running it.
 */
public final class CertLifecycleFlow implements Exercise {

  /** The stable id used in the route ({@code /harness/cert-lifecycle/run}) and the result. */
  public static final String ID = "cert-lifecycle";

  private static final String SUBJECT = "console-smoke-test";
  private static final Duration LEAF_TTL = Duration.ofHours(1);

  @Override
  public String id() {
    return ID;
  }

  @Override
  public String title() {
    return "Certificate lifecycle";
  }

  @Override
  public String description() {
    return "Issue a leaf certificate from mini-ca, prove it chains to the CA root, then renew and "
        + "revoke it. NOTE: this issues and revokes real certificates.";
  }

  /**
   * Run the lifecycle against the wired CA. No operator input is needed — the flow generates its own
   * CSR; the CA admin token is the one the client already holds.
   *
   * @param ca the wired mini-ca client.
   * @return the result (PASS only if the leaf chained to the root and the serial was revoked).
   */
  public ExerciseResult run(final MiniCaClient ca) {
    final List<Step> steps = new ArrayList<>();

    final String csr = Csr.generate(SUBJECT);
    steps.add(new Step("Generate CSR", Status.PASS, "EC P-256 PKCS#10 request for CN=" + SUBJECT));

    final Certificate issued;
    final String caPem;
    try {
      issued = ca.issue(csr, LEAF_TTL);
      caPem = issued.caCertificate();
    } catch (final ClientException e) {
      // No oracle: a bad CSR, a refused admin token, and an unreachable CA all look the same.
      steps.add(new Step("Issue certificate", Status.FAIL, "the CA refused to issue or was unreachable"));
      return ExerciseResult.of(this, steps, "Could not issue a certificate.");
    }
    steps.add(new Step("Issue certificate", Status.PASS,
        "serial=" + issued.serial() + ", notAfter=" + issued.notAfter()));

    final ChainResult chain = validateChain(issued.certificate(), caPem);
    steps.add(new Step("Validate chain to CA root", chain.valid() ? Status.PASS : Status.FAIL,
        chain.detail()));
    if (!chain.valid()) {
      return ExerciseResult.of(this, steps, "The issued leaf did NOT chain to the CA root.");
    }

    final Certificate renewed;
    try {
      // Renew, passing the original serial so the CA revokes the cert we replace.
      renewed = ca.renew(Csr.generate(SUBJECT), LEAF_TTL, issued.serial());
    } catch (final ClientException e) {
      steps.add(new Step("Renew certificate", Status.FAIL, "the CA refused to renew or was unreachable"));
      return ExerciseResult.of(this, steps, "Could not renew the certificate.");
    }
    steps.add(new Step("Renew certificate", Status.PASS, "new serial=" + renewed.serial()));

    try {
      ca.revoke(renewed.serial(), "certificate-lifecycle smoke test");
    } catch (final ClientException e) {
      steps.add(new Step("Revoke certificate", Status.FAIL, "the CA refused to revoke or was unreachable"));
      return ExerciseResult.of(this, steps, "Could not revoke the certificate.");
    }
    steps.add(new Step("Revoke certificate", Status.PASS, "revoked serial=" + renewed.serial()));

    final boolean onList;
    try {
      onList = ca.revocations().stream().anyMatch(r -> r.serial().equals(renewed.serial()));
    } catch (final ClientException e) {
      steps.add(new Step("Confirm on revocation list", Status.FAIL, "could not read the revocation list"));
      return ExerciseResult.of(this, steps, "Could not read the revocation list.");
    }
    steps.add(new Step("Confirm on revocation list", onList ? Status.PASS : Status.FAIL,
        "revoked serial " + (onList ? "present" : "MISSING") + " on the list"));

    final boolean passed = onList;
    return ExerciseResult.of(this, steps, passed
        ? "Issued a leaf that chained to the CA root, renewed it, and revoked the renewal."
        : "The revoked serial did not appear on the revocation list.");
  }

  /** Validate that {@code leafPem} chains to {@code caPem} via the JDK's PKIX validator (no BC). */
  private static ChainResult validateChain(final String leafPem, final String caPem) {
    try {
      final CertificateFactory factory = CertificateFactory.getInstance("X.509");
      final X509Certificate leaf = parse(factory, leafPem);
      final X509Certificate root = parse(factory, caPem);
      final CertPath path = factory.generateCertPath(List.of(leaf));
      final PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(root, null)));
      // The CA's revocation list is a JSON list, not a DER CRL — the harness checks issuance/chain
      // here and exercises revocation separately, so disable PKIX revocation checking.
      params.setRevocationEnabled(false);
      CertPathValidator.getInstance("PKIX").validate(path, params);
      return new ChainResult(true, "leaf for " + leaf.getSubjectX500Principal().getName()
          + " chains to " + root.getSubjectX500Principal().getName());
    } catch (final GeneralSecurityException e) {
      // Any validation failure is reported as a category, never the underlying exception detail.
      return new ChainResult(false, "the leaf did not validate against the CA root");
    }
  }

  private static X509Certificate parse(final CertificateFactory factory, final String pem)
      throws GeneralSecurityException {
    return (X509Certificate) factory.generateCertificate(
        new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
  }

  /** The outcome of a chain validation: valid flag + a non-secret detail line. */
  private record ChainResult(boolean valid, String detail) {
  }
}
