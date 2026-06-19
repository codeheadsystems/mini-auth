package com.codeheadsystems.minica.client;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.minica.client.model.Certificate;
import com.codeheadsystems.minica.client.model.HealthStatus;
import com.codeheadsystems.minica.client.model.IssuanceLogEntry;
import com.codeheadsystems.minica.client.model.RevocationEntry;
import java.net.URI;
import java.time.Duration;
import java.util.List;

/**
 * A client for mini-ca — the internal certificate authority.
 *
 * <p>It speaks two surfaces: the <b>public</b> trust-anchor / revocation / health endpoints (no
 * credential — a verifier needs the root and the revocation list), and the <b>admin</b> issuance /
 * renewal / revocation / log endpoints (guarded by mini-ca's admin bearer token, supplied when the
 * client is built). Certificates and CSRs cross the wire as PEM — public material, no secrets; the CA
 * never sees a requester's private key.
 *
 * <p>Every method may throw {@link ClientException} (the no-oracle collapse): a malformed CSR, a
 * refused admin token, and an unreachable CA are indistinguishable to the caller, by design (the CA
 * itself returns one generic {@code 400} for any bad CSR).
 *
 * <p>Slice 5 exposes the issuance/renewal/revocation/log surface the Certificates page and the
 * certificate-lifecycle exercise need.
 */
public interface MiniCaClient {

  /**
   * @return the CA root certificate, PEM (the trust anchor — public).
   * @throws ClientException on any failure.
   */
  String caCertificatePem();

  /**
   * @return the CA's revocation list (public).
   * @throws ClientException on any failure.
   */
  List<RevocationEntry> revocations();

  /**
   * Issue a leaf certificate from a PKCS#10 CSR (admin).
   *
   * @param csrPem the certificate signing request, PEM.
   * @param ttl    the requested leaf lifetime, clamped to the CA's max; null uses the CA default.
   * @return the issued certificate (leaf + CA PEM + expiry).
   * @throws ClientException on any failure (a bad CSR, a refused admin token — no oracle).
   */
  Certificate issue(String csrPem, Duration ttl);

  /**
   * Renew a leaf, optionally revoking the cert it replaces (admin).
   *
   * @param csrPem         the certificate signing request, PEM.
   * @param ttl            the requested leaf lifetime; null uses the CA default.
   * @param previousSerial the serial of the cert being replaced (revoked on success), or null.
   * @return the renewed certificate.
   * @throws ClientException on any failure.
   */
  Certificate renew(String csrPem, Duration ttl, String previousSerial);

  /**
   * Revoke a certificate by serial (admin). Idempotent.
   *
   * @param serial the certificate serial (lowercase hex).
   * @param reason an optional operator-supplied reason.
   * @throws ClientException on any failure.
   */
  void revoke(String serial, String reason);

  /**
   * @return the CA's issuance log, oldest first (admin).
   * @throws ClientException on any failure (including a refused admin token — no oracle).
   */
  List<IssuanceLogEntry> issuanceLog();

  /**
   * @return the CA's liveness status.
   * @throws ClientException on any failure.
   */
  HealthStatus health();

  /**
   * Build an HTTP-backed client.
   *
   * @param baseUri    the CA origin (e.g. {@code http://127.0.0.1:8499}).
   * @param adminToken the CA admin bearer token, used for issuance/renewal/revocation/log (held in
   *                   memory only, never logged).
   * @return a client over loopback-friendly transports.
   */
  static MiniCaClient http(final URI baseUri, final String adminToken) {
    return new HttpMiniCaClient(baseUri, adminToken);
  }
}
