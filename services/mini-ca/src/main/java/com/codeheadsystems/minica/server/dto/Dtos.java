package com.codeheadsystems.minica.server.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * Request and response bodies for the CA's admin API. Certificates and CSRs cross the wire as PEM.
 */
public final class Dtos {

  private Dtos() {
  }

  /**
   * Body of {@code POST /issue}.
   *
   * @param csr        the PKCS#10 certificate signing request, PEM.
   * @param ttlSeconds requested leaf lifetime in seconds (optional; clamped to the configured max).
   * @param sans       subject alternative names — DNS names or IPv4 addresses (optional).
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record IssueRequest(String csr, Long ttlSeconds, List<String> sans) {
  }

  /**
   * Body of {@code POST /renew}: like {@link IssueRequest}, plus the serial of the cert being
   * replaced (which is revoked on success).
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record RenewRequest(String csr, Long ttlSeconds, List<String> sans, String previousSerial) {
  }

  /** Body of {@code POST /revoke}. */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record RevokeRequest(String serial, String reason) {
  }

  /**
   * Response of {@code POST /issue} and {@code POST /renew}.
   *
   * @param serial         the issued certificate's serial (lowercase hex) — the revocation handle.
   * @param certificate    the issued leaf certificate, PEM.
   * @param caCertificate  the CA root certificate, PEM (the trust anchor to validate the leaf).
   * @param notAfter       leaf expiry (epoch seconds).
   */
  public record IssueResponse(String serial, String certificate, String caCertificate, long notAfter) {
  }
}
