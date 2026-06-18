package com.codeheadsystems.minica.store;

import com.codeheadsystems.minica.model.IssuedCertificate;
import com.codeheadsystems.minica.model.Revocation;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * The CA's own persisted documents, one per file. The CA <b>key</b> is NOT here — it lives in a
 * mini-token {@code SigningKeys} document so it can be wrapped under mini-kms; these are the public
 * bits (the root certificate) and the operational records (issuance log, revocation list).
 */
public final class CaDocuments {

  private CaDocuments() {
  }

  /**
   * The CA root certificate ({@code ca-cert.json}). Public — it is the trust anchor verifiers fetch.
   *
   * @param caCertificatePem the self-signed root in PEM.
   * @param createdAt        when the CA was bootstrapped (epoch seconds).
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record CaCertificate(String caCertificatePem, long createdAt) {
  }

  /** The issuance log ({@code issuance-log.json}), oldest first. */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record IssuanceLog(List<IssuedCertificate> entries) {
    public IssuanceLog {
      entries = entries == null ? List.of() : List.copyOf(entries);
    }
  }

  /** The revocation list ({@code revocations.json}). */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record RevocationList(List<Revocation> revocations) {
    public RevocationList {
      revocations = revocations == null ? List.of() : List.copyOf(revocations);
    }
  }
}
