package com.codeheadsystems.miniidp.server.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Request bodies for mini-idp's own admin API.
 *
 * <p>Client/service-account management moved to mini-directory, so the client-registry DTOs are
 * gone; what remains is the revocation request for mini-idp's denylist.
 */
public final class Dtos {

  private Dtos() {
  }

  /**
   * Body of {@code POST /admin/revocations}.
   *
   * @param jti       the token id to revoke (required).
   * @param expiresAt the revoked token's expiry (epoch seconds); optional — defaults to now + the
   *                  configured token TTL so the entry lingers at least one full lifetime.
   * @param reason    optional operator reason.
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record RevocationRequest(String jti, Long expiresAt, String reason) {
  }
}
