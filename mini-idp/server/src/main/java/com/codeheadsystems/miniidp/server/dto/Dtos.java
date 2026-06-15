package com.codeheadsystems.miniidp.server.dto;

import com.codeheadsystems.miniidp.model.ClientRecord;
import com.codeheadsystems.miniidp.token.GrantsClaim;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Request and response bodies for the admin and discovery APIs.
 *
 * <p>The authorization payload is expressed everywhere as a {@link GrantsClaim} ({@code control} +
 * {@code groups}), so the admin API speaks the exact same shape that ends up in the token's
 * {@code grants} claim — one contract, no translation. Crucially, {@link ClientView} omits the
 * secret hash entirely: listing clients never returns secret material.
 */
public final class Dtos {

  private Dtos() {
  }

  /**
   * Body of {@code POST /admin/clients}.
   *
   * @param displayName   optional human label.
   * @param authorization the grants/control authority to issue (may be null = none).
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record RegisterClientRequest(String displayName, GrantsClaim authorization) {
  }

  /**
   * Response of {@code POST /admin/clients}: includes the one-time plaintext secret. This is the
   * only time the secret is ever returned; it is not recoverable later.
   *
   * @param clientId      the new client id.
   * @param secret        the one-time plaintext secret (store it now).
   * @param displayName   the human label, if any.
   * @param authorization the authorization the client's tokens will carry.
   * @param createdAt     creation time (epoch seconds).
   */
  public record RegisterClientResponse(String clientId, String secret, String displayName,
                                       GrantsClaim authorization, long createdAt) {
  }

  /**
   * A client as returned by {@code GET /admin/clients} — deliberately WITHOUT any secret hash.
   *
   * @param clientId      the client id.
   * @param displayName   the human label, if any.
   * @param enabled       whether the client may obtain tokens.
   * @param createdAt     creation time (epoch seconds).
   * @param authorization the authorization the client's tokens carry.
   */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record ClientView(String clientId, String displayName, boolean enabled, long createdAt,
                           GrantsClaim authorization) {

    /** Project a stored record into its safe view (drops the secret hash). */
    public static ClientView from(final ClientRecord record) {
      return new ClientView(record.clientId(), record.displayName(), record.enabled(),
          record.createdAt(), GrantsClaim.from(record.authorization()));
    }
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
