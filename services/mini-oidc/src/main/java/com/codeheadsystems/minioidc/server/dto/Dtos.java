package com.codeheadsystems.minioidc.server.dto;

import com.codeheadsystems.minioidc.model.OidcClient;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

/**
 * Request and response bodies for the client-admin API.
 *
 * <p>The one-time client secret is returned only at registration, and only for a confidential
 * client; {@link ClientView} (every listing) never includes secret material.
 */
public final class Dtos {

  private Dtos() {
  }

  /**
   * Body of {@code POST /admin/clients}.
   *
   * @param name         a human label shown on the consent screen.
   * @param redirectUris the exact redirect URIs the client may use (at least one).
   * @param scopes       the scopes the client may request.
   * @param confidential whether to mint a client secret (else a public, PKCE-only client).
   */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record RegisterClientRequest(String name, List<String> redirectUris, List<String> scopes,
                                      boolean confidential) {
  }

  /**
   * Response of {@code POST /admin/clients}: includes the one-time secret for a confidential client.
   *
   * @param clientId     the new client id.
   * @param clientSecret the one-time plaintext secret (null for a public client); store it now.
   * @param name         the human label.
   * @param redirectUris the registered redirect URIs.
   * @param scopes       the allowed scopes.
   * @param confidential whether the client has a secret.
   */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record RegisterClientResponse(String clientId, String clientSecret, String name,
                                       List<String> redirectUris, List<String> scopes,
                                       boolean confidential) {
  }

  /** A client as listed by the admin API — never includes the secret hash. */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record ClientView(String clientId, String name, List<String> redirectUris,
                           List<String> scopes, boolean confidential, long createdAt) {

    /** Project a stored client into its safe view. */
    public static ClientView from(final OidcClient client) {
      return new ClientView(client.clientId(), client.name(), client.redirectUris(),
          client.scopes(), client.isConfidential(), client.createdAt());
    }
  }
}
