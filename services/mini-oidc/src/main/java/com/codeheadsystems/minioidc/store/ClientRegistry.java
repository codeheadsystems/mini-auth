package com.codeheadsystems.minioidc.store;

import com.codeheadsystems.minioidc.model.OidcClient;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * The persisted client registry document ({@code clients.json}) — the one JSON file holding every
 * registered relying party. Written through {@link JsonStore} (atomic + {@code 0600}, since client
 * records carry Argon2id secret hashes).
 *
 * @param clients the registered clients; never null.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientRegistry(List<OidcClient> clients) {

  public ClientRegistry {
    clients = clients == null ? List.of() : List.copyOf(clients);
  }
}
