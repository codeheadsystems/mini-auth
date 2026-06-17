package com.codeheadsystems.miniidp.store;

import com.codeheadsystems.miniidp.model.ClientRecord;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * The top-level JSON document shapes persisted by {@link JsonStore} that are SPECIFIC to mini-idp.
 *
 * <p>The token plane's documents (the signing-key set, the revocation denylist, the audit log)
 * moved to {@code com.codeheadsystems.minitoken.store.TokenStoreDocuments} when the token plane was
 * extracted; what remains here is the client registry, which is mini-idp's own — it holds hashed
 * client secrets and grants, an issuer-specific concern rather than token-plane state.
 */
public final class StoreDocuments {

  private StoreDocuments() {
  }

  /** The client registry file: {@code clients.json}. */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public record ClientRegistry(List<ClientRecord> clients) {
    public ClientRegistry {
      clients = clients == null ? List.of() : List.copyOf(clients);
    }
  }
}
