package com.codeheadsystems.minioidc.service;

import com.codeheadsystems.minioidc.model.OidcClient;
import com.codeheadsystems.minioidc.secret.Argon2SecretHasher;
import com.codeheadsystems.minioidc.secret.SecretHash;
import com.codeheadsystems.minioidc.store.ClientRegistry;
import com.codeheadsystems.minioidc.store.JsonStore;
import com.codeheadsystems.minioidc.util.Tokens;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The relying-party registry: register/list/get clients, and authenticate a confidential client at
 * the token endpoint.
 *
 * <p>State is held in memory and persisted to {@code clients.json} via {@link JsonStore} on every
 * mutation (mirroring mini-idp's {@code ClientService}). A confidential client's secret is generated
 * here, Argon2id-hashed immediately, and the plaintext returned exactly once at registration. All
 * methods are {@code synchronized}.
 */
public final class ClientService {

  private final JsonStore<ClientRegistry> store;
  private final Argon2SecretHasher hasher;
  private final Tokens tokens;
  private final Clock clock;
  private final Map<String, OidcClient> clients = new LinkedHashMap<>();

  public ClientService(final JsonStore<ClientRegistry> store, final Argon2SecretHasher hasher,
                       final Tokens tokens, final Clock clock) {
    this.store = store;
    this.hasher = hasher;
    this.tokens = tokens;
    this.clock = clock;
    if (store.exists()) {
      for (final OidcClient client : store.load().clients()) {
        clients.put(client.clientId(), client);
      }
    }
  }

  /**
   * Register a relying party.
   *
   * @param name         a human label shown on the consent screen.
   * @param redirectUris the exact redirect URIs this client may use (at least one).
   * @param scopes       the scopes it may request.
   * @param confidential whether to mint a client secret (confidential) or leave it public (PKCE-only).
   * @return the stored client plus the one-time secret (null for a public client).
   */
  public synchronized Registration register(final String name, final List<String> redirectUris,
                                            final List<String> scopes, final boolean confidential) {
    if (redirectUris == null || redirectUris.isEmpty()) {
      throw new IllegalArgumentException("at least one redirect URI is required");
    }
    final String clientId = tokens.newClientId();
    char[] secret = null;
    SecretHash secretHash = null;
    if (confidential) {
      secret = tokens.newClientSecret();
      secretHash = hasher.hash(secret);
    }
    final OidcClient client = new OidcClient(clientId, name, secretHash, redirectUris, scopes,
        clock.instant().getEpochSecond());
    clients.put(clientId, client);
    persist();
    return new Registration(client, secret);
  }

  /** @return all registered clients. */
  public synchronized List<OidcClient> list() {
    return new ArrayList<>(clients.values());
  }

  /** @return the client with this id, if present. */
  public synchronized Optional<OidcClient> get(final String clientId) {
    return Optional.ofNullable(clientId == null ? null : clients.get(clientId));
  }

  /**
   * Authenticate a confidential client at the token endpoint, with no credential oracle: an unknown
   * client id still incurs a dummy hash verification so timing does not reveal which check failed.
   *
   * @param clientId the presented client id.
   * @param secret   the presented secret (caller should zero it afterwards).
   * @return whether the client authenticated.
   */
  public synchronized boolean authenticate(final String clientId, final char[] secret) {
    final OidcClient client = clientId == null ? null : clients.get(clientId);
    if (client == null || client.secretHash() == null) {
      hasher.verify(secret, DUMMY_HASH);
      return false;
    }
    return hasher.verify(secret, client.secretHash());
  }

  private void persist() {
    store.save(new ClientRegistry(new ArrayList<>(clients.values())));
  }

  /**
   * The result of registering a client.
   *
   * @param client the persisted client.
   * @param secret the one-time plaintext secret (null for a public client); zero it after use.
   */
  public record Registration(OidcClient client, char[] secret) {
  }

  // A fixed, well-formed hash to keep timing uniform for unknown/public-client lookups.
  private static final SecretHash DUMMY_HASH = new SecretHash(
      SecretHash.ALGORITHM_ARGON2ID,
      "AAAAAAAAAAAAAAAAAAAAAA==",
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      8, 1, 1);
}
