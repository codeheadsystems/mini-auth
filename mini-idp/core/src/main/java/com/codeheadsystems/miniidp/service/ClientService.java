package com.codeheadsystems.miniidp.service;

import com.codeheadsystems.miniidp.auth.Authorization;
import com.codeheadsystems.miniidp.model.ClientRecord;
import com.codeheadsystems.miniidp.secret.Argon2SecretHasher;
import com.codeheadsystems.miniidp.secret.SecretHash;
import com.codeheadsystems.miniidp.store.JsonStore;
import com.codeheadsystems.miniidp.store.StoreDocuments.ClientRegistry;
import com.codeheadsystems.miniidp.util.RandomIds;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The client registry: registration, listing, removal, grant updates, and credential
 * verification.
 *
 * <p>State is held in memory (a {@code clientId -> }{@link ClientRecord} map) and persisted to a
 * single JSON file via {@link JsonStore} on every mutation. All public methods are
 * {@code synchronized} so concurrent HTTP worker threads see a consistent registry — the registry
 * is small and writes are infrequent, so a single coarse lock is simplest and entirely adequate.
 *
 * <p>Secrets are generated here, hashed immediately with Argon2id, and the plaintext is returned
 * to the caller exactly once (at registration). The registry never stores or returns the raw
 * secret again.
 */
public final class ClientService {

  private final JsonStore<ClientRegistry> store;
  private final Argon2SecretHasher hasher;
  private final RandomIds ids;
  private final Clock clock;
  private final Map<String, ClientRecord> clients = new LinkedHashMap<>();

  /**
   * @param store  the backing JSON store.
   * @param hasher the Argon2id hasher for client secrets.
   * @param ids    the random id/secret generator.
   * @param clock  the clock used for {@code createdAt} timestamps.
   */
  public ClientService(final JsonStore<ClientRegistry> store, final Argon2SecretHasher hasher,
                       final RandomIds ids, final Clock clock) {
    this.store = store;
    this.hasher = hasher;
    this.ids = ids;
    this.clock = clock;
    if (store.exists()) {
      for (final ClientRecord record : store.load().clients()) {
        clients.put(record.clientId(), record);
      }
    }
  }

  /**
   * Register a new client with the given display name and authorization.
   *
   * @param displayName   optional human label (may be null).
   * @param authorization the grants/control-plane authority issued tokens will carry.
   * @return the new record plus the one-time plaintext secret (caller must zero the secret).
   */
  public synchronized Registration register(final String displayName, final Authorization authorization) {
    final String clientId = ids.newClientId();
    final char[] secret = ids.newClientSecret();
    final SecretHash secretHash = hasher.hash(secret);
    final ClientRecord record = new ClientRecord(
        clientId, displayName, secretHash,
        authorization == null ? Authorization.none() : authorization,
        true, clock.instant().getEpochSecond());
    clients.put(clientId, record);
    persist();
    return new Registration(record, secret);
  }

  /** @return all client records (without any secret material beyond the one-way hash). */
  public synchronized List<ClientRecord> list() {
    return new ArrayList<>(clients.values());
  }

  /** @return the record for the given clientId, if present. */
  public synchronized Optional<ClientRecord> get(final String clientId) {
    return Optional.ofNullable(clients.get(clientId));
  }

  /**
   * Remove a client from the registry.
   *
   * @param clientId the client to remove.
   * @return whether a client was removed.
   */
  public synchronized boolean remove(final String clientId) {
    final boolean removed = clients.remove(clientId) != null;
    if (removed) {
      persist();
    }
    return removed;
  }

  /**
   * Replace a client's authorization (the {@code PUT .../grants} admin operation).
   *
   * @param clientId      the client to update.
   * @param authorization the new authorization.
   * @return the updated record, or empty if no such client.
   */
  public synchronized Optional<ClientRecord> setAuthorization(final String clientId,
                                                              final Authorization authorization) {
    final ClientRecord existing = clients.get(clientId);
    if (existing == null) {
      return Optional.empty();
    }
    final ClientRecord updated = existing.withAuthorization(
        authorization == null ? Authorization.none() : authorization);
    clients.put(clientId, updated);
    persist();
    return Optional.of(updated);
  }

  /**
   * Verify a client's credentials for the client-credentials grant.
   *
   * <p>Returns the record only when the client exists, is enabled, and the secret matches. To
   * avoid an "unknown client vs. wrong secret" timing oracle, an unknown clientId still incurs a
   * hash verification against a throwaway hash, so both failure paths do comparable work. The
   * caller surfaces a single generic error regardless of which check failed.
   *
   * @param clientId the presented client id.
   * @param secret   the presented secret (caller should zero it afterwards).
   * @return the authenticated record, or empty on any failure.
   */
  public synchronized Optional<ClientRecord> authenticate(final String clientId, final char[] secret) {
    final ClientRecord record = clientId == null ? null : clients.get(clientId);
    if (record == null) {
      // Spend comparable effort on a dummy verification so timing does not reveal client existence.
      hasher.verify(secret, DUMMY_HASH);
      return Optional.empty();
    }
    final boolean ok = record.enabled() && hasher.verify(secret, record.secretHash());
    return ok ? Optional.of(record) : Optional.empty();
  }

  private void persist() {
    store.save(new ClientRegistry(new ArrayList<>(clients.values())));
  }

  /**
   * The result of registering a client: the stored record plus the one-time plaintext secret.
   *
   * @param client the persisted record.
   * @param secret the plaintext secret, shown to the operator exactly once; zero it after use.
   */
  public record Registration(ClientRecord client, char[] secret) {
  }

  // A fixed, well-formed hash used only to keep timing uniform for unknown-client lookups. Its
  // parameters are tiny on purpose; it never authenticates anything (no secret hashes to it).
  private static final SecretHash DUMMY_HASH = new SecretHash(
      SecretHash.ALGORITHM_ARGON2ID,
      "AAAAAAAAAAAAAAAAAAAAAA==",
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      8, 1, 1);
}
