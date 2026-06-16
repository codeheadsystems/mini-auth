package com.codeheadsystems.miniidp.service;

import com.codeheadsystems.miniidp.model.Revocation;
import com.codeheadsystems.miniidp.store.JsonStore;
import com.codeheadsystems.miniidp.store.StoreDocuments.Revocations;
import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The revocation denylist: token ids ({@code jti}) an operator has killed before their natural
 * expiry.
 *
 * <p>Short TTLs are the primary control — tokens mostly just expire — so this denylist stays
 * small. A verifier (mini-kms) is expected to poll {@link #activeDenylist()} and reject any token
 * whose {@code jti} appears. Entries are pruned once the revoked token's own {@code exp} has
 * passed, since after that the token fails on expiry grounds regardless.
 *
 * <p>Persisted via {@link JsonStore}; methods are {@code synchronized}.
 */
public final class RevocationService {

  private final JsonStore<Revocations> store;
  private final Clock clock;
  private final Map<String, Revocation> byJti = new LinkedHashMap<>();

  /**
   * @param store the backing JSON store.
   * @param clock the clock used for revocation timestamps and pruning.
   */
  public RevocationService(final JsonStore<Revocations> store, final Clock clock) {
    this.store = store;
    this.clock = clock;
    if (store.exists()) {
      for (final Revocation revocation : store.load().revocations()) {
        byJti.put(revocation.jti(), revocation);
      }
    }
  }

  /**
   * Revoke a token id.
   *
   * @param jti       the token id to revoke.
   * @param expiresAt the revoked token's own expiry (epoch seconds), after which the entry is
   *                  prunable.
   * @param reason    optional operator reason (may be null).
   * @return the recorded revocation.
   */
  public synchronized Revocation revoke(final String jti, final long expiresAt, final String reason) {
    if (jti == null || jti.isBlank()) {
      throw new IllegalArgumentException("jti must not be blank");
    }
    final Revocation revocation = new Revocation(jti, clock.instant().getEpochSecond(), expiresAt, reason);
    byJti.put(jti, revocation);
    prune();
    persist();
    return revocation;
  }

  /** @return whether the given token id is currently revoked (and not yet pruned). */
  public synchronized boolean isRevoked(final String jti) {
    prune();
    return jti != null && byJti.containsKey(jti);
  }

  /** @return the current active denylist (expired entries pruned), for a verifier to poll. */
  public synchronized List<Revocation> activeDenylist() {
    prune();
    return new ArrayList<>(byJti.values());
  }

  private void prune() {
    final long now = clock.instant().getEpochSecond();
    byJti.values().removeIf(revocation -> revocation.expiresAt() < now);
  }

  private void persist() {
    store.save(new Revocations(new ArrayList<>(byJti.values())));
  }
}
