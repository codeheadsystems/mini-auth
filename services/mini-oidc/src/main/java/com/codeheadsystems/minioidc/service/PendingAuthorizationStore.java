package com.codeheadsystems.minioidc.service;

import com.codeheadsystems.minioidc.model.PendingAuthorization;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Holds validated {@code /authorize} requests server-side while the human logs in and consents.
 *
 * <p>Short-lived and in-memory: an interrupted login simply expires. Keyed by the opaque
 * {@code requestId} the login/consent UI carries (the real request parameters never round-trip
 * through the browser, so they cannot be tampered with).
 */
public final class PendingAuthorizationStore {

  private final Clock clock;
  private final Duration ttl;
  private final Map<String, PendingAuthorization> byId = new ConcurrentHashMap<>();

  public PendingAuthorizationStore(final Clock clock, final Duration ttl) {
    this.clock = clock;
    this.ttl = ttl;
  }

  /** Park a pending authorization. */
  public void put(final PendingAuthorization pending) {
    byId.put(pending.requestId(), pending);
  }

  /** @return the pending authorization if present and not expired. */
  public Optional<PendingAuthorization> get(final String requestId) {
    final PendingAuthorization pending = requestId == null ? null : byId.get(requestId);
    if (pending == null) {
      return Optional.empty();
    }
    if (clock.instant().getEpochSecond() - pending.createdAt() > ttl.toSeconds()) {
      byId.remove(requestId);
      return Optional.empty();
    }
    return Optional.of(pending);
  }

  /** Remove a pending authorization (once consent completes). */
  public void remove(final String requestId) {
    byId.remove(requestId);
  }
}
