package com.codeheadsystems.minioidc.service;

import com.codeheadsystems.minioidc.model.BrowserSession;
import com.codeheadsystems.minioidc.util.Tokens;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages browser SSO sessions: the record that a browser has an authenticated human behind it, so
 * a returning {@code /authorize} needs no re-authentication until the session expires.
 *
 * <p>The session lifetime is deliberately <b>independent of any token TTL</b> — tokens are minted
 * short and refreshed, while this governs how long the human stays signed in to the OP. Only the
 * SHA-256 of the cookie value is stored, so the in-memory store holds no replayable cookie. Sessions
 * are in-memory (a restart signs everyone out — acceptable for this educational service).
 */
public final class SessionService {

  private final Clock clock;
  private final Tokens tokens;
  private final Duration sessionTtl;
  private final Map<String, BrowserSession> byIdHash = new ConcurrentHashMap<>();

  public SessionService(final Clock clock, final Tokens tokens, final Duration sessionTtl) {
    this.clock = clock;
    this.tokens = tokens;
    this.sessionTtl = sessionTtl;
  }

  /**
   * Create a session for a just-authenticated human.
   *
   * @param subject  the authenticated principal id.
   * @param authTime when the human authenticated (epoch seconds).
   * @return the clear session id to set as a cookie (its hash is what is stored).
   */
  public String create(final String subject, final long authTime) {
    final String sessionId = tokens.newSessionId();
    final long now = clock.instant().getEpochSecond();
    byIdHash.put(Tokens.sha256(sessionId),
        new BrowserSession(Tokens.sha256(sessionId), subject, authTime, now + sessionTtl.toSeconds()));
    return sessionId;
  }

  /** @return the live session for this cookie value, if present and unexpired. */
  public Optional<BrowserSession> lookup(final String sessionId) {
    if (sessionId == null || sessionId.isBlank()) {
      return Optional.empty();
    }
    final String idHash = Tokens.sha256(sessionId);
    final BrowserSession session = byIdHash.get(idHash);
    if (session == null) {
      return Optional.empty();
    }
    if (clock.instant().getEpochSecond() >= session.expiresAt()) {
      byIdHash.remove(idHash);
      return Optional.empty();
    }
    return Optional.of(session);
  }

  /** Destroy the session behind this cookie value (single logout). */
  public void destroy(final String sessionId) {
    if (sessionId != null && !sessionId.isBlank()) {
      byIdHash.remove(Tokens.sha256(sessionId));
    }
  }

  /** @return the configured session lifetime. */
  public Duration sessionTtl() {
    return sessionTtl;
  }
}
