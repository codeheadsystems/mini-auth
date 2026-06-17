package com.codeheadsystems.minitoken.session;

import com.codeheadsystems.minitoken.store.DocumentStore;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * The shared browser-SSO-session mechanism: create / look up / destroy {@link BrowserSession}s over
 * a {@link DocumentStore} (the family's persistence SPI). Both mini-oidc and a forward-auth gateway
 * construct one of these over the SAME {@code sessions.json} file, so they share one session store
 * rather than inventing a second — mini-oidc is the writer (create on login, destroy on logout),
 * the gateway a reader (look up on every proxied request).
 *
 * <p>The cookie value is a 256-bit random id; only its SHA-256 is persisted, so the store holds no
 * replayable cookie. Reads never write (a gateway must not mutate the store), so expired sessions
 * are filtered out on read and physically pruned only when the writer next persists. All methods are
 * {@code synchronized}; the store is the single source of truth (no in-memory cache), so a session
 * created by one process is immediately visible to another reading the same file.
 */
public final class SessionService {

  /** The default SSO session cookie name shared across the family. */
  public static final String DEFAULT_COOKIE_NAME = "mioidc_session";

  private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

  private final DocumentStore<Sessions> store;
  private final Clock clock;
  private final Duration sessionTtl;
  private final SecureRandom secureRandom = new SecureRandom();

  /**
   * @param store      the backing document store (e.g. an atomic-{@code 0600} JSON file).
   * @param clock      the clock for expiry.
   * @param sessionTtl the lifetime new sessions are created with.
   */
  public SessionService(final DocumentStore<Sessions> store, final Clock clock, final Duration sessionTtl) {
    this.store = store;
    this.clock = clock;
    this.sessionTtl = sessionTtl;
  }

  /**
   * Create a session for a just-authenticated human.
   *
   * @param subject  the authenticated principal id.
   * @param authTime when the human authenticated (epoch seconds).
   * @return the clear session id to set as a cookie (only its hash is stored).
   */
  public synchronized String create(final String subject, final long authTime) {
    final String sessionId = randomId();
    final long now = clock.instant().getEpochSecond();
    final List<BrowserSession> live = unexpired(now);
    live.add(new BrowserSession(sha256(sessionId), subject, authTime, now + sessionTtl.toSeconds()));
    store.save(new Sessions(live));
    return sessionId;
  }

  /** @return the live session for this cookie value, if present and unexpired (no write). */
  public synchronized Optional<BrowserSession> lookup(final String sessionId) {
    if (sessionId == null || sessionId.isBlank()) {
      return Optional.empty();
    }
    final String idHash = sha256(sessionId);
    final long now = clock.instant().getEpochSecond();
    for (final BrowserSession session : load()) {
      if (session.idHash().equals(idHash) && now < session.expiresAt()) {
        return Optional.of(session);
      }
    }
    return Optional.empty();
  }

  /** Destroy the session behind this cookie value (single logout). */
  public synchronized void destroy(final String sessionId) {
    if (sessionId == null || sessionId.isBlank()) {
      return;
    }
    final String idHash = sha256(sessionId);
    final List<BrowserSession> remaining = unexpired(clock.instant().getEpochSecond());
    remaining.removeIf(session -> session.idHash().equals(idHash));
    store.save(new Sessions(remaining));
  }

  private List<BrowserSession> load() {
    return store.exists() ? new ArrayList<>(store.load().sessions()) : new ArrayList<>();
  }

  private List<BrowserSession> unexpired(final long now) {
    final List<BrowserSession> live = new ArrayList<>();
    for (final BrowserSession session : load()) {
      if (now < session.expiresAt()) {
        live.add(session);
      }
    }
    return live;
  }

  private String randomId() {
    final byte[] bytes = new byte[32];
    secureRandom.nextBytes(bytes);
    return BASE64URL.encodeToString(bytes);
  }

  /** @return the unpadded base64url SHA-256 of a value — the at-rest form of the session id. */
  public static String sha256(final String value) {
    try {
      return BASE64URL.encodeToString(
          MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (final NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }
}
