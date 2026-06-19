package com.codeheadsystems.miniconsole.server;

import com.codeheadsystems.miniconsole.store.JsonStore;
import com.codeheadsystems.minitoken.session.SessionService;
import com.codeheadsystems.minitoken.session.Sessions;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;

/**
 * The console-login session: a thin wrapper over mini-token's {@link SessionService} so the console
 * reuses the family's proven, file-backed session mechanism rather than inventing a second one.
 *
 * <p>Two deliberate differences from mini-oidc's use of the same machinery:
 * <ul>
 *   <li>It is backed by the console's <b>own</b> store ({@code console-sessions.json}), a separate
 *       namespace from the family SSO session file — the console is the sole writer of its store.</li>
 *   <li>The session cookie uses the console-specific {@link Cookies#SESSION} name, never the shared
 *       SSO cookie, so the two can't collide on a co-hosted setup.</li>
 * </ul>
 *
 * <p>The console has a single principal: the operator who presented the bootstrap console token. We
 * record it as {@code "console-admin"} (a fixed subject — no identity data is stored).
 */
public final class ConsoleSession {

  /** The fixed subject recorded for the authenticated operator (no identity data is stored). */
  public static final String SUBJECT = "console-admin";

  private final SessionService sessions;
  private final Clock clock;

  /**
   * @param dataDir    the directory the {@code console-sessions.json} store lives in.
   * @param clock      the clock for session expiry.
   * @param sessionTtl the lifetime new console sessions are created with.
   */
  public ConsoleSession(final Path dataDir, final Clock clock, final Duration sessionTtl) {
    this.sessions = new SessionService(
        new JsonStore<>(dataDir.resolve("console-sessions.json"), Sessions.class), clock, sessionTtl);
    this.clock = clock;
  }

  /** @return a fresh session id to set as the {@code mini-console-session} cookie. */
  public String establish() {
    return sessions.create(SUBJECT, clock.instant().getEpochSecond());
  }

  /** @return whether the cookie value names a live, unexpired console session. */
  public boolean isValid(final String sessionId) {
    return sessions.lookup(sessionId).isPresent();
  }

  /** Destroy the session behind this cookie value (logout). */
  public void end(final String sessionId) {
    sessions.destroy(sessionId);
  }
}
