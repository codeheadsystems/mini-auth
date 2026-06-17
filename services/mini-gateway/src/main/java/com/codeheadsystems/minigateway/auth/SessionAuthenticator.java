package com.codeheadsystems.minigateway.auth;

import com.codeheadsystems.minitoken.session.BrowserSession;
import com.codeheadsystems.minitoken.session.SessionService;
import java.util.List;
import java.util.Optional;

/**
 * Validates the <b>shared</b> mini-oidc SSO session: it reads the session cookie from the proxied
 * request and looks it up through the same {@link SessionService} (over the same {@code
 * sessions.json}) that mini-oidc writes to — one session mechanism, not two. A session carries no
 * scopes, so a session-authenticated caller satisfies {@code PUBLIC}/{@code AUTHENTICATED} routes but
 * not scope-gated ones (those want a bearer token).
 */
public final class SessionAuthenticator {

  private final SessionService sessions;

  public SessionAuthenticator(final SessionService sessions) {
    this.sessions = sessions;
  }

  /**
   * @param sessionCookieValue the value of the SSO session cookie from the proxied request (or null).
   * @return the authenticated caller, or empty if there is no live session.
   */
  public Optional<AuthenticatedUser> authenticate(final String sessionCookieValue) {
    return sessions.lookup(sessionCookieValue)
        .map(BrowserSession::subject)
        .map(subject -> new AuthenticatedUser(subject, false, List.of(), "session"));
  }
}
