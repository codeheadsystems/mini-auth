package com.codeheadsystems.miniconsole.server;

import com.codeheadsystems.miniconsole.pages.DashboardPage;
import com.codeheadsystems.miniconsole.pages.LoginPage;
import com.codeheadsystems.miniconsole.server.http.ApiException;
import com.codeheadsystems.miniconsole.server.http.HttpResponse;
import com.codeheadsystems.miniconsole.server.http.RequestContext;
import com.codeheadsystems.miniconsole.server.http.Router;
import java.util.Map;

/**
 * The Slice 0 route table: a public health check, a paste-the-token login that mints a session, an
 * authenticated Dashboard, and logout.
 *
 * <p>Auth model: the console token is the bootstrap credential, presented once by being pasted into
 * the {@code /login} form (constant-time compared, never logged). On success the console mints a
 * {@link ConsoleSession} and the {@link Cookies#SESSION} cookie carries it forward; every page but
 * {@code /login} and {@code /health} requires a valid session, else a browser-friendly 302 to
 * {@code /login} (no 401 body, no oracle). State-changing POSTs ({@code /login}, {@code /logout})
 * carry a double-submit {@link Csrf} token.
 */
public final class ConsoleHandlers {

  /** How long the short-lived CSRF cookie lives (long enough to submit the form). */
  private static final long CSRF_TTL_SECONDS = 3600;

  private final ConsoleSession session;
  private final AdminAuthenticator auth;
  private final Cookies cookies;
  private final Csrf csrf;
  private final long sessionTtlSeconds;

  /**
   * @param session           the console-login session store.
   * @param auth              the console-token constant-time comparator.
   * @param cookies           the cookie builder (console-specific names).
   * @param csrf              the double-submit CSRF helper.
   * @param sessionTtlSeconds the session cookie {@code Max-Age}.
   */
  public ConsoleHandlers(final ConsoleSession session, final AdminAuthenticator auth,
                         final Cookies cookies, final Csrf csrf, final long sessionTtlSeconds) {
    this.session = session;
    this.auth = auth;
    this.cookies = cookies;
    this.csrf = csrf;
    this.sessionTtlSeconds = sessionTtlSeconds;
  }

  /** @return the router with the Slice 0 routes registered. */
  public Router router() {
    return new Router()
        .route("GET", "/health", this::health)
        .route("GET", "/login", this::loginForm)
        .route("POST", "/login", this::loginSubmit)
        .route("GET", "/", this::dashboard)
        .route("POST", "/logout", this::logout);
  }

  /** Public liveness — no session required, no downstream calls. */
  private HttpResponse health(final RequestContext context) {
    return HttpResponse.json(200, Map.of("status", "ok"));
  }

  /** Render the sign-in form with a fresh CSRF token (set as the matching cookie). */
  private HttpResponse loginForm(final RequestContext context) {
    final String token = csrf.mint();
    return HttpResponse.html(LoginPage.render(token, false))
        .header("Set-Cookie", cookies.csrf(token, CSRF_TTL_SECONDS));
  }

  /**
   * Validate CSRF, then constant-time compare the pasted token. On success mint a session and
   * redirect to the Dashboard; on failure re-render the login page with a single generic message
   * (no oracle: a wrong token and a missing one are indistinguishable).
   */
  private HttpResponse loginSubmit(final RequestContext context) {
    final Map<String, String> form = context.formParams();
    if (!csrf.verify(context.cookie(Cookies.CSRF), form.get("csrf"))) {
      throw ApiException.badRequest("invalid or missing CSRF token");
    }
    if (!auth.matches(form.get("token"))) {
      // Re-render at 200 with a fresh CSRF token; reveal nothing about why it failed.
      final String token = csrf.mint();
      return HttpResponse.html(LoginPage.render(token, true))
          .header("Set-Cookie", cookies.csrf(token, CSRF_TTL_SECONDS));
    }
    final String sessionId = session.establish();
    return HttpResponse.redirect("/")
        .header("Set-Cookie", cookies.session(sessionId, sessionTtlSeconds));
  }

  /** The authenticated Dashboard; 302 to /login without a valid session. */
  private HttpResponse dashboard(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    // A fresh CSRF token for the logout form (double-submit).
    final String token = csrf.mint();
    final String host = context.header("Host");
    final String address = host != null ? host : "loopback";
    return HttpResponse.html(DashboardPage.render(address, token))
        .header("Set-Cookie", cookies.csrf(token, CSRF_TTL_SECONDS));
  }

  /** Destroy the session and clear the cookie; requires a valid session + CSRF. */
  private HttpResponse logout(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    if (!csrf.verify(context.cookie(Cookies.CSRF), context.formParams().get("csrf"))) {
      throw ApiException.badRequest("invalid or missing CSRF token");
    }
    session.end(context.cookie(Cookies.SESSION));
    return HttpResponse.redirect("/login")
        .header("Set-Cookie", cookies.clearSession());
  }

  /**
   * @return a 302-to-login response if there is no valid session, else null (caller proceeds). The
   *     browser-friendly equivalent of a 401 — no body, no detail.
   */
  private HttpResponse requireSession(final RequestContext context) {
    final String sessionId = context.cookie(Cookies.SESSION);
    if (sessionId == null || !session.isValid(sessionId)) {
      return HttpResponse.redirect("/login");
    }
    return null;
  }
}
