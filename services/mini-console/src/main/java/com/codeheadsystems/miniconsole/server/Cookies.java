package com.codeheadsystems.miniconsole.server;

/**
 * Builds the {@code Set-Cookie} values for the console-login session and the CSRF token, with the
 * security attributes the console relies on.
 *
 * <ul>
 *   <li><b>HttpOnly</b> — JavaScript can never read the session id (XSS can't exfiltrate it).</li>
 *   <li><b>SameSite=Lax</b> — withheld from cross-site POSTs (CSRF defense in depth, alongside the
 *       per-form double-submit CSRF token).</li>
 *   <li><b>Secure</b> — set when configured (behind TLS). Off by default so the loopback HTTP flow
 *       works; any LAN exposure MUST run behind a TLS reverse proxy with this enabled.</li>
 *   <li><b>Path=/</b>, and a {@code Max-Age} matching the session lifetime.</li>
 * </ul>
 *
 * <p>Adapted from mini-oidc's {@code Cookies}. <b>The one deliberate change:</b> the cookie name is
 * the console-specific {@code mini-console-session}, NOT mini-token's shared
 * {@code SessionService.DEFAULT_COOKIE_NAME} ({@code "mioidc_session"}) — so a console cookie can
 * never collide with a co-hosted mini-oidc SSO session cookie on a shared host.
 */
public final class Cookies {

  /** The console-login session cookie name — distinct from the family SSO cookie. */
  public static final String SESSION = "mini-console-session";

  /** The double-submit CSRF cookie name (paired with a matching hidden form field). */
  public static final String CSRF = "mini-console-csrf";

  private final boolean secure;

  public Cookies(final boolean secure) {
    this.secure = secure;
  }

  /** @return a {@code Set-Cookie} value establishing the session for {@code maxAgeSeconds}. */
  public String session(final String value, final long maxAgeSeconds) {
    return build(SESSION, value, maxAgeSeconds);
  }

  /** @return a {@code Set-Cookie} value that immediately clears the session cookie (logout). */
  public String clearSession() {
    return build(SESSION, "", 0);
  }

  /** @return a {@code Set-Cookie} value carrying a fresh CSRF token (short-lived). */
  public String csrf(final String value, final long maxAgeSeconds) {
    return build(CSRF, value, maxAgeSeconds);
  }

  private String build(final String name, final String value, final long maxAge) {
    final StringBuilder cookie = new StringBuilder()
        .append(name).append('=').append(value)
        .append("; Path=/; HttpOnly; SameSite=Lax; Max-Age=").append(maxAge);
    if (secure) {
      cookie.append("; Secure");
    }
    return cookie.toString();
  }
}
