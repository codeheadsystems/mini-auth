package com.codeheadsystems.minioidc.server;

/**
 * Builds the {@code Set-Cookie} value for the browser SSO session cookie, with the security
 * attributes the OP relies on.
 *
 * <ul>
 *   <li><b>HttpOnly</b> — JavaScript can never read the session id (XSS can't exfiltrate it).</li>
 *   <li><b>SameSite=Lax</b> — the cookie rides the top-level GET redirect back to {@code
 *       /authorize} (the SSO flow), but is withheld from cross-site POSTs (CSRF defense in depth,
 *       alongside the per-form CSRF token).</li>
 *   <li><b>Secure</b> — set when configured (behind TLS). It is off by default so the loopback HTTP
 *       dev flow works; any LAN exposure MUST run behind a TLS reverse proxy with this enabled.</li>
 *   <li><b>Path=/</b>, and a {@code Max-Age} matching the session lifetime.</li>
 * </ul>
 */
public final class Cookies {

  /** The browser SSO session cookie name. */
  public static final String SESSION = "mioidc_session";

  private final boolean secure;

  public Cookies(final boolean secure) {
    this.secure = secure;
  }

  /** @return a {@code Set-Cookie} value establishing the session for {@code maxAgeSeconds}. */
  public String session(final String value, final long maxAgeSeconds) {
    return build(value, maxAgeSeconds);
  }

  /** @return a {@code Set-Cookie} value that immediately clears the session cookie (logout). */
  public String clearSession() {
    return build("", 0);
  }

  private String build(final String value, final long maxAge) {
    final StringBuilder cookie = new StringBuilder()
        .append(SESSION).append('=').append(value)
        .append("; Path=/; HttpOnly; SameSite=Lax; Max-Age=").append(maxAge);
    if (secure) {
      cookie.append("; Secure");
    }
    return cookie.toString();
  }
}
