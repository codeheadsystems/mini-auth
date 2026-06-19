package com.codeheadsystems.minigateway.client;

/**
 * The inputs for a {@code /verify} call — exactly what a reverse proxy forwards: the original
 * request's method and URI (sent as {@code X-Forwarded-Method} / {@code X-Forwarded-Uri}), the
 * caller's own credentials (a bearer access token and/or the shared SSO session cookie), and whether
 * the caller is a browser (so the gateway can choose a 302-to-login over a 401).
 *
 * <p>The {@code bearerToken} and {@code cookie} are the <i>client's</i> credentials being exercised,
 * not an operator admin token; they are sent on the single call and never logged.
 *
 * @param method      the original request method (e.g. {@code GET}); blank defaults to {@code GET}.
 * @param uri         the original request URI/path (e.g. {@code /admin/panel}); blank defaults to {@code /}.
 * @param bearerToken a bearer access token to present, or null (no {@code Authorization} header).
 * @param cookie      a raw {@code Cookie} header value to present (e.g. the SSO session cookie), or null.
 * @param browser     whether to identify as a browser ({@code Accept: text/html}), so an
 *                    unauthenticated request elicits a 302-to-login rather than a 401.
 */
public record VerifyRequest(String method, String uri, String bearerToken, String cookie,
                            boolean browser) {

  /** A no-credential probe (the unauthenticated branch). */
  public static VerifyRequest anonymous(final String method, final String uri, final boolean browser) {
    return new VerifyRequest(method, uri, null, null, browser);
  }

  /** A probe carrying a bearer access token (the API-client branch). */
  public static VerifyRequest withBearer(final String method, final String uri, final String bearerToken) {
    return new VerifyRequest(method, uri, bearerToken, null, false);
  }
}
