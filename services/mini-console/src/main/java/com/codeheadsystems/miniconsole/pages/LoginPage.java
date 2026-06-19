package com.codeheadsystems.miniconsole.pages;

/**
 * The console sign-in page: a single form into which the operator pastes the bootstrap console
 * token.
 *
 * <p>Modeled on mini-oidc's {@code LoginPages.login} but drastically simpler — there is no WebAuthn
 * ceremony, just a password-typed field POSTed to {@code /login}. The token travels in the POST body
 * (never a URL or header), so it never lands in the access log. A hidden CSRF field carries the
 * double-submit token. On a failed attempt the page shows a single generic message — it never
 * distinguishes a wrong token from a missing one (no oracle).
 */
public final class LoginPage {

  private LoginPage() {
  }

  /**
   * @param csrf  the freshly-minted CSRF token to embed (also set as the {@code mini-console-csrf}
   *              cookie by the handler); escaped here.
   * @param error whether to show the generic sign-in-failed message.
   * @return a complete HTML document.
   */
  public static String render(final String csrf, final boolean error) {
    final String body = """
        <p>Sign in with your console admin token.</p>
        $ERR
        <form method="post" action="/login">
          <input type="hidden" name="csrf" value="$CSRF">
          <p><input type="password" name="token" placeholder="console admin token" autofocus></p>
          <p><button type="submit">Sign in</button></p>
        </form>
        """
        .replace("$ERR", error ? "<p class=\"err\">Sign-in failed.</p>" : "")
        .replace("$CSRF", Layout.escape(csrf));
    return Layout.page("Sign in", "", body);
  }
}
