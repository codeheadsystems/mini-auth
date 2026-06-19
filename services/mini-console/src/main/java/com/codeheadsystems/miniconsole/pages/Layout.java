package com.codeheadsystems.miniconsole.pages;

/**
 * The shared HTML chrome for every console page: a minimal, dependency-free document with a nav bar.
 *
 * <p>Hand-rolled in the spirit of mini-oidc's {@code LoginPages} — no template engine, no JS build,
 * no client-side framework. Every dynamic value a page interpolates MUST be passed through
 * {@link #escape} first; a page <b>never</b> renders a secret (the console holds tokens, but no page
 * shows them).
 */
public final class Layout {

  private Layout() {
  }

  /**
   * Wrap a page body in the shared document chrome.
   *
   * @param title   the page title (shown in {@code <title>} and the header; escaped).
   * @param navHtml already-built nav markup (e.g. a logout form), or empty string for the login page.
   * @param bodyHtml the already-built, already-escaped page body markup.
   * @return a complete HTML document.
   */
  public static String page(final String title, final String navHtml, final String bodyHtml) {
    return """
        <!DOCTYPE html>
        <html lang="en"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>$TITLE — mini-console</title>
        <style>
          body { font-family: system-ui, sans-serif; max-width: 52rem; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
          header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #ddd; padding-bottom: .5rem; }
          h1 { font-size: 1.3rem; margin: 0; }
          table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
          th, td { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #eee; }
          .muted { color: #888; }
          button { font: inherit; padding: .4rem .8rem; cursor: pointer; }
          input[type=password], input[type=text], textarea { font: inherit; padding: .4rem; width: 100%; box-sizing: border-box; }
          .err { color: #b00020; }
          .banner { border: 2px solid #b00020; border-radius: .4rem; padding: 1rem; margin-top: 1rem; }
          .warn { color: #b00020; font-weight: 600; }
          .secret-value { background: #f3f3f3; padding: .2rem .4rem; word-break: break-all; }
        </style></head>
        <body>
        <header><h1>$TITLE</h1>$NAV</header>
        $BODY
        </body></html>
        """
        .replace("$TITLE", escape(title))
        .replace("$NAV", navHtml)
        .replace("$BODY", bodyHtml);
  }

  /**
   * The nav shown on every authenticated page: links to the Dashboard and Identities, plus the
   * CSRF-protected sign-out form. Passed as the {@code navHtml} to {@link #page}.
   *
   * @param csrf the CSRF token for the sign-out form (escaped here).
   * @return the nav markup.
   */
  public static String authenticatedNav(final String csrf) {
    return """
        <nav style="display:flex;gap:1rem;align-items:center">
          <a href="/">Dashboard</a>
          <a href="/identities">Identities</a>
          <a href="/audit">Audit</a>
          <a href="/harness">Harness</a>
          <form method="post" action="/logout" style="margin:0">
            <input type="hidden" name="csrf" value="$CSRF">
            <button type="submit">Sign out</button>
          </form>
        </nav>
        """.replace("$CSRF", escape(csrf));
  }

  /**
   * HTML-escape a value for safe interpolation into element text or an attribute. Copied verbatim
   * from mini-oidc's {@code LoginPages.escape}.
   *
   * @param value the raw value (may be null → empty string).
   * @return the entity-escaped value.
   */
  public static String escape(final String value) {
    if (value == null) {
      return "";
    }
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("\"", "&quot;").replace("'", "&#39;");
  }
}
