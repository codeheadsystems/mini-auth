package com.codeheadsystems.miniconsole.pages;

import com.codeheadsystems.minioidc.client.model.ClientSummary;
import com.codeheadsystems.minioidc.client.model.RegisteredClient;
import java.util.List;

/**
 * The Clients pages: list mini-oidc relying-party clients and register a new one. Server-rendered
 * HTML in the family style; HTML-escaped throughout.
 *
 * <p>With one exception — the {@link #registered} banner — these pages <b>never render a secret</b>:
 * the client list carries no secret material, and a newly minted confidential client's secret is
 * shown exactly once, on the registration result, and never again (it is not stored or re-fetchable).
 *
 * <p>Every state-changing form carries a hidden {@code csrf} field (double-submit), so a POST without
 * the matching cookie is rejected before any OP call.
 */
public final class ClientsPages {

  private ClientsPages() {
  }

  /**
   * The list view: the registered clients (never their secrets) and the register form.
   *
   * @param clients the registered clients.
   * @param csrf    the CSRF token threaded into the nav and the register form.
   * @return a complete HTML document.
   */
  public static String list(final List<ClientSummary> clients, final String csrf) {
    final StringBuilder body = new StringBuilder();
    body.append("<h2 style=\"font-size:1.1rem\">Registered clients</h2>");
    if (clients.isEmpty()) {
      body.append("<p class=\"muted\">No clients registered yet.</p>");
    } else {
      body.append("<table><thead><tr><th>Client id</th><th>Name</th><th>Type</th>"
          + "<th>Redirect URIs</th><th>Scopes</th></tr></thead><tbody>");
      for (final ClientSummary client : clients) {
        body.append("<tr><td><code>").append(Layout.escape(client.clientId())).append("</code></td><td>")
            .append(Layout.escape(client.name())).append("</td><td>")
            .append(client.confidential() ? "confidential" : "public").append("</td><td>")
            .append(Layout.escape(String.join(", ", client.redirectUris()))).append("</td><td>")
            .append(Layout.escape(String.join(" ", client.scopes()))).append("</td></tr>");
      }
      body.append("</tbody></table>");
    }
    body.append(registerForm(csrf));
    return Layout.page("Clients", Layout.authenticatedNav(csrf), body.toString());
  }

  /**
   * The one-time client-secret banner — the ONLY page that ever renders a client secret, and only on
   * the registration result. The secret is not stored and not re-fetchable; navigating away loses it.
   * A public (PKCE-only) client has no secret, so none is shown.
   *
   * @param client the freshly registered client (carries the one-time secret for a confidential one).
   * @param csrf   the CSRF token for the nav.
   * @return a complete HTML document.
   */
  public static String registered(final RegisteredClient client, final String csrf) {
    final StringBuilder banner = new StringBuilder();
    banner.append("<div class=\"banner\"><h2>Client registered</h2>");
    banner.append("<p>Client id: <code>").append(Layout.escape(client.clientId())).append("</code></p>");
    if (client.clientSecret() != null) {
      banner.append("<p class=\"warn\">Copy this secret now — it will not be shown again.</p>");
      banner.append("<p>Client secret: <code class=\"secret-value\">")
          .append(Layout.escape(client.clientSecret())).append("</code></p>");
    } else {
      banner.append("<p class=\"muted\">This is a public (PKCE-only) client — it has no secret.</p>");
    }
    banner.append("<p><a href=\"/clients\">Done</a></p></div>");
    return Layout.page("Client registered", Layout.authenticatedNav(csrf), banner.toString());
  }

  /** The page shown when no mini-oidc client is configured. */
  public static String notConfigured(final String csrf) {
    final String body = "<p class=\"muted\">mini-oidc is not configured. Set <code>--oidc-url</code> "
        + "and an OIDC admin token to manage relying-party clients.</p>";
    return Layout.page("Clients", Layout.authenticatedNav(csrf), body);
  }

  /** The generic page shown when an OP call fails (no oracle — a refused token and an unreachable OP look alike). */
  public static String unavailable(final String csrf) {
    return Layout.page("Clients", Layout.authenticatedNav(csrf),
        "<p class=\"muted\">mini-oidc is unavailable.</p>");
  }

  private static String registerForm(final String csrf) {
    return """
        <h2 style="font-size:1.1rem;margin-top:2rem">Register a client</h2>
        <form method="post" action="/clients">
          <input type="hidden" name="csrf" value="$CSRF">
          <p><label>Name<br><input type="text" name="name" autocomplete="off"></label></p>
          <p><label>Redirect URIs (one per line)<br><textarea name="redirectUris" rows="3"></textarea></label></p>
          <p><label>Scopes (space-separated)<br><input type="text" name="scopes" value="openid" autocomplete="off"></label></p>
          <p><label><input type="checkbox" name="confidential" value="true"> Confidential (mint a client secret)</label></p>
          <button type="submit">Register</button>
        </form>
        """.replace("$CSRF", Layout.escape(csrf));
  }
}
