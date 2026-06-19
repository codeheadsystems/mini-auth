package com.codeheadsystems.miniconsole.pages;

import java.util.List;

/**
 * The Dashboard — the one authenticated page in Slice 0.
 *
 * <p>It proves the server renders an authenticated page while being <b>honest about what is not yet
 * built</b>: it calls nothing downstream and fabricates no health data. Each family service is shown
 * with a literal "n/a — client not wired yet" status plus the slice that will wire it. As later
 * slices add a client library, its row flips from this placeholder to a real {@code health()} result.
 * This is the honest seam the family ethos requires — a placeholder that says so.
 */
public final class DashboardPage {

  /** One service row: display name and the slice number that wires its client. */
  private record Service(String name, int slice) {
  }

  // The six downstream services and the slice where each gets a client + page (see the roadmap in
  // docs/design/mini-console.md). None are wired in Slice 0.
  private static final List<Service> SERVICES = List.of(
      new Service("mini-directory", 1),
      new Service("mini-idp", 3),
      new Service("mini-kms", 4),
      new Service("mini-ca", 5),
      new Service("mini-oidc", 6),
      new Service("mini-gateway", 7));

  private DashboardPage() {
  }

  /**
   * @param boundAddress the host:port the console is bound to (for the self-status line).
   * @param csrf         the CSRF token for the logout form (escaped here).
   * @return a complete HTML document.
   */
  public static String render(final String boundAddress, final String csrf) {
    final StringBuilder rows = new StringBuilder();
    for (final Service service : SERVICES) {
      rows.append("<tr><td>").append(Layout.escape(service.name()))
          .append("</td><td class=\"muted\">n/a — client not wired yet (Slice ")
          .append(service.slice()).append(")</td></tr>");
    }

    final String nav = """
        <form method="post" action="/logout" style="margin:0">
          <input type="hidden" name="csrf" value="$CSRF">
          <button type="submit">Sign out</button>
        </form>
        """.replace("$CSRF", Layout.escape(csrf));

    final String body = """
        <p>mini-console is running on <code>$ADDR</code>, signed in as <code>console-admin</code>.</p>
        <p class="muted">This console adds no new authority — it is a client of admin surfaces that
        already exist. The data layer below is intentionally stubbed in this slice.</p>
        <table>
          <thead><tr><th>Service</th><th>Status</th></tr></thead>
          <tbody>$ROWS</tbody>
        </table>
        """
        .replace("$ADDR", Layout.escape(boundAddress))
        .replace("$ROWS", rows.toString());

    return Layout.page("Dashboard", nav, body);
  }
}
