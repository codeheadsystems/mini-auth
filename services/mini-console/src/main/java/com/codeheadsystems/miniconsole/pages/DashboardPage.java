package com.codeheadsystems.miniconsole.pages;

import java.util.List;

/**
 * The Dashboard — the landing page after sign-in.
 *
 * <p>It lists every family service with its wiring status. As of Slice 1, <b>mini-directory is
 * live</b>: its row shows a real {@code health()} result (or "not configured" / "unreachable") and
 * links to the Identities pages. The other five services remain honest placeholders — "n/a — client
 * not wired yet (Slice N)" — calling nothing downstream and fabricating no data, until their slice
 * lands. This is the honest seam the family ethos requires.
 */
public final class DashboardPage {

  /** One not-yet-wired service row: display name and the slice number that wires its client. */
  private record Pending(String name, int slice) {
  }

  // The services still awaiting a client + page (see the roadmap in docs/design/mini-console.md).
  // mini-directory is no longer here — it is rendered live below.
  private static final List<Pending> PENDING = List.of(
      new Pending("mini-idp", 3),
      new Pending("mini-kms", 4),
      new Pending("mini-ca", 5),
      new Pending("mini-oidc", 6),
      new Pending("mini-gateway", 7));

  private DashboardPage() {
  }

  /**
   * @param boundAddress        the host:port the console is bound to (for the self-status line).
   * @param csrf                the CSRF token for the nav's sign-out form (escaped here).
   * @param directoryConfigured whether a mini-directory client is wired (links the row when true).
   * @param directoryStatus     the mini-directory status line (already non-secret, escaped here).
   * @return a complete HTML document.
   */
  public static String render(final String boundAddress, final String csrf,
                              final boolean directoryConfigured, final String directoryStatus) {
    final StringBuilder rows = new StringBuilder();

    // mini-directory: live as of Slice 1.
    final String name = directoryConfigured
        ? "<a href=\"/identities\">mini-directory</a>" : "mini-directory";
    rows.append("<tr><td>").append(name).append("</td><td>")
        .append(Layout.escape(directoryStatus)).append("</td></tr>");

    // The remaining services: honest placeholders.
    for (final Pending service : PENDING) {
      rows.append("<tr><td>").append(Layout.escape(service.name()))
          .append("</td><td class=\"muted\">n/a — client not wired yet (Slice ")
          .append(service.slice()).append(")</td></tr>");
    }

    final String body = """
        <p>mini-console is running on <code>$ADDR</code>, signed in as <code>console-admin</code>.</p>
        <p class="muted">This console adds no new authority — it is a client of admin surfaces that
        already exist.</p>
        <table>
          <thead><tr><th>Service</th><th>Status</th></tr></thead>
          <tbody>$ROWS</tbody>
        </table>
        """
        .replace("$ADDR", Layout.escape(boundAddress))
        .replace("$ROWS", rows.toString());

    return Layout.page("Dashboard", Layout.authenticatedNav(csrf), body);
  }
}
