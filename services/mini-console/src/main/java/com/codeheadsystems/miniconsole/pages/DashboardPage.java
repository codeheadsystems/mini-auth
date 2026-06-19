package com.codeheadsystems.miniconsole.pages;

import java.util.List;

/**
 * The Dashboard — the landing page after sign-in.
 *
 * <p>It lists every family service with its wiring status. As of Slice 3, <b>mini-directory and
 * mini-idp are live</b>: each row shows a real {@code health()} result (or "not configured" /
 * "unreachable") and links to its pages. The other four services remain honest placeholders — "n/a —
 * client not wired yet (Slice N)" — calling nothing downstream and fabricating no data, until their
 * slice lands. This is the honest seam the family ethos requires.
 */
public final class DashboardPage {

  /** One not-yet-wired service row: display name and the slice number that wires its client. */
  private record Pending(String name, int slice) {
  }

  // The services still awaiting a client + page (see the roadmap in docs/design/mini-console.md).
  // mini-directory (Slice 1), mini-idp (Slice 3), mini-kms (Slice 4), and mini-ca (Slice 5) are
  // rendered live below.
  private static final List<Pending> PENDING = List.of(
      new Pending("mini-oidc", 6),
      new Pending("mini-gateway", 7));

  private DashboardPage() {
  }

  /**
   * @param boundAddress        the host:port the console is bound to (for the self-status line).
   * @param csrf                the CSRF token for the nav's sign-out form (escaped here).
   * @param directoryConfigured whether a mini-directory client is wired (links the row when true).
   * @param directoryStatus     the mini-directory status line (already non-secret, escaped here).
   * @param idpConfigured       whether a mini-idp client is wired (links the row when true).
   * @param idpStatus           the mini-idp status line (already non-secret, escaped here).
   * @param kmsConfigured       whether a mini-kms client is wired (links the row when true).
   * @param kmsStatus           the mini-kms status line (already non-secret, escaped here).
   * @param caConfigured        whether a mini-ca client is wired (links the row when true).
   * @param caStatus            the mini-ca status line (already non-secret, escaped here).
   * @return a complete HTML document.
   */
  public static String render(final String boundAddress, final String csrf,
                              final boolean directoryConfigured, final String directoryStatus,
                              final boolean idpConfigured, final String idpStatus,
                              final boolean kmsConfigured, final String kmsStatus,
                              final boolean caConfigured, final String caStatus) {
    final StringBuilder rows = new StringBuilder();

    // mini-directory: live as of Slice 1.
    final String directoryName = directoryConfigured
        ? "<a href=\"/identities\">mini-directory</a>" : "mini-directory";
    rows.append("<tr><td>").append(directoryName).append("</td><td>")
        .append(Layout.escape(directoryStatus)).append("</td></tr>");

    // mini-idp: live as of Slice 3 (links to the Audit log + the Harness).
    final String idpName = idpConfigured
        ? "<a href=\"/audit\">mini-idp</a>" : "mini-idp";
    rows.append("<tr><td>").append(idpName).append("</td><td>")
        .append(Layout.escape(idpStatus)).append("</td></tr>");

    // mini-kms: live as of Slice 4 (links to the Keys page).
    final String kmsName = kmsConfigured ? "<a href=\"/keys\">mini-kms</a>" : "mini-kms";
    rows.append("<tr><td>").append(kmsName).append("</td><td>")
        .append(Layout.escape(kmsStatus)).append("</td></tr>");

    // mini-ca: live as of Slice 5 (links to the Certificates page).
    final String caName = caConfigured ? "<a href=\"/certificates\">mini-ca</a>" : "mini-ca";
    rows.append("<tr><td>").append(caName).append("</td><td>")
        .append(Layout.escape(caStatus)).append("</td></tr>");

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
