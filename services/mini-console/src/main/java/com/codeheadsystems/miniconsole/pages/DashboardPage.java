package com.codeheadsystems.miniconsole.pages;

/**
 * The Dashboard — the landing page after sign-in.
 *
 * <p>It lists every family service with its wiring status. As of Slice 7 <b>all six downstream
 * services are live</b>: each row shows a real {@code health()} result (or "not configured" /
 * "unreachable") and links to its pages — mini-directory (Slice 1), mini-idp (Slice 3), mini-kms
 * (Slice 4), mini-ca (Slice 5), mini-oidc (Slice 6), and mini-gateway (Slice 7). No row fabricates
 * data: a service the operator did not wire honestly reads "not configured", per the family ethos.
 */
public final class DashboardPage {

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
   * @param oidcConfigured      whether a mini-oidc client is wired (links the row when true).
   * @param oidcStatus          the mini-oidc status line (already non-secret, escaped here).
   * @param gatewayConfigured   whether a mini-gateway client is wired (links the Harness when true).
   * @param gatewayStatus       the mini-gateway status line (already non-secret, escaped here).
   * @return a complete HTML document.
   */
  public static String render(final String boundAddress, final String csrf,
                              final boolean directoryConfigured, final String directoryStatus,
                              final boolean idpConfigured, final String idpStatus,
                              final boolean kmsConfigured, final String kmsStatus,
                              final boolean caConfigured, final String caStatus,
                              final boolean oidcConfigured, final String oidcStatus,
                              final boolean gatewayConfigured, final String gatewayStatus) {
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

    // mini-oidc: live as of Slice 6 (links to the Clients page).
    final String oidcName = oidcConfigured ? "<a href=\"/clients\">mini-oidc</a>" : "mini-oidc";
    rows.append("<tr><td>").append(oidcName).append("</td><td>")
        .append(Layout.escape(oidcStatus)).append("</td></tr>");

    // mini-gateway: live as of Slice 7 (its forward-auth exercise lives on the Harness page).
    final String gatewayName = gatewayConfigured ? "<a href=\"/harness\">mini-gateway</a>" : "mini-gateway";
    rows.append("<tr><td>").append(gatewayName).append("</td><td>")
        .append(Layout.escape(gatewayStatus)).append("</td></tr>");

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
