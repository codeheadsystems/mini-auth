package com.codeheadsystems.miniconsole.pages;

import com.codeheadsystems.minitoken.model.AuditEntry;
import java.time.Instant;
import java.util.List;

/**
 * The Audit page: mini-idp's audit log (token issuance, key rotation, revocation). Audit entries
 * carry no secret material by construction — a token issuance references the token by its {@code jti},
 * never its serialized form — so the page renders them directly.
 */
public final class AuditPages {

  private AuditPages() {
  }

  /**
   * Render the audit log as a table (most-relevant columns: time, event, client, detail).
   *
   * @param entries the audit entries (oldest first, as the IDP returns them).
   * @param csrf    the CSRF token for the nav (escaped here).
   * @return a complete HTML document.
   */
  public static String list(final List<AuditEntry> entries, final String csrf) {
    final StringBuilder body = new StringBuilder();
    body.append("<p class=\"muted\">mini-idp's audit log — security events, no secrets.</p>");
    if (entries.isEmpty()) {
      body.append("<p>No audit entries yet.</p>");
    } else {
      body.append("<table><thead><tr><th>Time (UTC)</th><th>Event</th><th>Client</th>"
          + "<th>Detail</th></tr></thead><tbody>");
      for (final AuditEntry entry : entries) {
        body.append("<tr><td>").append(Layout.escape(Instant.ofEpochSecond(entry.at()).toString()))
            .append("</td><td>").append(Layout.escape(entry.event()))
            .append("</td><td>").append(Layout.escape(entry.clientId()))
            .append("</td><td>").append(Layout.escape(entry.detail())).append("</td></tr>");
      }
      body.append("</tbody></table>");
    }
    return Layout.page("Audit", Layout.authenticatedNav(csrf), body.toString());
  }

  /** The page shown when no mini-idp is configured. */
  public static String notConfigured(final String csrf) {
    final String body = "<p class=\"muted\">No mini-idp is configured. Set <code>--idp-url</code> "
        + "(and an IDP token) to view its audit log.</p>";
    return Layout.page("Audit", Layout.authenticatedNav(csrf), body);
  }

  /** The generic "could not read the audit log" page (no oracle — never says why). */
  public static String unavailable(final String csrf) {
    final String body = "<p class=\"warn\">The audit log is currently unavailable.</p>";
    return Layout.page("Audit", Layout.authenticatedNav(csrf), body);
  }
}
