package com.codeheadsystems.miniconsole.pages;

import com.codeheadsystems.minica.client.model.Certificate;
import com.codeheadsystems.minica.client.model.IssuanceLogEntry;
import com.codeheadsystems.minica.client.model.RevocationEntry;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The Certificates pages: mini-ca's trust anchor, issuance log, and revocation list, plus the forms to
 * issue, renew, and revoke a certificate.
 *
 * <p>Certificates and CSRs are public material — there are no secrets to redact here; the CA never
 * returns a private key. Every state-changing control is a CSRF-guarded POST, and revocation (a
 * destructive op) goes through a confirm step. The page renders only what the CA returns.
 */
public final class CertificatesPages {

  private CertificatesPages() {
  }

  /** The Certificates landing page: CA root, issue/renew forms, the issuance log, the revocations. */
  public static String overview(final String caPem, final List<IssuanceLogEntry> log,
                                final List<RevocationEntry> revocations, final String csrf) {
    final Set<String> revoked =
        revocations.stream().map(RevocationEntry::serial).collect(Collectors.toSet());
    final StringBuilder body = new StringBuilder();

    body.append("<details><summary>CA root certificate (PEM)</summary><pre class=\"secret-value\">")
        .append(Layout.escape(caPem)).append("</pre></details>");

    body.append("<h2 style=\"font-size:1.1rem;margin-top:1.5rem\">Issue a certificate</h2>");
    body.append(csrForm("/certificates/issue", "Issue", false, csrf));

    body.append("<h2 style=\"font-size:1.1rem;margin-top:1.5rem\">Renew a certificate</h2>");
    body.append(csrForm("/certificates/renew", "Renew", true, csrf));

    body.append("<h2 style=\"font-size:1.1rem;margin-top:1.5rem\">Issuance log</h2>");
    body.append(logTable(log, revoked));

    body.append("<h2 style=\"font-size:1.1rem;margin-top:1.5rem\">Revocation list</h2>");
    body.append(revocationTable(revocations));

    return Layout.page("Certificates", Layout.authenticatedNav(csrf), body.toString());
  }

  /** The result page after issuing/renewing: the leaf + CA PEM and the serial (all public). */
  public static String issued(final Certificate cert, final String csrf) {
    final String body = """
        <p><strong>Issued</strong> — serial <code>$SERIAL</code>, expires at $EXP (epoch seconds).</p>
        <details open><summary>Leaf certificate (PEM)</summary><pre class="secret-value">$LEAF</pre></details>
        <details><summary>CA certificate (PEM)</summary><pre class="secret-value">$CA</pre></details>
        <p style="margin-top:1rem"><a href="/certificates">Back to Certificates</a></p>
        """
        .replace("$SERIAL", Layout.escape(cert.serial()))
        .replace("$EXP", Long.toString(cert.notAfter()))
        .replace("$LEAF", Layout.escape(cert.certificate()))
        .replace("$CA", Layout.escape(cert.caCertificate()));
    return Layout.page("Certificate issued", Layout.authenticatedNav(csrf), body);
  }

  /** The revoke-confirmation page for a single serial (the actual revoke is a separate POST). */
  public static String confirmRevoke(final String serial, final String reason, final String csrf) {
    final String body = """
        <div class="banner">
          <p class="warn">Revoke certificate $SERIAL?</p>
          <p>The serial is added to the revocation list. (Short leaf TTLs are the primary control;
          revocation kills a specific outstanding leaf before it expires.)</p>
          <form method="post" action="/certificates/revoke" style="margin:0">
            <input type="hidden" name="csrf" value="$CSRF">
            <input type="hidden" name="serial" value="$SERIAL">
            <input type="hidden" name="reason" value="$REASON">
            <button type="submit">Revoke $SERIAL</button>
          </form>
          <p style="margin-top:.5rem"><a href="/certificates">Cancel</a></p>
        </div>
        """
        .replace("$SERIAL", Layout.escape(serial))
        .replace("$REASON", Layout.escape(reason))
        .replace("$CSRF", Layout.escape(csrf));
    return Layout.page("Confirm revoke", Layout.authenticatedNav(csrf), body);
  }

  /** The page shown when no mini-ca is configured. */
  public static String notConfigured(final String csrf) {
    final String body = "<p class=\"muted\">No mini-ca is configured. Set <code>--ca-url</code> "
        + "(and a CA token) to manage certificates.</p>";
    return Layout.page("Certificates", Layout.authenticatedNav(csrf), body);
  }

  /** The generic page shown when a CA call fails (no oracle). */
  public static String unavailable(final String csrf) {
    return Layout.page("Certificates", Layout.authenticatedNav(csrf),
        "<p class=\"muted\">mini-ca is unavailable.</p>");
  }

  private static String csrForm(final String action, final String label, final boolean renew,
                                final String csrf) {
    final String previous = renew
        ? "<p><label>Previous serial to revoke (optional)<br>"
            + "<input type=\"text\" name=\"previousSerial\" autocomplete=\"off\"></label></p>"
        : "";
    return """
        <form method="post" action="$ACTION">
          <input type="hidden" name="csrf" value="$CSRF">
          <p><label>PKCS#10 CSR (PEM)<br>
            <textarea name="csr" rows="6" autocomplete="off"
              placeholder="-----BEGIN CERTIFICATE REQUEST-----"></textarea></label></p>
          <p><label>TTL seconds (optional)<br>
            <input type="text" name="ttlSeconds" autocomplete="off"></label></p>
          $PREVIOUS
          <button type="submit">$LABEL</button>
        </form>
        """
        .replace("$ACTION", action)
        .replace("$LABEL", Layout.escape(label))
        .replace("$PREVIOUS", previous)
        .replace("$CSRF", Layout.escape(csrf));
  }

  private static String logTable(final List<IssuanceLogEntry> log, final Set<String> revoked) {
    if (log.isEmpty()) {
      return "<p class=\"muted\">No certificates issued yet.</p>";
    }
    final StringBuilder rows = new StringBuilder();
    for (final IssuanceLogEntry entry : log) {
      final boolean isRevoked = revoked.contains(entry.serial());
      rows.append("<tr><td><code>").append(Layout.escape(entry.serial())).append("</code></td><td>")
          .append(Layout.escape(entry.subject())).append("</td><td>").append(entry.notAfter())
          .append("</td><td>");
      if (isRevoked) {
        rows.append("<span class=\"muted\">revoked</span>");
      } else {
        rows.append("<a href=\"/certificates/revoke/confirm?serial=")
            .append(urlEncode(entry.serial())).append("\">Revoke</a>");
      }
      rows.append("</td></tr>");
    }
    return "<table><thead><tr><th>Serial</th><th>Subject</th><th>Not after</th><th>Action</th>"
        + "</tr></thead><tbody>" + rows + "</tbody></table>";
  }

  private static String revocationTable(final List<RevocationEntry> revocations) {
    if (revocations.isEmpty()) {
      return "<p class=\"muted\">Nothing revoked.</p>";
    }
    final StringBuilder rows = new StringBuilder();
    for (final RevocationEntry entry : revocations) {
      rows.append("<tr><td><code>").append(Layout.escape(entry.serial())).append("</code></td><td>")
          .append(entry.revokedAt()).append("</td><td>")
          .append(Layout.escape(entry.reason())).append("</td></tr>");
    }
    return "<table><thead><tr><th>Serial</th><th>Revoked at</th><th>Reason</th></tr></thead><tbody>"
        + rows + "</tbody></table>";
  }

  private static String urlEncode(final String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }
}
