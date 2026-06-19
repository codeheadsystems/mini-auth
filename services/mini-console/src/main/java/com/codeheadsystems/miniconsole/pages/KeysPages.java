package com.codeheadsystems.miniconsole.pages;

import com.codeheadsystems.minikms.protocol.KeyGroupView;
import com.codeheadsystems.minikms.protocol.KekVersionView;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * The Keys page: mini-kms key-group management (control plane) and mini-idp signing-key rotation.
 *
 * <p>Each backend renders independently — "not configured" when its client is absent, "unavailable"
 * when a call fails (no oracle), or its live state otherwise. Every state-changing control is a
 * CSRF-guarded POST; destroying a key version (irreversible crypto-shredding) goes through a
 * confirm step. No page renders a key or a token — only non-secret metadata (group names, version
 * numbers, statuses, key ids).
 */
public final class KeysPages {

  /** Whether a backend is wired, reachable, or not. */
  public enum Availability {
    /** No client configured for this backend. */
    NOT_CONFIGURED,
    /** Configured but a call failed (collapsed, no oracle). */
    UNAVAILABLE,
    /** Live data available. */
    OK
  }

  private KeysPages() {
  }

  /**
   * The Keys landing page.
   *
   * @param kmsState the mini-kms availability.
   * @param groups   the KMS key groups (used only when {@code kmsState} is OK).
   * @param idpState the mini-idp availability.
   * @param idpKids  the published mini-idp signing-key ids (used only when {@code idpState} is OK).
   * @param csrf     the CSRF token threaded into every form (escaped here).
   * @return a complete HTML document.
   */
  public static String render(final Availability kmsState, final List<KeyGroupView> groups,
                              final Availability idpState, final List<String> idpKids,
                              final String csrf) {
    final StringBuilder body = new StringBuilder();

    body.append("<h2 style=\"font-size:1.1rem\">mini-kms key groups</h2>");
    body.append(switch (kmsState) {
      case NOT_CONFIGURED -> muted("Not configured. Set <code>--kms-tcp</code> and the KMS tokens.");
      case UNAVAILABLE -> muted("Unavailable.");
      case OK -> kmsGroups(groups, csrf);
    });

    body.append("<h2 style=\"font-size:1.1rem;margin-top:2rem\">mini-idp signing key</h2>");
    body.append(switch (idpState) {
      case NOT_CONFIGURED -> muted("Not configured. Set <code>--idp-url</code> and an IDP token.");
      case UNAVAILABLE -> muted("Unavailable.");
      case OK -> idpSection(idpKids, csrf);
    });

    return Layout.page("Keys", Layout.authenticatedNav(csrf), body.toString());
  }

  /**
   * The destroy-confirmation page for a single KMS key version.
   *
   * @param keyId   the group name.
   * @param version the version to destroy.
   * @param csrf    the CSRF token (escaped here).
   * @return a complete HTML document.
   */
  public static String confirmDestroy(final String keyId, final long version, final String csrf) {
    final String body = """
        <div class="banner">
          <p class="warn">Destroy version $V of key group "$K"?</p>
          <p>This is <strong>irreversible</strong> — the version's key material is crypto-shredded and
          anything still encrypted under it becomes permanently unrecoverable.</p>
          <form method="post" action="/keys/kms/$KE/destroy" style="margin:0">
            <input type="hidden" name="csrf" value="$CSRF">
            <input type="hidden" name="version" value="$V">
            <button type="submit">Destroy version $V</button>
          </form>
          <p style="margin-top:.5rem"><a href="/keys">Cancel</a></p>
        </div>
        """
        .replace("$KE", urlEncode(keyId))
        .replace("$K", Layout.escape(keyId))
        .replace("$V", Long.toString(version))
        .replace("$CSRF", Layout.escape(csrf));
    return Layout.page("Confirm destroy", Layout.authenticatedNav(csrf), body);
  }

  private static String kmsGroups(final List<KeyGroupView> groups, final String csrf) {
    final StringBuilder html = new StringBuilder();
    if (groups.isEmpty()) {
      html.append(muted("No key groups yet."));
    }
    for (final KeyGroupView group : groups) {
      final String ge = urlEncode(group.keyId());
      html.append("<section style=\"margin-top:1rem\"><h3 style=\"font-size:1rem\">")
          .append(Layout.escape(group.keyId())).append("</h3>");
      html.append("<table><thead><tr><th>Version</th><th>Status</th><th>Created</th>"
          + "<th>Actions</th></tr></thead><tbody>");
      for (final KekVersionView version : group.versions()) {
        html.append("<tr><td>").append(version.version());
        if (version.version() == group.activeVersion()) {
          html.append(" <span class=\"muted\">(active)</span>");
        }
        html.append("</td><td>").append(Layout.escape(version.status()))
            .append("</td><td>").append(version.createdAtEpochSec())
            .append("</td><td>").append(versionActions(ge, version, group.activeVersion(), csrf))
            .append("</td></tr>");
      }
      html.append("</tbody></table>");
      html.append(postButton("/keys/kms/" + ge + "/rotate", "Rotate (new active version)", csrf));
      html.append("</section>");
    }
    // Create a new group.
    html.append("""
        <form method="post" action="/keys/kms" style="margin-top:1.5rem">
          <input type="hidden" name="csrf" value="$CSRF">
          <label>New key group<br><input type="text" name="keyId" autocomplete="off"></label>
          <p><button type="submit">Create group</button></p>
        </form>
        """.replace("$CSRF", Layout.escape(csrf)));
    return html.toString();
  }

  private static String versionActions(final String groupEnc, final KekVersionView version,
                                       final long activeVersion, final String csrf) {
    if (version.version() == activeVersion) {
      return "<span class=\"muted\">—</span>";
    }
    final StringBuilder actions = new StringBuilder();
    final String status = version.status();
    if ("DISABLED".equals(status)) {
      actions.append(versionPost(groupEnc, "enable", version.version(), "Enable", csrf));
    } else if (!"DESTROYED".equals(status)) {
      actions.append(versionPost(groupEnc, "disable", version.version(), "Disable", csrf));
    }
    if (!"DESTROYED".equals(status)) {
      // Destroy is irreversible — route through the confirm page (a GET), not a direct POST.
      actions.append(" <a href=\"/keys/kms/").append(groupEnc).append("/destroy?version=")
          .append(version.version()).append("\">Destroy</a>");
    }
    return actions.isEmpty() ? "<span class=\"muted\">—</span>" : actions.toString();
  }

  private static String versionPost(final String groupEnc, final String op, final long version,
                                    final String label, final String csrf) {
    return """
        <form method="post" action="/keys/kms/$G/$OP" style="display:inline">
          <input type="hidden" name="csrf" value="$CSRF">
          <input type="hidden" name="version" value="$V">
          <button type="submit">$LABEL</button>
        </form>"""
        .replace("$G", groupEnc).replace("$OP", op).replace("$V", Long.toString(version))
        .replace("$LABEL", Layout.escape(label)).replace("$CSRF", Layout.escape(csrf));
  }

  private static String idpSection(final List<String> kids, final String csrf) {
    final StringBuilder html = new StringBuilder();
    html.append("<p>Published signing keys: ");
    if (kids.isEmpty()) {
      html.append("<span class=\"muted\">none</span>");
    } else {
      final StringBuilder joined = new StringBuilder();
      for (int i = 0; i < kids.size(); i++) {
        if (i > 0) {
          joined.append(", ");
        }
        joined.append("<code>").append(Layout.escape(kids.get(i))).append("</code>");
      }
      html.append(joined);
    }
    html.append("</p>");
    html.append(muted("Rotating mints a fresh key and makes it active; the retired key stays in the "
        + "JWKS so in-flight tokens keep verifying."));
    html.append(postButton("/keys/idp/rotate", "Rotate signing key", csrf));
    return html.toString();
  }

  private static String postButton(final String action, final String label, final String csrf) {
    return """
        <form method="post" action="$ACTION" style="margin-top:.5rem">
          <input type="hidden" name="csrf" value="$CSRF">
          <button type="submit">$LABEL</button>
        </form>"""
        .replace("$ACTION", action).replace("$LABEL", Layout.escape(label))
        .replace("$CSRF", Layout.escape(csrf));
  }

  private static String muted(final String html) {
    return "<p class=\"muted\">" + html + "</p>";
  }

  private static String urlEncode(final String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }
}
