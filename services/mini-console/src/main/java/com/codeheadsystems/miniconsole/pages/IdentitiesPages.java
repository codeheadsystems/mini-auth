package com.codeheadsystems.miniconsole.pages;

import com.codeheadsystems.minidirectory.client.model.Account;
import com.codeheadsystems.minidirectory.client.model.GrantSpec;
import com.codeheadsystems.minidirectory.client.model.Group;
import com.codeheadsystems.minidirectory.client.model.Resolution;
import com.codeheadsystems.minidirectory.client.model.Role;
import java.util.List;

/**
 * The read-only Identities views (Slice 1): a list of principals/groups/roles, and one principal's
 * detail with its resolved grants. Server-rendered HTML in the shared {@link Layout} chrome.
 *
 * <p>Every interpolated value is passed through {@link Layout#escape}. These pages <b>never render a
 * secret</b> — the directory's {@code AccountView} carries no secret hash, and humans have no secret
 * at all; only ids, labels, memberships, and {@code (action, resource)} grants are shown.
 */
public final class IdentitiesPages {

  private IdentitiesPages() {
  }

  /**
   * The list view: principals (linked to detail), groups, and roles.
   *
   * @param accounts the principals.
   * @param groups   the groups.
   * @param roles    the roles.
   * @param csrf     the CSRF token for the nav sign-out form.
   * @return a complete HTML document.
   */
  public static String list(final List<Account> accounts, final List<Group> groups,
                            final List<Role> roles, final String csrf) {
    final StringBuilder principals = new StringBuilder();
    for (final Account account : accounts) {
      principals.append("<tr><td><a href=\"/identities/").append(urlPath(account.id())).append("\">")
          .append(Layout.escape(account.id())).append("</a></td><td>")
          .append(Layout.escape(String.valueOf(account.kind()))).append("</td><td>")
          .append(account.admin() ? "admin" : "").append("</td><td>")
          .append(account.enabled() ? "enabled" : "disabled").append("</td><td>")
          .append(Layout.escape(account.displayName())).append("</td></tr>");
    }

    final StringBuilder groupRows = new StringBuilder();
    for (final Group group : groups) {
      groupRows.append("<tr><td>").append(Layout.escape(group.id())).append("</td><td>")
          .append(Layout.escape(group.description())).append("</td><td>")
          .append(Layout.escape(joinIds(group.roles()))).append("</td></tr>");
    }

    final StringBuilder roleRows = new StringBuilder();
    for (final Role role : roles) {
      roleRows.append("<tr><td>").append(Layout.escape(role.id())).append("</td><td>")
          .append(Layout.escape(role.description())).append("</td><td>")
          .append(Layout.escape(grantSummary(role.grants()))).append("</td></tr>");
    }

    final String body = """
        <h2>Principals</h2>
        <table>
          <thead><tr><th>Id</th><th>Kind</th><th>Admin</th><th>Status</th><th>Name</th></tr></thead>
          <tbody>$PRINCIPALS</tbody>
        </table>
        <h2>Groups</h2>
        <table>
          <thead><tr><th>Id</th><th>Description</th><th>Roles</th></tr></thead>
          <tbody>$GROUPS</tbody>
        </table>
        <h2>Roles</h2>
        <table>
          <thead><tr><th>Id</th><th>Description</th><th>Grants</th></tr></thead>
          <tbody>$ROLES</tbody>
        </table>
        """
        .replace("$PRINCIPALS", placeholderIfEmpty(principals, 5))
        .replace("$GROUPS", placeholderIfEmpty(groupRows, 3))
        .replace("$ROLES", placeholderIfEmpty(roleRows, 3));

    return Layout.page("Identities", Layout.authenticatedNav(csrf), body);
  }

  /**
   * One principal's detail and resolved grants.
   *
   * @param account    the principal.
   * @param resolution the resolved (fully-expanded) grants.
   * @param csrf       the CSRF token for the nav sign-out form.
   * @return a complete HTML document.
   */
  public static String detail(final Account account, final Resolution resolution, final String csrf) {
    final StringBuilder resolved = new StringBuilder();
    for (final GrantSpec grant : resolution.grants()) {
      resolved.append("<tr><td>").append(Layout.escape(grant.action())).append("</td><td>")
          .append(Layout.escape(grant.resource())).append("</td></tr>");
    }

    final String body = """
        <p><a href="/identities">&larr; all identities</a></p>
        <h2>$ID</h2>
        <dl>
          <dt>Kind</dt><dd>$KIND</dd>
          <dt>Display name</dt><dd>$NAME</dd>
          <dt>Admin</dt><dd>$ADMIN</dd>
          <dt>Status</dt><dd>$STATUS</dd>
          <dt>Member of</dt><dd>$MEMBEROF</dd>
          <dt>Direct roles</dt><dd>$ROLES</dd>
          <dt>Direct grants</dt><dd>$DIRECT</dd>
        </dl>
        <h3>Resolved grants <span class="muted">(roles &amp; groups expanded)</span></h3>
        <table>
          <thead><tr><th>Action</th><th>Resource</th></tr></thead>
          <tbody>$RESOLVED</tbody>
        </table>
        """
        .replace("$ID", Layout.escape(account.id()))
        .replace("$KIND", Layout.escape(String.valueOf(account.kind())))
        .replace("$NAME", Layout.escape(account.displayName()))
        .replace("$ADMIN", account.admin() ? "yes" : "no")
        .replace("$STATUS", account.enabled() ? "enabled" : "disabled")
        .replace("$MEMBEROF", Layout.escape(joinIds(account.memberOf())))
        .replace("$ROLES", Layout.escape(joinIds(account.roles())))
        .replace("$DIRECT", Layout.escape(grantSummary(account.grants())))
        .replace("$RESOLVED", placeholderIfEmpty(resolved, 2));

    return Layout.page("Identity", Layout.authenticatedNav(csrf), body);
  }

  /** The page shown when no mini-directory is wired (an honest seam, not an error). */
  public static String notConfigured(final String csrf) {
    final String body = """
        <p class="muted">mini-directory is not configured. Start the console with
        <code>--directory-url</code> and a directory token
        (<code>MINICONSOLE_DIRECTORY_TOKEN</code> or <code>--directory-token-file</code>) to browse
        identities here.</p>
        """;
    return Layout.page("Identities", Layout.authenticatedNav(csrf), body);
  }

  /** The generic page shown when a directory call fails (no oracle — not-found vs error look the same). */
  public static String unavailable(final String csrf) {
    final String body = """
        <p class="err">The directory could not be reached or the request failed.</p>
        <p><a href="/identities">Try again</a></p>
        """;
    return Layout.page("Identities", Layout.authenticatedNav(csrf), body);
  }

  // --- helpers ---------------------------------------------------------------------------------

  private static String joinIds(final List<String> ids) {
    return ids == null || ids.isEmpty() ? "—" : String.join(", ", ids);
  }

  private static String grantSummary(final List<GrantSpec> grants) {
    if (grants == null || grants.isEmpty()) {
      return "—";
    }
    final StringBuilder summary = new StringBuilder();
    for (final GrantSpec grant : grants) {
      if (summary.length() > 0) {
        summary.append(", ");
      }
      summary.append(grant.action()).append(':').append(grant.resource());
    }
    return summary.toString();
  }

  /** Percent-safe path segment for a link (mirrors the client's id encoding). */
  private static String urlPath(final String id) {
    return java.net.URLEncoder.encode(id, java.nio.charset.StandardCharsets.UTF_8);
  }

  private static String placeholderIfEmpty(final StringBuilder rows, final int columns) {
    if (rows.length() > 0) {
      return rows.toString();
    }
    return "<tr><td class=\"muted\" colspan=\"" + columns + "\">none</td></tr>";
  }
}
