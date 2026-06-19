package com.codeheadsystems.miniconsole.pages;

import com.codeheadsystems.minidirectory.client.model.Account;
import com.codeheadsystems.minidirectory.client.model.GrantSpec;
import com.codeheadsystems.minidirectory.client.model.Group;
import com.codeheadsystems.minidirectory.client.model.Resolution;
import com.codeheadsystems.minidirectory.client.model.Role;
import java.util.List;

/**
 * The Identities views: a list of principals/groups/roles with create forms and delete links
 * (Slice 2), one principal's detail with its resolved grants and an assignment editor, the
 * delete-confirm step, and the one-time service-account secret banner. Server-rendered HTML in the
 * shared {@link Layout} chrome.
 *
 * <p>Every interpolated value is passed through {@link Layout#escape}. With one deliberate
 * exception — the {@link #serviceAccountCreated} banner — these pages <b>never render a secret</b>:
 * the directory's account view carries no secret hash, humans have no secret, and the once-only
 * secret is shown only on the creation result and never again.
 *
 * <p>Every state-changing form carries a hidden {@code csrf} field (double-submit), so a POST
 * without the matching cookie is rejected before any directory call.
 */
public final class IdentitiesPages {

  private IdentitiesPages() {
  }

  /**
   * The list view: principals (linked to detail, with a delete link), groups, roles, and the create
   * forms.
   *
   * @param accounts the principals.
   * @param groups   the groups.
   * @param roles    the roles.
   * @param csrf     the CSRF token threaded into the nav and every create form.
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
          .append(Layout.escape(account.displayName())).append("</td><td>")
          .append(deleteLink("/identities/" + urlPath(account.id()) + "/delete")).append("</td></tr>");
    }

    final StringBuilder groupRows = new StringBuilder();
    for (final Group group : groups) {
      groupRows.append("<tr><td>").append(Layout.escape(group.id())).append("</td><td>")
          .append(Layout.escape(group.description())).append("</td><td>")
          .append(Layout.escape(joinIds(group.roles()))).append("</td><td>")
          .append(deleteLink("/groups/" + urlPath(group.id()) + "/delete")).append("</td></tr>");
    }

    final StringBuilder roleRows = new StringBuilder();
    for (final Role role : roles) {
      roleRows.append("<tr><td>").append(Layout.escape(role.id())).append("</td><td>")
          .append(Layout.escape(role.description())).append("</td><td>")
          .append(Layout.escape(grantSummary(role.grants()))).append("</td><td>")
          .append(deleteLink("/roles/" + urlPath(role.id()) + "/delete")).append("</td></tr>");
    }

    final String body = """
        <h2>Principals</h2>
        <table>
          <thead><tr><th>Id</th><th>Kind</th><th>Admin</th><th>Status</th><th>Name</th><th></th></tr></thead>
          <tbody>$PRINCIPALS</tbody>
        </table>
        <h2>Groups</h2>
        <table>
          <thead><tr><th>Id</th><th>Description</th><th>Roles</th><th></th></tr></thead>
          <tbody>$GROUPS</tbody>
        </table>
        <h2>Roles</h2>
        <table>
          <thead><tr><th>Id</th><th>Description</th><th>Grants</th><th></th></tr></thead>
          <tbody>$ROLES</tbody>
        </table>
        $CREATE
        """
        .replace("$PRINCIPALS", placeholderIfEmpty(principals, 6))
        .replace("$GROUPS", placeholderIfEmpty(groupRows, 4))
        .replace("$ROLES", placeholderIfEmpty(roleRows, 4))
        .replace("$CREATE", createForms(csrf));

    return Layout.page("Identities", Layout.authenticatedNav(csrf), body);
  }

  /**
   * One principal's detail, its resolved grants, an assignment editor, and a delete link.
   *
   * @param account    the principal.
   * @param resolution the resolved (fully-expanded) grants.
   * @param csrf       the CSRF token threaded into the assignment form and the nav.
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
        <h3>Edit assignment</h3>
        <form method="post" action="/identities/$IDPATH/assignment">
          $CSRF
          <p><label><input type="checkbox" name="enabled"$ENABLED> enabled</label></p>
          <p><label><input type="checkbox" name="admin"$ADMINCHK> admin</label></p>
          <p><label>Member of (comma-separated)<br><input type="text" name="memberOf" value="$MEMBEROFVAL"></label></p>
          <p><label>Roles (comma-separated)<br><input type="text" name="roles" value="$ROLESVAL"></label></p>
          <p><label>Direct grants (one <code>action:resource</code> per line)<br>
            <textarea name="grants" rows="3">$GRANTSVAL</textarea></label></p>
          <button type="submit">Save assignment</button>
        </form>
        <h3>Delete</h3>
        <p><a href="/identities/$IDPATH/delete">Delete this principal…</a></p>
        """
        .replace("$IDPATH", urlPath(account.id()))
        .replace("$CSRF", csrfField(csrf))
        .replace("$ENABLED", account.enabled() ? " checked" : "")
        .replace("$ADMINCHK", account.admin() ? " checked" : "")
        .replace("$MEMBEROFVAL", Layout.escape(csv(account.memberOf())))
        .replace("$ROLESVAL", Layout.escape(csv(account.roles())))
        .replace("$GRANTSVAL", Layout.escape(grantLines(account.grants())))
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

  /**
   * The one-time service-account secret banner — the ONLY page that ever renders a secret, and only
   * on the creation result. The secret is not stored and not re-fetchable; navigating away loses it.
   *
   * @param id     the new service account's id.
   * @param secret the one-time plaintext secret (escaped; shown exactly once).
   * @param csrf   the CSRF token for the nav.
   * @return a complete HTML document.
   */
  public static String serviceAccountCreated(final String id, final String secret, final String csrf) {
    final String body = """
        <div class="banner">
          <h2>Service account created</h2>
          <p>Id: <code>$ID</code></p>
          <p class="warn">Copy this secret now — it will not be shown again.</p>
          <p>Secret: <code class="secret-value">$SECRET</code></p>
          <p><a href="/identities">Done</a></p>
        </div>
        """
        .replace("$ID", Layout.escape(id))
        .replace("$SECRET", Layout.escape(secret));
    return Layout.page("Service account created", Layout.authenticatedNav(csrf), body);
  }

  /**
   * The delete confirmation step (a real deletion only happens on the subsequent POST).
   *
   * @param kind   the noun shown to the operator (e.g. {@code "principal"}, {@code "group"}).
   * @param id     the id being deleted.
   * @param action the POST target that performs the deletion.
   * @param csrf   the CSRF token for the confirm form.
   * @return a complete HTML document.
   */
  public static String confirmDelete(final String kind, final String id, final String action,
                                     final String csrf) {
    final String body = """
        <h2>Delete $KIND</h2>
        <p>Really delete <code>$ID</code>? This cannot be undone.</p>
        <form method="post" action="$ACTION">
          $CSRF
          <button type="submit">Delete</button>
        </form>
        <p><a href="/identities">Cancel</a></p>
        """
        .replace("$KIND", Layout.escape(kind))
        .replace("$ID", Layout.escape(id))
        .replace("$ACTION", Layout.escape(action))
        .replace("$CSRF", csrfField(csrf));
    return Layout.page("Confirm delete", Layout.authenticatedNav(csrf), body);
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

  // --- create forms ----------------------------------------------------------------------------

  private static String createForms(final String csrf) {
    return """
        <details>
          <summary>Create…</summary>
          <h3>New human</h3>
          <form method="post" action="/identities/humans">
            $CSRF
            <p><label>Id<br><input type="text" name="id" required></label></p>
            <p><label>Display name<br><input type="text" name="displayName"></label></p>
            <p><label><input type="checkbox" name="admin"> admin</label></p>
            <p><label>Member of (comma-separated)<br><input type="text" name="memberOf"></label></p>
            <p><label>Roles (comma-separated)<br><input type="text" name="roles"></label></p>
            <p><label>Direct grants (<code>action:resource</code> per line)<br>
              <textarea name="grants" rows="2"></textarea></label></p>
            <button type="submit">Create human</button>
          </form>
          <h3>New service account</h3>
          <form method="post" action="/identities/service-accounts">
            $CSRF
            <p><label>Display name<br><input type="text" name="displayName"></label></p>
            <p><label><input type="checkbox" name="admin"> admin</label></p>
            <p><label>Member of (comma-separated)<br><input type="text" name="memberOf"></label></p>
            <p><label>Roles (comma-separated)<br><input type="text" name="roles"></label></p>
            <p><label>Direct grants (<code>action:resource</code> per line)<br>
              <textarea name="grants" rows="2"></textarea></label></p>
            <button type="submit">Create service account</button>
          </form>
          <h3>New group</h3>
          <form method="post" action="/identities/groups">
            $CSRF
            <p><label>Id<br><input type="text" name="id" required></label></p>
            <p><label>Description<br><input type="text" name="description"></label></p>
            <p><label>Roles (comma-separated)<br><input type="text" name="roles"></label></p>
            <p><label>Direct grants (<code>action:resource</code> per line)<br>
              <textarea name="grants" rows="2"></textarea></label></p>
            <button type="submit">Create group</button>
          </form>
          <h3>New role</h3>
          <form method="post" action="/identities/roles">
            $CSRF
            <p><label>Id<br><input type="text" name="id" required></label></p>
            <p><label>Description<br><input type="text" name="description"></label></p>
            <p><label>Grants (<code>action:resource</code> per line)<br>
              <textarea name="grants" rows="2"></textarea></label></p>
            <button type="submit">Create role</button>
          </form>
        </details>
        """.replace("$CSRF", csrfField(csrf));
  }

  // --- helpers ---------------------------------------------------------------------------------

  private static String csrfField(final String csrf) {
    return "<input type=\"hidden\" name=\"csrf\" value=\"" + Layout.escape(csrf) + "\">";
  }

  private static String deleteLink(final String href) {
    return "<a href=\"" + href + "\">delete</a>";
  }

  private static String joinIds(final List<String> ids) {
    return ids == null || ids.isEmpty() ? "—" : String.join(", ", ids);
  }

  /** Comma-separated ids for a text input value ("" when empty, so the field renders blank). */
  private static String csv(final List<String> ids) {
    return ids == null || ids.isEmpty() ? "" : String.join(", ", ids);
  }

  /** One {@code action:resource} per line for a textarea value. */
  private static String grantLines(final List<GrantSpec> grants) {
    if (grants == null || grants.isEmpty()) {
      return "";
    }
    final StringBuilder lines = new StringBuilder();
    for (final GrantSpec grant : grants) {
      if (lines.length() > 0) {
        lines.append('\n');
      }
      lines.append(grant.action()).append(':').append(grant.resource());
    }
    return lines.toString();
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
