package com.codeheadsystems.miniconsole.server;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.miniconsole.harness.ExerciseRegistry;
import com.codeheadsystems.miniconsole.harness.ExerciseResult;
import com.codeheadsystems.miniconsole.harness.flows.M2mTokenFlow;
import com.codeheadsystems.miniconsole.pages.AuditPages;
import com.codeheadsystems.miniconsole.pages.DashboardPage;
import com.codeheadsystems.miniconsole.pages.HarnessPages;
import com.codeheadsystems.miniconsole.pages.IdentitiesPages;
import com.codeheadsystems.miniconsole.pages.LoginPage;
import com.codeheadsystems.miniconsole.server.http.ApiException;
import com.codeheadsystems.miniconsole.server.http.HttpResponse;
import com.codeheadsystems.miniconsole.server.http.RequestContext;
import com.codeheadsystems.miniconsole.server.http.Router;
import com.codeheadsystems.minidirectory.client.MiniDirectoryClient;
import com.codeheadsystems.minidirectory.client.model.Assignment;
import com.codeheadsystems.minidirectory.client.model.GrantSpec;
import com.codeheadsystems.minidirectory.client.model.NewGroup;
import com.codeheadsystems.minidirectory.client.model.NewHuman;
import com.codeheadsystems.minidirectory.client.model.NewRole;
import com.codeheadsystems.minidirectory.client.model.NewServiceAccount;
import com.codeheadsystems.minidirectory.client.model.ServiceAccountCreated;
import com.codeheadsystems.miniidp.client.MiniIdpClient;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * The console route table: a public health check, a paste-the-token login that mints a session, an
 * authenticated Dashboard, and (from Slice 1) the read-only Identities pages backed by the
 * mini-directory client.
 *
 * <p>Auth model: the console token is the bootstrap credential, presented once by being pasted into
 * the {@code /login} form (constant-time compared, never logged). On success the console mints a
 * {@link ConsoleSession} and the {@link Cookies#SESSION} cookie carries it forward; every page but
 * {@code /login} and {@code /health} requires a valid session, else a browser-friendly 302 to
 * {@code /login} (no 401 body, no oracle). State-changing POSTs ({@code /login}, {@code /logout})
 * carry a double-submit {@link Csrf} token.
 *
 * <p>The {@link MiniDirectoryClient} is optional: when the directory is not configured the Identities
 * pages and the Dashboard row say so rather than failing. Any directory call that throws collapses to
 * a generic "unavailable" page — no oracle (a missing principal and a refused token look the same).
 */
public final class ConsoleHandlers {

  /** How long the short-lived CSRF cookie lives (long enough to submit the form). */
  private static final long CSRF_TTL_SECONDS = 3600;

  private final ConsoleSession session;
  private final AdminAuthenticator auth;
  private final Cookies cookies;
  private final Csrf csrf;
  private final long sessionTtlSeconds;
  private final MiniDirectoryClient directory;
  private final MiniIdpClient idp;
  private final ExerciseRegistry exercises;
  private final M2mTokenFlow m2mFlow;

  /**
   * @param session           the console-login session store.
   * @param auth              the console-token constant-time comparator.
   * @param cookies           the cookie builder (console-specific names).
   * @param csrf              the double-submit CSRF helper.
   * @param sessionTtlSeconds the session cookie {@code Max-Age}.
   * @param directory         the mini-directory client, or null when the directory is not configured.
   * @param idp               the mini-idp client, or null when mini-idp is not configured.
   * @param exercises         the exercise registry (for the Harness page listing).
   * @param m2mFlow           the machine-to-machine token flow (dispatched by the run route).
   */
  public ConsoleHandlers(final ConsoleSession session, final AdminAuthenticator auth,
                         final Cookies cookies, final Csrf csrf, final long sessionTtlSeconds,
                         final MiniDirectoryClient directory, final MiniIdpClient idp,
                         final ExerciseRegistry exercises, final M2mTokenFlow m2mFlow) {
    this.session = session;
    this.auth = auth;
    this.cookies = cookies;
    this.csrf = csrf;
    this.sessionTtlSeconds = sessionTtlSeconds;
    this.directory = directory;
    this.idp = idp;
    this.exercises = exercises;
    this.m2mFlow = m2mFlow;
  }

  /** @return the router with the console routes registered. */
  public Router router() {
    return new Router()
        .route("GET", "/health", this::health)
        .route("GET", "/login", this::loginForm)
        .route("POST", "/login", this::loginSubmit)
        .route("GET", "/", this::dashboard)
        .route("GET", "/identities", this::identities)
        // Create routes are literal (2-segment) and POST, so they never shadow GET /identities/{id}.
        .route("POST", "/identities/humans", this::createHuman)
        .route("POST", "/identities/service-accounts", this::createServiceAccount)
        .route("POST", "/identities/groups", this::createGroup)
        .route("POST", "/identities/roles", this::createRole)
        .route("GET", "/identities/{id}", this::identityDetail)
        .route("POST", "/identities/{id}/assignment", this::updateAssignment)
        .route("GET", "/identities/{id}/delete", this::deleteAccountConfirm)
        .route("POST", "/identities/{id}/delete", this::deleteAccount)
        .route("GET", "/groups/{id}/delete", this::deleteGroupConfirm)
        .route("POST", "/groups/{id}/delete", this::deleteGroup)
        .route("GET", "/roles/{id}/delete", this::deleteRoleConfirm)
        .route("POST", "/roles/{id}/delete", this::deleteRole)
        // mini-idp (Slice 3): the audit log and the exercise harness.
        .route("GET", "/audit", this::audit)
        .route("GET", "/harness", this::harness)
        .route("POST", "/harness/m2m-token/run", this::runM2mToken)
        .route("POST", "/logout", this::logout);
  }

  /** Public liveness — no session required, no downstream calls. */
  private HttpResponse health(final RequestContext context) {
    return HttpResponse.json(200, Map.of("status", "ok"));
  }

  /** Render the sign-in form with a fresh CSRF token (set as the matching cookie). */
  private HttpResponse loginForm(final RequestContext context) {
    final String token = csrf.mint();
    return HttpResponse.html(LoginPage.render(token, false))
        .header("Set-Cookie", cookies.csrf(token, CSRF_TTL_SECONDS));
  }

  /**
   * Validate CSRF, then constant-time compare the pasted token. On success mint a session and
   * redirect to the Dashboard; on failure re-render the login page with a single generic message
   * (no oracle: a wrong token and a missing one are indistinguishable).
   */
  private HttpResponse loginSubmit(final RequestContext context) {
    final Map<String, String> form = context.formParams();
    if (!csrf.verify(context.cookie(Cookies.CSRF), form.get("csrf"))) {
      throw ApiException.badRequest("invalid or missing CSRF token");
    }
    if (!auth.matches(form.get("token"))) {
      // Re-render at 200 with a fresh CSRF token; reveal nothing about why it failed.
      final String token = csrf.mint();
      return HttpResponse.html(LoginPage.render(token, true))
          .header("Set-Cookie", cookies.csrf(token, CSRF_TTL_SECONDS));
    }
    final String sessionId = session.establish();
    return HttpResponse.redirect("/")
        .header("Set-Cookie", cookies.session(sessionId, sessionTtlSeconds));
  }

  /** The authenticated Dashboard; 302 to /login without a valid session. */
  private HttpResponse dashboard(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String token = csrf.mint();
    final String host = context.header("Host");
    final String address = host != null ? host : "loopback";
    return htmlWithCsrf(DashboardPage.render(address, token, directory != null, directoryStatus(),
        idp != null, idpStatus()), token);
  }

  /** @return the live mini-directory status line for the Dashboard row (no secret, no oracle). */
  private String directoryStatus() {
    if (directory == null) {
      return "not configured (set --directory-url)";
    }
    try {
      return "healthy (" + directory.health().status() + ")";
    } catch (final ClientException e) {
      // Reachability problem — report it generically; never leak the cause.
      return "unreachable";
    }
  }

  /** @return the live mini-idp status line for the Dashboard row (no secret, no oracle). */
  private String idpStatus() {
    if (idp == null) {
      return "not configured (set --idp-url)";
    }
    try {
      return "healthy (" + idp.health().status() + ")";
    } catch (final ClientException e) {
      return "unreachable";
    }
  }

  /** The Identities list (read-only): principals, groups, and roles from mini-directory. */
  private HttpResponse identities(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String token = csrf.mint();
    if (directory == null) {
      return htmlWithCsrf(IdentitiesPages.notConfigured(token), token);
    }
    try {
      return htmlWithCsrf(IdentitiesPages.list(directory.listAccounts(), directory.listGroups(),
          directory.listRoles(), token), token);
    } catch (final ClientException e) {
      return htmlWithCsrf(IdentitiesPages.unavailable(token), token);
    }
  }

  /** One principal's detail plus its resolved (fully-expanded) grants. */
  private HttpResponse identityDetail(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String token = csrf.mint();
    if (directory == null) {
      return htmlWithCsrf(IdentitiesPages.notConfigured(token), token);
    }
    final String id = context.pathParam("id");
    try {
      return htmlWithCsrf(
          IdentitiesPages.detail(directory.getAccount(id), directory.resolve(id), token), token);
    } catch (final ClientException e) {
      // Not-found and any other failure collapse to one generic page — no oracle.
      return htmlWithCsrf(IdentitiesPages.unavailable(token), token);
    }
  }

  // ---- Mutations (Slice 2) -------------------------------------------------------------------
  //
  // Every state-changing POST is session-required AND CSRF-guarded (double-submit, exactly like
  // /login and /logout). The CSRF token is verified BEFORE any directory call. On success we
  // Post/Redirect/Get to /identities so a refresh cannot resubmit; the one exception is service-
  // account creation, which renders the one-time secret banner DIRECTLY (a redirect would lose it,
  // and we must never store or re-serve it). Any ClientException collapses to a generic page — a
  // collision, a dangling reference, and an unreachable directory look identical (no oracle).

  /** Create a human principal, then redirect back to the list. */
  private HttpResponse createHuman(final RequestContext context) {
    return mutate(context, form -> {
      directory.createHuman(new NewHuman(blankToNull(form.get("id")), blankToNull(form.get("displayName")),
          checkbox(form, "admin"), parseList(form.get("memberOf")), parseList(form.get("roles")),
          parseGrants(form.get("grants"))));
      return HttpResponse.redirect("/identities");
    });
  }

  /**
   * Create a service account and render its one-time secret banner. The secret is held only for the
   * lifetime of this response — never stored in the console, never logged, never re-fetchable.
   */
  private HttpResponse createServiceAccount(final RequestContext context) {
    return mutate(context, form -> {
      final ServiceAccountCreated created = directory.createServiceAccount(new NewServiceAccount(
          blankToNull(form.get("displayName")), checkbox(form, "admin"), parseList(form.get("memberOf")),
          parseList(form.get("roles")), parseGrants(form.get("grants"))));
      final String token = csrf.mint();
      // Direct HTML (not a redirect): this is the only place the secret is shown, and only now.
      return htmlWithCsrf(
          IdentitiesPages.serviceAccountCreated(created.id(), created.secret(), token), token);
    });
  }

  /** Create a group, then redirect back to the list. */
  private HttpResponse createGroup(final RequestContext context) {
    return mutate(context, form -> {
      directory.createGroup(new NewGroup(blankToNull(form.get("id")), blankToNull(form.get("description")),
          parseList(form.get("roles")), parseGrants(form.get("grants"))));
      return HttpResponse.redirect("/identities");
    });
  }

  /** Create a role, then redirect back to the list. */
  private HttpResponse createRole(final RequestContext context) {
    return mutate(context, form -> {
      directory.createRole(new NewRole(blankToNull(form.get("id")), blankToNull(form.get("description")),
          parseGrants(form.get("grants"))));
      return HttpResponse.redirect("/identities");
    });
  }

  /** Replace a principal's authorization, then redirect to its detail page. */
  private HttpResponse updateAssignment(final RequestContext context) {
    final String id = context.pathParam("id");
    return mutate(context, form -> {
      directory.updateAssignment(id, new Assignment(checkbox(form, "enabled"), checkbox(form, "admin"),
          parseList(form.get("memberOf")), parseList(form.get("roles")), parseGrants(form.get("grants"))));
      return HttpResponse.redirect("/identities/" + encode(id));
    });
  }

  /** Confirm-step page for deleting a principal (GET, no mutation). */
  private HttpResponse deleteAccountConfirm(final RequestContext context) {
    return confirmDelete(context, "principal", "/identities/" + encode(context.pathParam("id")) + "/delete");
  }

  /** Delete a principal, then redirect to the list. */
  private HttpResponse deleteAccount(final RequestContext context) {
    final String id = context.pathParam("id");
    return mutate(context, form -> {
      directory.deleteAccount(id);
      return HttpResponse.redirect("/identities");
    });
  }

  /** Confirm-step page for deleting a group (GET, no mutation). */
  private HttpResponse deleteGroupConfirm(final RequestContext context) {
    return confirmDelete(context, "group", "/groups/" + encode(context.pathParam("id")) + "/delete");
  }

  /** Delete a group, then redirect to the list. */
  private HttpResponse deleteGroup(final RequestContext context) {
    final String id = context.pathParam("id");
    return mutate(context, form -> {
      directory.deleteGroup(id);
      return HttpResponse.redirect("/identities");
    });
  }

  /** Confirm-step page for deleting a role (GET, no mutation). */
  private HttpResponse deleteRoleConfirm(final RequestContext context) {
    return confirmDelete(context, "role", "/roles/" + encode(context.pathParam("id")) + "/delete");
  }

  /** Delete a role, then redirect to the list. */
  private HttpResponse deleteRole(final RequestContext context) {
    final String id = context.pathParam("id");
    return mutate(context, form -> {
      directory.deleteRole(id);
      return HttpResponse.redirect("/identities");
    });
  }

  // ---- mini-idp: Audit + Harness (Slice 3) ---------------------------------------------------

  /** The mini-idp audit log (read-only); "not configured" without an IDP, generic on any failure. */
  private HttpResponse audit(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String token = csrf.mint();
    if (idp == null) {
      return htmlWithCsrf(AuditPages.notConfigured(token), token);
    }
    try {
      return htmlWithCsrf(AuditPages.list(idp.audit(), token), token);
    } catch (final ClientException e) {
      // A refused admin token and an unreachable IDP look the same — no oracle.
      return htmlWithCsrf(AuditPages.unavailable(token), token);
    }
  }

  /** The Harness page: list the available exercises (and the m2m run form). */
  private HttpResponse harness(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String token = csrf.mint();
    if (idp == null) {
      return htmlWithCsrf(HarnessPages.notConfigured(token), token);
    }
    return htmlWithCsrf(HarnessPages.list(exercises, token), token);
  }

  /**
   * Run the machine-to-machine token flow with the operator-supplied client id + secret. Session-
   * required and CSRF-guarded; the credentials are used for the single run and never stored or
   * logged. The rendered result carries only the non-secret facts the flow returned.
   */
  private HttpResponse runM2mToken(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String token = csrf.mint();
    if (idp == null) {
      return htmlWithCsrf(HarnessPages.notConfigured(token), token);
    }
    final Map<String, String> form = context.formParams();
    if (!csrf.verify(context.cookie(Cookies.CSRF), form.get("csrf"))) {
      throw ApiException.badRequest("invalid or missing CSRF token");
    }
    // The secret lives only for this call; it is never put into the session, a log, or the result.
    final ExerciseResult result =
        m2mFlow.run(idp, form.getOrDefault("clientId", ""), form.getOrDefault("clientSecret", ""));
    return htmlWithCsrf(HarnessPages.result(result, token), token);
  }

  /**
   * The shared guard for every mutating POST: require a session, short-circuit if no directory is
   * configured, verify CSRF before any side effect, run the action, and collapse any directory
   * failure to a generic page (no oracle).
   *
   * @param context the request.
   * @param action  the mutation, given the parsed form; returns the success response.
   * @return the action's response, or a redirect/error/not-configured page.
   */
  private HttpResponse mutate(final RequestContext context,
                             final Function<Map<String, String>, HttpResponse> action) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    if (directory == null) {
      return page(IdentitiesPages::notConfigured);
    }
    final Map<String, String> form = context.formParams();
    if (!csrf.verify(context.cookie(Cookies.CSRF), form.get("csrf"))) {
      throw ApiException.badRequest("invalid or missing CSRF token");
    }
    try {
      return action.apply(form);
    } catch (final ClientException e) {
      // Collision, dangling reference, refused, unreachable — all one generic outcome.
      return page(IdentitiesPages::unavailable);
    }
  }

  /** Render a delete confirmation page (session-required; the actual delete is a separate POST). */
  private HttpResponse confirmDelete(final RequestContext context, final String kind, final String action) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String token = csrf.mint();
    return htmlWithCsrf(
        IdentitiesPages.confirmDelete(kind, context.pathParam("id"), action, token), token);
  }

  /** Render an authenticated page that takes only a fresh CSRF token (e.g. the generic error pages). */
  private HttpResponse page(final Function<String, String> render) {
    final String token = csrf.mint();
    return htmlWithCsrf(render.apply(token), token);
  }

  /** Destroy the session and clear the cookie; requires a valid session + CSRF. */
  private HttpResponse logout(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    if (!csrf.verify(context.cookie(Cookies.CSRF), context.formParams().get("csrf"))) {
      throw ApiException.badRequest("invalid or missing CSRF token");
    }
    session.end(context.cookie(Cookies.SESSION));
    return HttpResponse.redirect("/login")
        .header("Set-Cookie", cookies.clearSession());
  }

  /**
   * @return a 302-to-login response if there is no valid session, else null (caller proceeds). The
   *     browser-friendly equivalent of a 401 — no body, no detail.
   */
  private HttpResponse requireSession(final RequestContext context) {
    final String sessionId = context.cookie(Cookies.SESSION);
    if (sessionId == null || !session.isValid(sessionId)) {
      return HttpResponse.redirect("/login");
    }
    return null;
  }

  /** Serve an authenticated HTML page, setting the fresh CSRF cookie its forms (logout) double-submit. */
  private HttpResponse htmlWithCsrf(final String html, final String csrfToken) {
    return HttpResponse.html(html).header("Set-Cookie", cookies.csrf(csrfToken, CSRF_TTL_SECONDS));
  }

  // ---- Form parsing --------------------------------------------------------------------------

  /** Percent-encode an id for use as a single redirect/link path segment. */
  private static String encode(final String id) {
    return URLEncoder.encode(id, StandardCharsets.UTF_8);
  }

  /** @return the trimmed value, or null when blank (so optional fields aren't sent as empty strings). */
  private static String blankToNull(final String value) {
    return value == null || value.isBlank() ? null : value.trim();
  }

  /** @return true when an HTML checkbox is present (a checked box submits its name; unchecked is absent). */
  private static boolean checkbox(final Map<String, String> form, final String name) {
    return form.get(name) != null;
  }

  /** Parse a comma-separated text field into a trimmed, blank-free list of ids. */
  private static List<String> parseList(final String csv) {
    if (csv == null || csv.isBlank()) {
      return List.of();
    }
    final List<String> ids = new ArrayList<>();
    for (final String part : csv.split(",")) {
      final String trimmed = part.trim();
      if (!trimmed.isEmpty()) {
        ids.add(trimmed);
      }
    }
    return ids;
  }

  /**
   * Parse a textarea of {@code action:resource} (or {@code action resource}) lines into grants.
   * Blank and malformed lines are skipped — a console operator typing grants should not be able to
   * 500 the page.
   */
  private static List<GrantSpec> parseGrants(final String text) {
    if (text == null || text.isBlank()) {
      return List.of();
    }
    final List<GrantSpec> grants = new ArrayList<>();
    for (final String line : text.split("\\R")) {
      final String trimmed = line.trim();
      if (trimmed.isEmpty()) {
        continue;
      }
      final String[] parts = trimmed.split("[:\\s]+", 2);
      if (parts.length == 2 && !parts[0].isEmpty() && !parts[1].isEmpty()) {
        grants.add(new GrantSpec(parts[0].trim(), parts[1].trim()));
      }
    }
    return grants;
  }
}
