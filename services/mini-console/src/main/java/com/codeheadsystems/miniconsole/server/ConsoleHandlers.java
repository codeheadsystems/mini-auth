package com.codeheadsystems.miniconsole.server;

import com.codeheadsystems.miniclient.common.ClientException;
import com.codeheadsystems.miniconsole.harness.Exercise;
import com.codeheadsystems.miniconsole.harness.ExerciseRegistry;
import com.codeheadsystems.miniconsole.harness.ExerciseResult;
import com.codeheadsystems.miniconsole.harness.flows.CertLifecycleFlow;
import com.codeheadsystems.miniconsole.harness.flows.FullChainFlow;
import com.codeheadsystems.miniconsole.harness.flows.GatewayVerifyFlow;
import com.codeheadsystems.miniconsole.harness.flows.KeyRotationFlow;
import com.codeheadsystems.miniconsole.harness.flows.M2mTokenFlow;
import com.codeheadsystems.miniconsole.harness.flows.OidcCodePkceFlow;
import com.codeheadsystems.miniconsole.kms.KeyAdminException;
import com.codeheadsystems.miniconsole.kms.KeyGroupAdmin;
import com.codeheadsystems.miniconsole.pages.AuditPages;
import com.codeheadsystems.miniconsole.pages.CertificatesPages;
import com.codeheadsystems.miniconsole.pages.ClientsPages;
import com.codeheadsystems.miniconsole.pages.DashboardPage;
import com.codeheadsystems.miniconsole.pages.HarnessPages;
import com.codeheadsystems.miniconsole.pages.IdentitiesPages;
import com.codeheadsystems.miniconsole.pages.KeysPages;
import com.codeheadsystems.miniconsole.pages.LoginPage;
import com.codeheadsystems.miniconsole.server.http.ApiException;
import com.codeheadsystems.miniconsole.server.http.HttpResponse;
import com.codeheadsystems.miniconsole.server.http.RequestContext;
import com.codeheadsystems.miniconsole.server.http.Router;
import com.codeheadsystems.miniconsole.server.http.StaticResource;
import com.codeheadsystems.minica.client.MiniCaClient;
import com.codeheadsystems.minica.client.model.Certificate;
import com.codeheadsystems.minidirectory.client.MiniDirectoryClient;
import com.codeheadsystems.minidirectory.client.model.Assignment;
import com.codeheadsystems.minidirectory.client.model.GrantSpec;
import com.codeheadsystems.minidirectory.client.model.NewGroup;
import com.codeheadsystems.minidirectory.client.model.NewHuman;
import com.codeheadsystems.minidirectory.client.model.NewRole;
import com.codeheadsystems.minidirectory.client.model.NewServiceAccount;
import com.codeheadsystems.minidirectory.client.model.ServiceAccountCreated;
import com.codeheadsystems.minigateway.client.MiniGatewayClient;
import com.codeheadsystems.miniidp.client.MiniIdpClient;
import com.codeheadsystems.minikms.protocol.KeyGroupView;
import com.codeheadsystems.minioidc.client.MiniOidcClient;
import com.codeheadsystems.minioidc.client.model.ClientRegistration;
import com.codeheadsystems.minioidc.client.model.ClientSummary;
import com.codeheadsystems.minioidc.client.model.RegisteredClient;
import com.codeheadsystems.minitoken.jwks.Jwk;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Consumer;
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
  private final KeyGroupAdmin keys;
  private final MiniCaClient ca;
  private final MiniOidcClient oidc;
  private final MiniGatewayClient gateway;
  private final ExerciseRegistry exercises;
  private final M2mTokenFlow m2mFlow;
  private final KeyRotationFlow keyRotationFlow;
  private final CertLifecycleFlow certLifecycleFlow;
  private final OidcCodePkceFlow oidcFlow;
  private final GatewayVerifyFlow gatewayFlow;
  private final FullChainFlow fullChainFlow;
  private final OpenApiDocument openApi;

  /**
   * @param session           the console-login session store.
   * @param auth              the console-token constant-time comparator.
   * @param cookies           the cookie builder (console-specific names).
   * @param csrf              the double-submit CSRF helper.
   * @param sessionTtlSeconds the session cookie {@code Max-Age}.
   * @param directory         the mini-directory client, or null when the directory is not configured.
   * @param idp               the mini-idp client, or null when mini-idp is not configured.
   * @param keys              the KMS key-group admin port, or null when mini-kms is not configured.
   * @param ca                the mini-ca client, or null when mini-ca is not configured.
   * @param oidc              the mini-oidc client, or null when mini-oidc is not configured.
   * @param gateway           the mini-gateway client, or null when mini-gateway is not configured.
   * @param exercises         the exercise registry (for the Harness page listing).
   * @param m2mFlow           the machine-to-machine token flow (dispatched by its run route).
   * @param keyRotationFlow   the signing-key rotation flow (dispatched by its run route).
   * @param certLifecycleFlow the certificate-lifecycle flow (dispatched by its run route).
   * @param oidcFlow          the OIDC code+PKCE flow (dispatched by its run route).
   * @param gatewayFlow       the gateway forward-auth flow (dispatched by its run route).
   * @param fullChainFlow     the full-chain identity→token→gateway flow (dispatched by its run route).
   * @param openApi           the loaded OpenAPI spec for the read-only {@code /api} JSON surface.
   */
  public ConsoleHandlers(final ConsoleSession session, final AdminAuthenticator auth,
                         final Cookies cookies, final Csrf csrf, final long sessionTtlSeconds,
                         final MiniDirectoryClient directory, final MiniIdpClient idp,
                         final KeyGroupAdmin keys, final MiniCaClient ca, final MiniOidcClient oidc,
                         final MiniGatewayClient gateway, final ExerciseRegistry exercises,
                         final M2mTokenFlow m2mFlow, final KeyRotationFlow keyRotationFlow,
                         final CertLifecycleFlow certLifecycleFlow, final OidcCodePkceFlow oidcFlow,
                         final GatewayVerifyFlow gatewayFlow, final FullChainFlow fullChainFlow,
                         final OpenApiDocument openApi) {
    this.session = session;
    this.auth = auth;
    this.cookies = cookies;
    this.csrf = csrf;
    this.sessionTtlSeconds = sessionTtlSeconds;
    this.directory = directory;
    this.idp = idp;
    this.keys = keys;
    this.ca = ca;
    this.oidc = oidc;
    this.gateway = gateway;
    this.exercises = exercises;
    this.m2mFlow = m2mFlow;
    this.keyRotationFlow = keyRotationFlow;
    this.certLifecycleFlow = certLifecycleFlow;
    this.oidcFlow = oidcFlow;
    this.gatewayFlow = gatewayFlow;
    this.fullChainFlow = fullChainFlow;
    this.openApi = openApi;
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
        .route("POST", "/harness/key-rotation/run", this::runKeyRotation)
        .route("POST", "/harness/cert-lifecycle/run", this::runCertLifecycle)
        .route("POST", "/harness/oidc-pkce/run", this::runOidcPkce)
        .route("POST", "/harness/gateway-verify/run", this::runGatewayVerify)
        .route("POST", "/harness/full-chain/run", this::runFullChain)
        .route("POST", "/harness/run-all", this::runAll)
        // mini-oidc relying-party clients (Slice 6): list + register (one-time secret banner).
        .route("GET", "/clients", this::clients)
        .route("POST", "/clients", this::registerClient)
        // mini-ca certificates (Slice 5): issuance log + revocation list, issue/renew/revoke.
        .route("GET", "/certificates", this::certificates)
        .route("POST", "/certificates/issue", this::issueCert)
        .route("POST", "/certificates/renew", this::renewCert)
        .route("GET", "/certificates/revoke/confirm", this::revokeCertConfirm)
        .route("POST", "/certificates/revoke", this::revokeCert)
        // mini-kms key groups + idp signing-key rotation (Slice 4).
        .route("GET", "/keys", this::keysPage)
        .route("POST", "/keys/kms", this::createKeyGroup)
        .route("POST", "/keys/kms/{group}/rotate", this::rotateKeyGroup)
        .route("POST", "/keys/kms/{group}/disable", this::disableVersion)
        .route("POST", "/keys/kms/{group}/enable", this::enableVersion)
        .route("GET", "/keys/kms/{group}/destroy", this::destroyVersionConfirm)
        .route("POST", "/keys/kms/{group}/destroy", this::destroyVersion)
        .route("POST", "/keys/idp/rotate", this::rotateIdpKey)
        .route("POST", "/keys/oidc/rotate", this::rotateOidcKey)
        // The read-only JSON /api surface + its OpenAPI docs (Slice 8). The /api/* endpoints are
        // guarded by the console bearer token; the spec + Swagger UI are public (no secrets).
        .route("GET", "/api/health", this::apiHealth)
        .route("GET", "/api/harness", this::apiHarness)
        .route("GET", "/openapi.yaml", c -> HttpResponse.raw(200, "application/yaml", openApi.yaml()))
        .route("GET", "/openapi.json", c -> HttpResponse.raw(200, "application/json", openApi.json()))
        .route("GET", "/docs", c -> HttpResponse.text(200, "text/html; charset=utf-8", SwaggerUiPage.HTML))
        .route("GET", "/docs/swagger-ui.css",
            c -> HttpResponse.raw(200, "text/css", StaticResource.bytes("/swagger-ui/swagger-ui.css")))
        .route("GET", "/docs/swagger-ui-bundle.js",
            c -> HttpResponse.raw(200, "application/javascript",
                StaticResource.bytes("/swagger-ui/swagger-ui-bundle.js")))
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
        idp != null, idpStatus(), keys != null, keysStatus(), ca != null, caStatus(),
        oidc != null, oidcStatus(), gateway != null, gatewayStatus()), token);
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

  /** @return the live mini-kms status line for the Dashboard row (no secret, no oracle). */
  private String keysStatus() {
    if (keys == null) {
      return "not configured (set --kms-tcp)";
    }
    return keys.healthy() ? "healthy" : "unreachable";
  }

  /** @return the live mini-ca status line for the Dashboard row (no secret, no oracle). */
  private String caStatus() {
    if (ca == null) {
      return "not configured (set --ca-url)";
    }
    try {
      return "healthy (" + ca.health().status() + ")";
    } catch (final ClientException e) {
      return "unreachable";
    }
  }

  /** @return the live mini-oidc status line for the Dashboard row (no secret, no oracle). */
  private String oidcStatus() {
    if (oidc == null) {
      return "not configured (set --oidc-url)";
    }
    try {
      return "healthy (" + oidc.health().status() + ")";
    } catch (final ClientException e) {
      return "unreachable";
    }
  }

  /** @return the live mini-gateway status line for the Dashboard row (no secret, no oracle). */
  private String gatewayStatus() {
    if (gateway == null) {
      return "not configured (set --gateway-url)";
    }
    try {
      return "healthy (" + gateway.health().status() + ")";
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

  /** The Harness page: list the available exercises, gating each by whether its backend is wired. */
  private HttpResponse harness(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String token = csrf.mint();
    if (idp == null && ca == null && oidc == null && gateway == null) {
      return htmlWithCsrf(HarnessPages.notConfigured(token), token);
    }
    return htmlWithCsrf(HarnessPages.list(exercises, idp != null, ca != null, oidc != null,
        gateway != null, directory != null && idp != null && gateway != null, token), token);
  }

  /** Run the machine-to-machine token flow with the operator-supplied client id + secret. */
  private HttpResponse runM2mToken(final RequestContext context) {
    return runExercise(context, (clientId, secret) -> m2mFlow.run(idp, clientId, secret));
  }

  /**
   * Run the signing-key rotation flow with the operator-supplied client id + secret. NOTE: this
   * rotates a real mini-idp signing key (the Harness page warns the operator).
   */
  private HttpResponse runKeyRotation(final RequestContext context) {
    return runExercise(context, (clientId, secret) -> keyRotationFlow.run(idp, clientId, secret));
  }

  /**
   * Run the certificate-lifecycle flow. Unlike the idp flows it needs no operator credentials (it
   * generates its own CSR and uses the held CA admin token); it requires a session and a valid CSRF
   * token, and warns (on the Harness page) that it issues and revokes real certificates.
   */
  private HttpResponse runCertLifecycle(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String token = csrf.mint();
    if (!csrf.verify(context.cookie(Cookies.CSRF), context.formParams().get("csrf"))) {
      throw ApiException.badRequest("invalid or missing CSRF token");
    }
    if (ca == null) {
      return htmlWithCsrf(HarnessPages.notConfigured(token), token);
    }
    final ExerciseResult result = certLifecycleFlow.run(ca);
    return htmlWithCsrf(HarnessPages.result(result, token), token);
  }

  /**
   * Run the OIDC authorization-code + PKCE flow. Session-required and CSRF-guarded. The form supplies
   * a client id, redirect URI, and scope (always), plus an optional code + verifier + client secret to
   * complete the exchange after a manual passkey login. Without a code the flow honestly SKIPs the
   * interactive steps. The secret/code/verifier live only for the run and are never stored or logged.
   */
  private HttpResponse runOidcPkce(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String token = csrf.mint();
    if (oidc == null) {
      return htmlWithCsrf(HarnessPages.notConfigured(token), token);
    }
    final Map<String, String> form = context.formParams();
    if (!csrf.verify(context.cookie(Cookies.CSRF), form.get("csrf"))) {
      throw ApiException.badRequest("invalid or missing CSRF token");
    }
    final OidcCodePkceFlow.Inputs inputs = new OidcCodePkceFlow.Inputs(
        form.getOrDefault("clientId", ""), form.getOrDefault("redirectUri", ""),
        form.getOrDefault("scope", "openid"), form.getOrDefault("clientSecret", ""),
        form.getOrDefault("code", ""), form.getOrDefault("codeVerifier", ""));
    final ExerciseResult result = oidcFlow.run(oidc, inputs);
    return htmlWithCsrf(HarnessPages.result(result, token), token);
  }

  /**
   * Run the gateway forward-auth flow. Session-required and CSRF-guarded. The form supplies a gated
   * path (always) plus an optional bearer access token and a scope-gated path for the allow/forbid
   * branches; without a bearer the flow runs only the anonymous-denial branch. The bearer lives only
   * for the run and is never stored or logged.
   */
  private HttpResponse runGatewayVerify(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String token = csrf.mint();
    if (gateway == null) {
      return htmlWithCsrf(HarnessPages.notConfigured(token), token);
    }
    final Map<String, String> form = context.formParams();
    if (!csrf.verify(context.cookie(Cookies.CSRF), form.get("csrf"))) {
      throw ApiException.badRequest("invalid or missing CSRF token");
    }
    final GatewayVerifyFlow.Inputs inputs = new GatewayVerifyFlow.Inputs(
        form.getOrDefault("method", "GET"), form.getOrDefault("path", "/"),
        form.getOrDefault("bearerToken", ""), form.getOrDefault("scopePath", ""));
    final ExerciseResult result = gatewayFlow.run(gateway, inputs);
    return htmlWithCsrf(HarnessPages.result(result, token), token);
  }

  /**
   * Run the full-chain flow (identity → token → gateway, end to end). Session-required and
   * CSRF-guarded. It needs all three of mini-directory, mini-idp, and mini-gateway wired; the form
   * supplies the service-account id + secret (always) and an optional gated path. Without the
   * credentials the flow honestly SKIPs. The secret lives only for the run and is never stored or
   * logged.
   */
  private HttpResponse runFullChain(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String token = csrf.mint();
    if (directory == null || idp == null || gateway == null) {
      return htmlWithCsrf(HarnessPages.notConfigured(token), token);
    }
    final Map<String, String> form = context.formParams();
    if (!csrf.verify(context.cookie(Cookies.CSRF), form.get("csrf"))) {
      throw ApiException.badRequest("invalid or missing CSRF token");
    }
    final FullChainFlow.Inputs inputs = new FullChainFlow.Inputs(
        form.getOrDefault("clientId", ""), form.getOrDefault("clientSecret", ""),
        form.getOrDefault("path", "/"));
    final ExerciseResult result = fullChainFlow.run(directory, idp, gateway, inputs);
    return htmlWithCsrf(HarnessPages.result(result, token), token);
  }

  /**
   * Run every exercise that can run without operator-supplied credentials and render a summary line
   * plus each result. Session-required and CSRF-guarded. The flows that need a per-run secret (the m2m
   * token + signing-key rotation) are honestly reported SKIP rather than run with no credentials; the
   * certificate, OIDC, and gateway flows run their no-input/no-credential paths. No secret is ever
   * involved, so nothing here can leak one.
   */
  private HttpResponse runAll(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String token = csrf.mint();
    if (idp == null && ca == null && oidc == null && gateway == null) {
      return htmlWithCsrf(HarnessPages.notConfigured(token), token);
    }
    if (!csrf.verify(context.cookie(Cookies.CSRF), context.formParams().get("csrf"))) {
      throw ApiException.badRequest("invalid or missing CSRF token");
    }
    final List<ExerciseResult> results = new ArrayList<>();
    // The credential-needing token flows cannot run unattended — report SKIP, never a fake PASS.
    results.add(skipped(m2mFlow, "needs a client id + secret — run it individually from the Harness page"));
    results.add(skipped(keyRotationFlow,
        "needs a client id + secret (and rotates a real key) — run it individually"));
    // The certificate flow needs no input; run it when mini-ca is wired.
    results.add(ca != null ? certLifecycleFlow.run(ca)
        : skipped(certLifecycleFlow, "mini-ca is not configured (set --ca-url)"));
    // The OIDC flow runs its automatable parts and SKIPs the interactive login (no code supplied).
    results.add(oidc != null
        ? oidcFlow.run(oidc, new OidcCodePkceFlow.Inputs("", "", "openid", "", "", ""))
        : skipped(oidcFlow, "mini-oidc is not configured (set --oidc-url)"));
    // The gateway flow runs the anonymous-denial branch and SKIPs the bearer branches (no token).
    results.add(gateway != null
        ? gatewayFlow.run(gateway, new GatewayVerifyFlow.Inputs("GET", "/", "", ""))
        : skipped(gatewayFlow, "mini-gateway is not configured (set --gateway-url)"));
    // The full chain needs a service-account id + secret — report SKIP, never a fake PASS.
    results.add(skipped(fullChainFlow,
        "needs a service-account id + secret — run it individually from the Harness page"));
    return htmlWithCsrf(HarnessPages.summary(results, token), token);
  }

  /** @return a synthetic SKIP result for an exercise that could not be run unattended. */
  private static ExerciseResult skipped(final Exercise exercise, final String reason) {
    return new ExerciseResult(exercise.id(), exercise.title(), ExerciseResult.Status.SKIP,
        List.of(new ExerciseResult.Step("Not run", ExerciseResult.Status.SKIP, reason)), reason);
  }

  // ---- Read-only JSON /api surface (Slice 8) -------------------------------------------------

  /**
   * The health rollup as JSON — the programmatic twin of the Dashboard. Guarded by the console bearer
   * token (401 on a missing/wrong token, no oracle). Never returns a secret.
   */
  private HttpResponse apiHealth(final RequestContext context) {
    auth.requireAdmin(context.header("Authorization"));
    final List<Map<String, Object>> services = new ArrayList<>();
    services.add(service("mini-directory", directory != null, directoryStatus()));
    services.add(service("mini-idp", idp != null, idpStatus()));
    services.add(service("mini-kms", keys != null, keysStatus()));
    services.add(service("mini-ca", ca != null, caStatus()));
    services.add(service("mini-oidc", oidc != null, oidcStatus()));
    services.add(service("mini-gateway", gateway != null, gatewayStatus()));
    return HttpResponse.json(200, Map.of("services", services));
  }

  /** One service row for the {@code /api/health} rollup. */
  private static Map<String, Object> service(final String name, final boolean configured,
                                             final String status) {
    final Map<String, Object> row = new LinkedHashMap<>();
    row.put("name", name);
    row.put("configured", configured);
    row.put("status", status);
    return row;
  }

  /**
   * The exercise-harness catalog as JSON: each exercise plus whether its backend is wired. Guarded by
   * the console bearer token. Read-only — running an exercise stays a CSRF-guarded HTML POST.
   */
  private HttpResponse apiHarness(final RequestContext context) {
    auth.requireAdmin(context.header("Authorization"));
    final List<Map<String, Object>> list = new ArrayList<>();
    for (final Exercise exercise : exercises.all()) {
      final Map<String, Object> row = new LinkedHashMap<>();
      row.put("id", exercise.id());
      row.put("title", exercise.title());
      row.put("description", exercise.description());
      row.put("available", exerciseAvailable(exercise.id()));
      list.add(row);
    }
    return HttpResponse.json(200, Map.of("exercises", list));
  }

  /** @return whether the backend client an exercise needs is wired. */
  private boolean exerciseAvailable(final String exerciseId) {
    if (CertLifecycleFlow.ID.equals(exerciseId)) {
      return ca != null;
    }
    if (OidcCodePkceFlow.ID.equals(exerciseId)) {
      return oidc != null;
    }
    if (GatewayVerifyFlow.ID.equals(exerciseId)) {
      return gateway != null;
    }
    if (FullChainFlow.ID.equals(exerciseId)) {
      // The full chain spans the directory, the IDP, and the gateway — all three must be wired.
      return directory != null && idp != null && gateway != null;
    }
    // The remaining flows (m2m token, signing-key rotation) are backed by mini-idp.
    return idp != null;
  }

  // ---- mini-oidc: relying-party clients (Slice 6) --------------------------------------------

  /** The registered OIDC clients (read-only); "not configured" without an OP, generic on failure. */
  private HttpResponse clients(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String token = csrf.mint();
    if (oidc == null) {
      return htmlWithCsrf(ClientsPages.notConfigured(token), token);
    }
    try {
      final List<ClientSummary> list = oidc.listClients();
      return htmlWithCsrf(ClientsPages.list(list, token), token);
    } catch (final ClientException e) {
      return htmlWithCsrf(ClientsPages.unavailable(token), token);
    }
  }

  /**
   * Register a relying-party client. CSRF-guarded; on success renders the one-time client secret in a
   * banner DIRECTLY (a redirect would lose it) — shown once, never stored, never re-fetchable, never
   * logged. A public (PKCE-only) client has no secret.
   */
  private HttpResponse registerClient(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String token = csrf.mint();
    if (oidc == null) {
      return htmlWithCsrf(ClientsPages.notConfigured(token), token);
    }
    final Map<String, String> form = context.formParams();
    if (!csrf.verify(context.cookie(Cookies.CSRF), form.get("csrf"))) {
      throw ApiException.badRequest("invalid or missing CSRF token");
    }
    try {
      final RegisteredClient created = oidc.registerClient(new ClientRegistration(
          form.getOrDefault("name", ""), splitLines(form.get("redirectUris")),
          splitSpaces(form.getOrDefault("scopes", "openid")),
          "true".equals(form.get("confidential"))));
      // Direct HTML (not a redirect): the secret (if any) is shown here and only here.
      return htmlWithCsrf(ClientsPages.registered(created, token), token);
    } catch (final ClientException e) {
      return htmlWithCsrf(ClientsPages.unavailable(token), token);
    }
  }

  /** The shared guard for running a harness exercise: session-required and CSRF-guarded, the operator-
   * supplied credentials are used for the single run and never stored or logged, and the rendered
   * result carries only the non-secret facts the flow returned.
   *
   * @param context the request.
   * @param runner  the flow, given {@code (clientId, clientSecret)}; returns the result.
   * @return the result page, or a redirect/not-configured page.
   */
  private HttpResponse runExercise(final RequestContext context,
                                   final BiFunction<String, String, ExerciseResult> runner) {
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
        runner.apply(form.getOrDefault("clientId", ""), form.getOrDefault("clientSecret", ""));
    return htmlWithCsrf(HarnessPages.result(result, token), token);
  }

  // ---- mini-kms key groups + idp signing-key rotation (Slice 4) -------------------------------

  /** The Keys page: live mini-kms key groups and the mini-idp signing-key status. */
  private HttpResponse keysPage(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    return keysRerender();
  }

  /** Re-render the Keys page with a fresh CSRF token (used by GET /keys and after a mutation). */
  private HttpResponse keysRerender() {
    final String token = csrf.mint();
    return htmlWithCsrf(renderKeys(token), token);
  }

  /** Render the Keys page for the given CSRF token, resolving each backend's live state (no oracle). */
  private String renderKeys(final String token) {
    KeysPages.Availability kmsState;
    List<KeyGroupView> groups = List.of();
    if (keys == null) {
      kmsState = KeysPages.Availability.NOT_CONFIGURED;
    } else {
      try {
        groups = keys.listGroups();
        kmsState = KeysPages.Availability.OK;
      } catch (final KeyAdminException e) {
        kmsState = KeysPages.Availability.UNAVAILABLE;
      }
    }

    KeysPages.Availability idpState;
    List<String> kids = List.of();
    if (idp == null) {
      idpState = KeysPages.Availability.NOT_CONFIGURED;
    } else {
      try {
        kids = idp.jwks().keys().stream().map(Jwk::keyId).toList();
        idpState = KeysPages.Availability.OK;
      } catch (final ClientException e) {
        idpState = KeysPages.Availability.UNAVAILABLE;
      }
    }

    KeysPages.Availability oidcState;
    List<String> oidcKids = List.of();
    if (oidc == null) {
      oidcState = KeysPages.Availability.NOT_CONFIGURED;
    } else {
      try {
        oidcKids = oidc.jwks().keys().stream().map(Jwk::keyId).toList();
        oidcState = KeysPages.Availability.OK;
      } catch (final ClientException e) {
        oidcState = KeysPages.Availability.UNAVAILABLE;
      }
    }
    return KeysPages.render(kmsState, groups, idpState, kids, oidcState, oidcKids, token);
  }

  /** Create a KMS key group (CSRF-guarded). */
  private HttpResponse createKeyGroup(final RequestContext context) {
    return keysMutate(context, form -> keys.createGroup(requireField(form, "keyId")));
  }

  /** Rotate a KMS key group — mint a new active version (CSRF-guarded). */
  private HttpResponse rotateKeyGroup(final RequestContext context) {
    final String group = context.pathParam("group");
    return keysMutate(context, form -> keys.rotateGroup(group));
  }

  /** Disable a non-active KMS key version (CSRF-guarded). */
  private HttpResponse disableVersion(final RequestContext context) {
    final String group = context.pathParam("group");
    return keysMutate(context, form -> keys.disableVersion(group, version(form)));
  }

  /** Re-enable a disabled KMS key version (CSRF-guarded). */
  private HttpResponse enableVersion(final RequestContext context) {
    final String group = context.pathParam("group");
    return keysMutate(context, form -> keys.enableVersion(group, version(form)));
  }

  /** Confirm-step page for destroying a KMS key version (GET, no mutation). */
  private HttpResponse destroyVersionConfirm(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final long version;
    try {
      version = Long.parseLong(context.queryParam("version"));
    } catch (final NumberFormatException e) {
      throw ApiException.badRequest("invalid version");
    }
    final String token = csrf.mint();
    return htmlWithCsrf(KeysPages.confirmDestroy(context.pathParam("group"), version, token), token);
  }

  /** Destroy a non-active KMS key version — irreversible (CSRF-guarded, reached via the confirm page). */
  private HttpResponse destroyVersion(final RequestContext context) {
    final String group = context.pathParam("group");
    return keysMutate(context, form -> keys.destroyVersion(group, version(form)));
  }

  /** Rotate the mini-idp signing key (CSRF-guarded); redirect back to /keys on success. */
  private HttpResponse rotateIdpKey(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final Map<String, String> form = context.formParams();
    if (!csrf.verify(context.cookie(Cookies.CSRF), form.get("csrf"))) {
      throw ApiException.badRequest("invalid or missing CSRF token");
    }
    if (idp == null) {
      return keysRerender();
    }
    try {
      idp.rotateSigningKey();
      return HttpResponse.redirect("/keys");
    } catch (final ClientException e) {
      // A refused admin token and an unreachable IDP look the same — no oracle.
      return keysRerender();
    }
  }

  /** Rotate the mini-oidc signing key (CSRF-guarded); redirect back to /keys on success. */
  private HttpResponse rotateOidcKey(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final Map<String, String> form = context.formParams();
    if (!csrf.verify(context.cookie(Cookies.CSRF), form.get("csrf"))) {
      throw ApiException.badRequest("invalid or missing CSRF token");
    }
    if (oidc == null) {
      return keysRerender();
    }
    try {
      oidc.rotateSigningKey();
      return HttpResponse.redirect("/keys");
    } catch (final ClientException e) {
      // A refused admin token and an unreachable OP look the same — no oracle.
      return keysRerender();
    }
  }

  /**
   * The shared guard for every KMS key mutation: require a session, short-circuit if no KMS is
   * configured, verify CSRF before any side effect, run the operation, and Post/Redirect/Get back to
   * the Keys page. Any {@link KeyAdminException} collapses to a re-render of the current state (no
   * oracle — the failed operation simply did not happen, with no reason shown).
   */
  private HttpResponse keysMutate(final RequestContext context,
                                  final Consumer<Map<String, String>> action) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final Map<String, String> form = context.formParams();
    if (!csrf.verify(context.cookie(Cookies.CSRF), form.get("csrf"))) {
      throw ApiException.badRequest("invalid or missing CSRF token");
    }
    if (keys == null) {
      return keysRerender();
    }
    try {
      action.accept(form);
      return HttpResponse.redirect("/keys");
    } catch (final KeyAdminException e) {
      return keysRerender();
    }
  }

  /** Parse the {@code version} form field as a long, or 400 (generic). */
  private static long version(final Map<String, String> form) {
    try {
      return Long.parseLong(form.getOrDefault("version", ""));
    } catch (final NumberFormatException e) {
      throw ApiException.badRequest("invalid version");
    }
  }

  /** @return the trimmed required field, or 400 (generic) when blank. */
  private static String requireField(final Map<String, String> form, final String name) {
    final String value = form.get(name);
    if (value == null || value.isBlank()) {
      throw ApiException.badRequest("missing " + name);
    }
    return value.trim();
  }

  // ---- mini-ca certificates (Slice 5) --------------------------------------------------------

  /** The Certificates page: the CA root, the issuance log, and the revocation list (read-only). */
  private HttpResponse certificates(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String token = csrf.mint();
    if (ca == null) {
      return htmlWithCsrf(CertificatesPages.notConfigured(token), token);
    }
    try {
      return htmlWithCsrf(CertificatesPages.overview(ca.caCertificatePem(), ca.issuanceLog(),
          ca.revocations(), token), token);
    } catch (final ClientException e) {
      // A refused admin token and an unreachable CA look the same — no oracle.
      return htmlWithCsrf(CertificatesPages.unavailable(token), token);
    }
  }

  /** Issue a leaf from a pasted CSR (CSRF-guarded); render the issued certificate directly. */
  private HttpResponse issueCert(final RequestContext context) {
    return certMutate(context, form -> {
      final Certificate cert = ca.issue(requireField(form, "csr"), ttl(form.get("ttlSeconds")));
      return page(t -> CertificatesPages.issued(cert, t));
    });
  }

  /** Renew a leaf from a pasted CSR, optionally revoking a previous serial (CSRF-guarded). */
  private HttpResponse renewCert(final RequestContext context) {
    return certMutate(context, form -> {
      final Certificate cert = ca.renew(requireField(form, "csr"), ttl(form.get("ttlSeconds")),
          blankToNull(form.get("previousSerial")));
      return page(t -> CertificatesPages.issued(cert, t));
    });
  }

  /** Confirm-step page for revoking a certificate (GET, no mutation). Serial/reason are public. */
  private HttpResponse revokeCertConfirm(final RequestContext context) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final String serial = context.queryParam("serial");
    if (serial == null || serial.isBlank()) {
      throw ApiException.badRequest("serial is required");
    }
    final String token = csrf.mint();
    return htmlWithCsrf(
        CertificatesPages.confirmRevoke(serial, context.queryParam("reason"), token), token);
  }

  /** Revoke a certificate (CSRF-guarded, reached via the confirm page); redirect to /certificates. */
  private HttpResponse revokeCert(final RequestContext context) {
    return certMutate(context, form -> {
      ca.revoke(requireField(form, "serial"), blankToNull(form.get("reason")));
      return HttpResponse.redirect("/certificates");
    });
  }

  /**
   * The shared guard for every mini-ca mutation: require a session, verify CSRF before any side
   * effect, short-circuit if no CA is configured, run the action, and collapse any
   * {@link ClientException} to a generic page (no oracle — a malformed CSR, a refused admin token, and
   * an unreachable CA look alike; the CA itself returns one generic 400 for any bad CSR).
   */
  private HttpResponse certMutate(final RequestContext context,
                                  final Function<Map<String, String>, HttpResponse> action) {
    final HttpResponse redirect = requireSession(context);
    if (redirect != null) {
      return redirect;
    }
    final Map<String, String> form = context.formParams();
    if (!csrf.verify(context.cookie(Cookies.CSRF), form.get("csrf"))) {
      throw ApiException.badRequest("invalid or missing CSRF token");
    }
    if (ca == null) {
      return page(CertificatesPages::notConfigured);
    }
    try {
      return action.apply(form);
    } catch (final ClientException e) {
      return page(CertificatesPages::unavailable);
    }
  }

  /** Parse an optional {@code ttlSeconds} form field into a {@link Duration}, or null (CA default). */
  private static Duration ttl(final String seconds) {
    if (seconds == null || seconds.isBlank()) {
      return null;
    }
    try {
      final long value = Long.parseLong(seconds.trim());
      return value > 0 ? Duration.ofSeconds(value) : null;
    } catch (final NumberFormatException e) {
      throw ApiException.badRequest("invalid ttlSeconds");
    }
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

  /** Parse a newline-separated textarea (one redirect URI per line) into a blank-free list. */
  private static List<String> splitLines(final String text) {
    return splitOn(text, "\\R+");
  }

  /** Parse a whitespace-separated field (e.g. OAuth scopes) into a blank-free list. */
  private static List<String> splitSpaces(final String text) {
    return splitOn(text, "\\s+");
  }

  private static List<String> splitOn(final String text, final String regex) {
    if (text == null || text.isBlank()) {
      return List.of();
    }
    final List<String> items = new ArrayList<>();
    for (final String part : text.trim().split(regex)) {
      final String trimmed = part.trim();
      if (!trimmed.isEmpty()) {
        items.add(trimmed);
      }
    }
    return items;
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
