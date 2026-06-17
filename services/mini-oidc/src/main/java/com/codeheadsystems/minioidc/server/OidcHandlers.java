package com.codeheadsystems.minioidc.server;

import com.codeheadsystems.minioidc.auth.HumanAuthenticator;
import com.codeheadsystems.minioidc.auth.RecoveryAuthenticator;
import com.codeheadsystems.minioidc.directory.DirectoryUser;
import com.codeheadsystems.minioidc.directory.UserDirectory;
import com.codeheadsystems.minioidc.model.AuthorizationCode;
import com.codeheadsystems.minioidc.model.BrowserSession;
import com.codeheadsystems.minioidc.model.OidcClient;
import com.codeheadsystems.minioidc.model.PendingAuthorization;
import com.codeheadsystems.minioidc.server.dto.Dtos.ClientView;
import com.codeheadsystems.minioidc.server.dto.Dtos.RegisterClientRequest;
import com.codeheadsystems.minioidc.server.dto.Dtos.RegisterClientResponse;
import com.codeheadsystems.minioidc.server.http.ApiException;
import com.codeheadsystems.minioidc.server.http.HttpResponse;
import com.codeheadsystems.minioidc.server.http.Json;
import com.codeheadsystems.minioidc.server.http.RequestContext;
import com.codeheadsystems.minioidc.server.http.Router;
import com.codeheadsystems.minioidc.server.http.StaticResource;
import com.codeheadsystems.minioidc.service.AuthorizationCodeStore;
import com.codeheadsystems.minioidc.service.ClientService;
import com.codeheadsystems.minioidc.service.OidcTokens;
import com.codeheadsystems.minioidc.service.PendingAuthorizationStore;
import com.codeheadsystems.minioidc.service.RefreshTokenService;
import com.codeheadsystems.minioidc.service.ScopeAuthorizer;
import com.codeheadsystems.minioidc.service.SessionService;
import com.codeheadsystems.minioidc.util.Pkce;
import com.codeheadsystems.minioidc.util.Tokens;
import tools.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Builds the {@link Router} and implements every OpenID Provider endpoint: discovery + JWKS,
 * the browser authorization-code + PKCE flow (authorize → login/consent → code), the token endpoint
 * (code and refresh grants), {@code /userinfo}, single logout, passkey enrolment, and the
 * client-admin API.
 *
 * <p>Conventions mirror mini-idp: handlers are thin, all crypto/identity logic lives in services,
 * no secret material is logged or echoed (except the one-time client secret at registration), and
 * authentication/grant failures collapse to a single generic error — never an oracle. The browser
 * POSTs ({@code /login/**}, {@code /authorize/decision}) are CSRF-protected by a token bound to the
 * server-side pending authorization.
 */
public final class OidcHandlers {

  private final ServerConfig config;
  private final ClientService clients;
  private final OidcTokens tokens;
  private final ScopeAuthorizer scopeAuthorizer;
  private final UserDirectory directory;
  private final HumanAuthenticator humans;
  private final RecoveryAuthenticator recovery;
  private final SessionService sessions;
  private final PendingAuthorizationStore pending;
  private final AuthorizationCodeStore codes;
  private final RefreshTokenService refreshTokens;
  private final AdminAuthenticator adminAuth;
  private final OpenApiDocument openApi;
  private final Cookies cookies;
  private final Tokens tokenGen;
  private final Clock clock;

  public OidcHandlers(final ServerConfig config, final ClientService clients, final OidcTokens tokens,
                      final ScopeAuthorizer scopeAuthorizer, final UserDirectory directory,
                      final HumanAuthenticator humans, final RecoveryAuthenticator recovery,
                      final SessionService sessions, final PendingAuthorizationStore pending,
                      final AuthorizationCodeStore codes, final RefreshTokenService refreshTokens,
                      final AdminAuthenticator adminAuth, final OpenApiDocument openApi,
                      final Tokens tokenGen, final Clock clock) {
    this.config = config;
    this.clients = clients;
    this.tokens = tokens;
    this.scopeAuthorizer = scopeAuthorizer;
    this.directory = directory;
    this.humans = humans;
    this.recovery = recovery;
    this.sessions = sessions;
    this.pending = pending;
    this.codes = codes;
    this.refreshTokens = refreshTokens;
    this.adminAuth = adminAuth;
    this.openApi = openApi;
    this.cookies = new Cookies(config.secureCookies());
    this.tokenGen = tokenGen;
    this.clock = clock;
  }

  /** @return a router with every route registered. */
  public Router router() {
    final Router router = new Router();
    // Discovery + keys + meta.
    router.route("GET", "/health", ctx -> HttpResponse.json(200, Map.of("status", "ok")));
    router.route("GET", "/.well-known/openid-configuration", this::discovery);
    router.route("GET", "/jwks.json", this::jwks);
    router.route("GET", "/openapi.yaml", ctx -> HttpResponse.raw(200, "application/yaml", openApi.yaml()));
    router.route("GET", "/openapi.json", ctx -> HttpResponse.raw(200, "application/json", openApi.json()));
    router.route("GET", "/docs", ctx -> HttpResponse.html(SwaggerUiPage.HTML));
    router.route("GET", "/docs/swagger-ui.css",
        ctx -> HttpResponse.raw(200, "text/css", StaticResource.bytes("/swagger-ui/swagger-ui.css")));
    router.route("GET", "/docs/swagger-ui-bundle.js",
        ctx -> HttpResponse.raw(200, "application/javascript", StaticResource.bytes("/swagger-ui/swagger-ui-bundle.js")));

    // Browser authorization-code + PKCE flow.
    router.route("GET", "/authorize", this::authorize);
    router.route("GET", "/authorize/continue", this::authorizeContinue);
    router.route("POST", "/authorize/decision", this::decision);
    router.route("POST", "/login/passkey/start", this::passkeyStart);
    router.route("POST", "/login/passkey/finish", this::passkeyFinish);
    router.route("POST", "/login/recovery", this::recoveryLogin);

    // Token + userinfo + logout.
    router.route("POST", "/token", this::token);
    router.route("GET", "/userinfo", this::userinfo);
    router.route("GET", "/logout", this::logout);

    // Passkey enrolment (unauthenticated self-enrolment — see the security note in the README).
    router.route("POST", "/register/passkey/start", this::registerStart);
    router.route("POST", "/register/passkey/finish", this::registerFinish);

    // Client admin.
    router.route("POST", "/admin/clients", this::registerClient);
    router.route("GET", "/admin/clients", this::listClients);
    return router;
  }

  // ---- Discovery / JWKS ----------------------------------------------------------------------

  private HttpResponse discovery(final RequestContext ctx) {
    final String iss = config.issuer();
    final Map<String, Object> doc = new LinkedHashMap<>();
    doc.put("issuer", iss);
    doc.put("authorization_endpoint", iss + "/authorize");
    doc.put("token_endpoint", iss + "/token");
    doc.put("userinfo_endpoint", iss + "/userinfo");
    doc.put("jwks_uri", iss + "/jwks.json");
    doc.put("end_session_endpoint", iss + "/logout");
    doc.put("response_types_supported", List.of("code"));
    doc.put("grant_types_supported", List.of("authorization_code", "refresh_token"));
    doc.put("scopes_supported", List.of("openid", "profile", "email"));
    doc.put("subject_types_supported", List.of("public"));
    doc.put("id_token_signing_alg_values_supported", List.of("EdDSA"));
    doc.put("token_endpoint_auth_methods_supported",
        List.of("client_secret_basic", "client_secret_post", "none"));
    doc.put("code_challenge_methods_supported", List.of(Pkce.METHOD_S256, Pkce.METHOD_PLAIN));
    return HttpResponse.json(200, doc);
  }

  private HttpResponse jwks(final RequestContext ctx) {
    return HttpResponse.json(200, tokens.jwkSet());
  }

  // ---- Authorization endpoint ----------------------------------------------------------------

  private HttpResponse authorize(final RequestContext ctx) {
    final Map<String, String> q = ctx.queryParams();
    final OidcClient client = clients.get(q.get("client_id"))
        .orElseThrow(() -> ApiException.badRequest("unknown client_id"));
    final String redirectUri = q.get("redirect_uri");
    if (!client.allowsRedirect(redirectUri)) {
      // Never redirect to an unregistered URI — that is how codes get phished.
      throw ApiException.badRequest("redirect_uri is not registered for this client");
    }
    final String state = q.get("state");
    // From here, validation errors are reported by redirecting to the (trusted) redirect_uri.
    if (!"code".equals(q.get("response_type"))) {
      return errorRedirect(redirectUri, "unsupported_response_type", state);
    }
    final List<String> scopes = splitScopes(q.get("scope"));
    if (!scopes.contains(ScopeAuthorizer.OPENID)) {
      return errorRedirect(redirectUri, "invalid_scope", state);
    }
    final String challenge = q.get("code_challenge");
    final String method = q.getOrDefault("code_challenge_method", Pkce.METHOD_PLAIN);
    if (challenge == null || challenge.isBlank() || !Pkce.isSupportedMethod(method)) {
      // PKCE is mandatory for every authorization-code request.
      return errorRedirect(redirectUri, "invalid_request", state);
    }

    final PendingAuthorization request = new PendingAuthorization(
        tokenGen.newRequestId(), client.clientId(), redirectUri, "code", scopes, state,
        q.get("nonce"), challenge, method, tokenGen.newCsrfToken(),
        clock.instant().getEpochSecond());
    pending.put(request);

    return currentSession(ctx).isPresent()
        ? consentPage(request)
        : HttpResponse.html(LoginPages.login(request.requestId(), request.csrfToken()));
  }

  private HttpResponse authorizeContinue(final RequestContext ctx) {
    final PendingAuthorization request = pending.get(ctx.queryParam("req"))
        .orElseThrow(() -> ApiException.badRequest("unknown or expired authorization request"));
    if (currentSession(ctx).isEmpty()) {
      return HttpResponse.html(LoginPages.login(request.requestId(), request.csrfToken()));
    }
    return consentPage(request);
  }

  private HttpResponse consentPage(final PendingAuthorization request) {
    final String clientName = clients.get(request.clientId()).map(OidcClient::name).orElse(request.clientId());
    return HttpResponse.html(LoginPages.consent(
        request.requestId(), request.csrfToken(), clientName, request.scopes()));
  }

  private HttpResponse decision(final RequestContext ctx) {
    final Map<String, String> form = ctx.formParams();
    final PendingAuthorization request = pending.get(form.get("requestId"))
        .orElseThrow(() -> ApiException.badRequest("unknown or expired authorization request"));
    final BrowserSession session = currentSession(ctx)
        .orElseThrow(() -> ApiException.badRequest("no active session"));
    requireCsrf(request, form.get("csrf"));
    pending.remove(request.requestId());

    if (!"approve".equals(form.get("decision"))) {
      return errorRedirect(request.redirectUri(), "access_denied", request.state());
    }
    // Scope authorization backstop: only issue scopes mini-policy allows for this user.
    final DirectoryUser user = directory.resolve(session.subject())
        .orElseThrow(() -> ApiException.badRequest("user no longer resolvable"));
    final List<String> granted = scopeAuthorizer.authorize(user, request.scopes());

    final String code = tokenGen.newCode();
    codes.put(new AuthorizationCode(code, request.clientId(), request.redirectUri(), session.subject(),
        granted, request.nonce(), request.codeChallenge(), request.codeChallengeMethod(),
        session.authTime(), clock.instant().getEpochSecond() + config.codeTtl().toSeconds()));
    final Map<String, String> params = new LinkedHashMap<>();
    params.put("code", code);
    if (request.state() != null) {
      params.put("state", request.state());
    }
    return HttpResponse.redirect(appendQuery(request.redirectUri(), params));
  }

  // ---- Login (passkey + recovery) ------------------------------------------------------------

  private HttpResponse passkeyStart(final RequestContext ctx) {
    final JsonNode body = readJson(ctx);
    requirePending(text(body, "requestId"));
    final HumanAuthenticator.Challenge challenge = humans.startAssertion(text(body, "username"));
    // The options JSON already contains challengeId + publicKey; hand it to the browser verbatim.
    return HttpResponse.raw(200, "application/json",
        challenge.optionsJson().getBytes(StandardCharsets.UTF_8));
  }

  private HttpResponse passkeyFinish(final RequestContext ctx) {
    final JsonNode body = readJson(ctx);
    final PendingAuthorization request = requirePending(text(body, "requestId"));
    requireCsrf(request, text(body, "csrf"));
    final Optional<String> username = humans.finishAssertion(
        text(body, "challengeId"), body.get("assertion").toString());
    return completeLogin(request, username);
  }

  private HttpResponse recoveryLogin(final RequestContext ctx) {
    final Map<String, String> form = ctx.formParams();
    final PendingAuthorization request = requirePending(form.get("requestId"));
    requireCsrf(request, form.get("csrf"));
    final Optional<String> username = recovery.recoverWithBackupCode(form.get("username"), form.get("code"));
    if (username.isEmpty() || directory.resolve(username.get()).isEmpty()) {
      throw ApiException.unauthorized();
    }
    final String sessionId = sessions.create(username.get(), clock.instant().getEpochSecond());
    return HttpResponse.redirect("/authorize/continue?req=" + request.requestId())
        .header("Set-Cookie", cookies.session(sessionId, config.sessionTtl().toSeconds()));
  }

  /** Establish a session for a just-authenticated human and point the browser at consent. */
  private HttpResponse completeLogin(final PendingAuthorization request, final Optional<String> username) {
    if (username.isEmpty() || directory.resolve(username.get()).isEmpty()) {
      // One generic failure regardless of which check failed (no oracle).
      throw ApiException.unauthorized();
    }
    final String sessionId = sessions.create(username.get(), clock.instant().getEpochSecond());
    return HttpResponse.json(200, Map.of("next", "/authorize/continue?req=" + request.requestId()))
        .header("Set-Cookie", cookies.session(sessionId, config.sessionTtl().toSeconds()));
  }

  // ---- Token endpoint ------------------------------------------------------------------------

  private HttpResponse token(final RequestContext ctx) {
    final Map<String, String> form = ctx.formParams();
    final String grantType = form.get("grant_type");
    final OidcClient client = authenticateClient(ctx, form);
    if ("authorization_code".equals(grantType)) {
      return authorizationCodeGrant(form, client);
    }
    if ("refresh_token".equals(grantType)) {
      return refreshGrant(form, client);
    }
    throw ApiException.oauth("unsupported_grant_type", "unsupported grant_type");
  }

  private HttpResponse authorizationCodeGrant(final Map<String, String> form, final OidcClient client) {
    final String codeValue = form.get("code");
    final Optional<AuthorizationCode> redeemed = codes.consume(codeValue);
    if (redeemed.isEmpty()) {
      // A replayed code revokes the tokens it previously produced, then fails like any bad grant.
      if (codes.wasUsed(codeValue)) {
        codes.familyFor(codeValue).ifPresent(refreshTokens::revokeFamily);
      }
      throw ApiException.invalidGrant();
    }
    final AuthorizationCode code = redeemed.get();
    if (!code.clientId().equals(client.clientId())
        || !code.redirectUri().equals(form.get("redirect_uri"))
        || !Pkce.verify(code.codeChallengeMethod(), code.codeChallenge(), form.get("code_verifier"))) {
      throw ApiException.invalidGrant();
    }
    final DirectoryUser user = directory.resolve(code.subject())
        .orElse(new DirectoryUser(code.subject(), false, List.of(), null, null, false));
    final OidcTokens.AccessToken access = tokens.mintAccessToken(code.subject(), client.clientId(), code.scopes());
    final String idToken = tokens.mintIdToken(user, client.clientId(), code.nonce(), code.authTime(), code.scopes());
    final String refresh = refreshTokens.issue(client.clientId(), code.subject(), code.scopes());
    codes.bindFamily(codeValue, refresh.substring(0, refresh.indexOf('.')));
    return tokenResponse(access, idToken, refresh, code.scopes());
  }

  private HttpResponse refreshGrant(final Map<String, String> form, final OidcClient client) {
    final RefreshTokenService.Rotated rotated = refreshTokens.rotate(form.get("refresh_token"), client.clientId())
        .orElseThrow(ApiException::invalidGrant);
    final DirectoryUser user = directory.resolve(rotated.subject())
        .orElse(new DirectoryUser(rotated.subject(), false, List.of(), null, null, false));
    final OidcTokens.AccessToken access = tokens.mintAccessToken(rotated.subject(), client.clientId(), rotated.scopes());
    final String idToken = tokens.mintIdToken(user, client.clientId(), null, clock.instant().getEpochSecond(), rotated.scopes());
    return tokenResponse(access, idToken, rotated.wireToken(), rotated.scopes());
  }

  private HttpResponse tokenResponse(final OidcTokens.AccessToken access, final String idToken,
                                     final String refresh, final List<String> scopes) {
    final Map<String, Object> body = new LinkedHashMap<>();
    body.put("access_token", access.token());
    body.put("token_type", "Bearer");
    body.put("expires_in", access.expiresIn());
    body.put("id_token", idToken);
    body.put("refresh_token", refresh);
    body.put("scope", String.join(" ", scopes));
    return HttpResponse.json(200, body);
  }

  /**
   * Resolve and authenticate the client at the token endpoint: a confidential client must present a
   * matching secret (client_secret_post or HTTP Basic); a public client is identified by id and
   * relies on PKCE. One generic {@code invalid_client} on failure (no oracle).
   */
  private OidcClient authenticateClient(final RequestContext ctx, final Map<String, String> form) {
    final String[] basic = basicCredentials(ctx.header("Authorization"));
    final String clientId = form.getOrDefault("client_id", basic == null ? null : basic[0]);
    final String secret = form.getOrDefault("client_secret", basic == null ? null : basic[1]);
    final OidcClient client = clients.get(clientId).orElseThrow(ApiException::invalidClient);
    if (client.isConfidential()) {
      if (secret == null) {
        throw ApiException.invalidClient();
      }
      final char[] chars = secret.toCharArray();
      try {
        if (!clients.authenticate(clientId, chars)) {
          throw ApiException.invalidClient();
        }
      } finally {
        Arrays.fill(chars, '\0');
      }
    }
    return client;
  }

  // ---- UserInfo ------------------------------------------------------------------------------

  private HttpResponse userinfo(final RequestContext ctx) {
    final String header = ctx.header("Authorization");
    final String bearer = header != null && header.regionMatches(true, 0, "Bearer ", 0, 7)
        ? header.substring(7).trim() : null;
    final Optional<JsonNode> claims = bearer == null ? Optional.empty()
        : com.codeheadsystems.minioidc.service.OidcTokenVerifier.verify(
            bearer, tokens.jwkSet(), config.issuer(), tokens.accessAudience(), clock, 5);
    if (claims.isEmpty()) {
      // RFC 6750: a bad/expired token gets a generic 401 challenge, no detail.
      return HttpResponse.json(401, Map.of("error", "invalid_token"))
          .header("WWW-Authenticate", "Bearer error=\"invalid_token\"");
    }
    final String subject = claims.get().get("sub").asString();
    final List<String> scopes = splitScopes(claims.get().has("scope") ? claims.get().get("scope").asString() : "");
    final DirectoryUser user = directory.resolve(subject).orElse(null);
    final Map<String, Object> info = new LinkedHashMap<>();
    info.put("sub", subject);
    if (user != null && scopes.contains("profile") && user.name() != null) {
      info.put("name", user.name());
    }
    if (user != null && scopes.contains("email") && user.email() != null) {
      info.put("email", user.email());
      info.put("email_verified", user.emailVerified());
    }
    return HttpResponse.json(200, info);
  }

  // ---- Logout (single logout) ----------------------------------------------------------------

  private HttpResponse logout(final RequestContext ctx) {
    final String sessionId = ctx.cookie(Cookies.SESSION);
    currentSession(ctx).ifPresent(session -> refreshTokens.revokeForSubject(session.subject()));
    sessions.destroy(sessionId);
    final String postLogout = ctx.queryParam("post_logout_redirect_uri");
    final HttpResponse cleared = (postLogout != null && !postLogout.isBlank())
        ? HttpResponse.redirect(postLogout)
        : HttpResponse.json(200, Map.of("status", "logged_out"));
    return cleared.header("Set-Cookie", cookies.clearSession());
  }

  // ---- Passkey enrolment ---------------------------------------------------------------------

  private HttpResponse registerStart(final RequestContext ctx) {
    final JsonNode body = readJson(ctx);
    final HumanAuthenticator.Challenge challenge = humans.startRegistration(
        text(body, "username"), text(body, "displayName"));
    return HttpResponse.raw(200, "application/json",
        challenge.optionsJson().getBytes(StandardCharsets.UTF_8));
  }

  private HttpResponse registerFinish(final RequestContext ctx) {
    final JsonNode body = readJson(ctx);
    final boolean registered = humans.finishRegistration(
        text(body, "challengeId"), text(body, "username"), body.get("registration").toString());
    if (!registered) {
      throw ApiException.badRequest("passkey registration failed");
    }
    return HttpResponse.json(201, Map.of("registered", true));
  }

  // ---- Client admin --------------------------------------------------------------------------

  private HttpResponse registerClient(final RequestContext ctx) {
    adminAuth.requireAdmin(ctx.header("Authorization"));
    final RegisterClientRequest request = Json.parse(ctx.body(), RegisterClientRequest.class);
    final ClientService.Registration registration;
    try {
      registration = clients.register(request.name(), request.redirectUris(), request.scopes(),
          request.confidential());
    } catch (final IllegalArgumentException e) {
      throw ApiException.badRequest(e.getMessage());
    }
    final OidcClient client = registration.client();
    String secret = null;
    if (registration.secret() != null) {
      secret = new String(registration.secret());
      Arrays.fill(registration.secret(), '\0');
    }
    return HttpResponse.json(201, new RegisterClientResponse(client.clientId(), secret, client.name(),
        client.redirectUris(), client.scopes(), client.isConfidential()));
  }

  private HttpResponse listClients(final RequestContext ctx) {
    adminAuth.requireAdmin(ctx.header("Authorization"));
    final List<ClientView> views = new ArrayList<>();
    for (final OidcClient client : clients.list()) {
      views.add(ClientView.from(client));
    }
    return HttpResponse.json(200, views);
  }

  // ---- Helpers -------------------------------------------------------------------------------

  private Optional<BrowserSession> currentSession(final RequestContext ctx) {
    return sessions.lookup(ctx.cookie(Cookies.SESSION));
  }

  private PendingAuthorization requirePending(final String requestId) {
    return pending.get(requestId)
        .orElseThrow(() -> ApiException.badRequest("unknown or expired authorization request"));
  }

  private static void requireCsrf(final PendingAuthorization request, final String presented) {
    if (!Tokens.constantTimeEquals(request.csrfToken(), presented)) {
      throw ApiException.badRequest("CSRF token mismatch");
    }
  }

  private static HttpResponse errorRedirect(final String redirectUri, final String error, final String state) {
    final Map<String, String> params = new LinkedHashMap<>();
    params.put("error", error);
    if (state != null) {
      params.put("state", state);
    }
    return HttpResponse.redirect(appendQuery(redirectUri, params));
  }

  private static String appendQuery(final String uri, final Map<String, String> params) {
    final StringBuilder url = new StringBuilder(uri);
    url.append(uri.contains("?") ? '&' : '?');
    boolean first = true;
    for (final Map.Entry<String, String> entry : params.entrySet()) {
      if (!first) {
        url.append('&');
      }
      first = false;
      url.append(urlEncode(entry.getKey())).append('=').append(urlEncode(entry.getValue()));
    }
    return url.toString();
  }

  private static String urlEncode(final String value) {
    return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  private static List<String> splitScopes(final String scope) {
    final List<String> scopes = new ArrayList<>();
    if (scope != null) {
      for (final String s : scope.trim().split("\\s+")) {
        if (!s.isBlank() && !scopes.contains(s)) {
          scopes.add(s);
        }
      }
    }
    return scopes;
  }

  private static JsonNode readJson(final RequestContext ctx) {
    try {
      return Json.MAPPER.readTree(ctx.body());
    } catch (final RuntimeException e) {
      throw ApiException.badRequest("malformed JSON request body");
    }
  }

  private static String text(final JsonNode node, final String field) {
    return node != null && node.has(field) && !node.get(field).isNull() ? node.get(field).asString() : null;
  }

  private static String[] basicCredentials(final String authorizationHeader) {
    final String prefix = "Basic ";
    if (authorizationHeader == null || authorizationHeader.length() <= prefix.length()
        || !authorizationHeader.regionMatches(true, 0, prefix, 0, prefix.length())) {
      return null;
    }
    try {
      final String creds = new String(
          Base64.getDecoder().decode(authorizationHeader.substring(prefix.length()).trim()),
          StandardCharsets.UTF_8);
      final int colon = creds.indexOf(':');
      return colon < 0 ? null : new String[] {creds.substring(0, colon), creds.substring(colon + 1)};
    } catch (final IllegalArgumentException e) {
      return null;
    }
  }
}
