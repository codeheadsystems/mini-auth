package com.codeheadsystems.minigateway.server;

import com.codeheadsystems.minigateway.auth.AuthenticatedUser;
import com.codeheadsystems.minigateway.auth.BearerAuthenticator;
import com.codeheadsystems.minigateway.auth.SessionAuthenticator;
import com.codeheadsystems.minigateway.server.http.HttpResponse;
import com.codeheadsystems.minigateway.server.http.RequestContext;
import com.codeheadsystems.minigateway.server.http.Router;
import com.codeheadsystems.minigateway.service.RoutePolicy;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;

/**
 * The forward-auth endpoint. A reverse proxy (Traefik ForwardAuth, Caddy forward_auth, nginx
 * auth_request) calls {@code /verify} before forwarding each request, passing the original request's
 * method/URI in {@code X-Forwarded-*} (or {@code X-Original-*}) headers and the client's own
 * {@code Cookie}/{@code Authorization} headers. This handler:
 *
 * <ol>
 *   <li>validates the caller — a bearer access token (API) or the shared mini-oidc SSO session
 *       cookie (browser);</li>
 *   <li>evaluates the target route through {@link RoutePolicy} (mini-policy);</li>
 *   <li>answers <b>200</b> with identity headers on allow, <b>302</b>-to-login for an unauthenticated
 *       browser, <b>401</b> for an unauthenticated API client, and <b>403</b> for an authenticated
 *       caller the route forbids.</li>
 * </ol>
 *
 * <p>On allow, the proxy is told to copy {@code X-Auth-Subject} / {@code X-Auth-Scope} /
 * {@code X-Auth-Source} onto the upstream request, so a no-auth upstream still learns who the caller
 * is. No secrets (cookies, tokens) are ever logged.
 */
public final class GatewayHandlers {

  /** Identity headers handed to the upstream on allow (configure the proxy to copy these). */
  public static final String HEADER_SUBJECT = "X-Auth-Subject";
  public static final String HEADER_SCOPE = "X-Auth-Scope";
  public static final String HEADER_SOURCE = "X-Auth-Source";

  private static final String[] METHODS =
      {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"};

  private final ServerConfig config;
  private final RoutePolicy policy;
  private final SessionAuthenticator sessionAuth;
  private final BearerAuthenticator bearerAuth;

  /** @param bearerAuth the bearer authenticator, or null when bearer verification is not configured. */
  public GatewayHandlers(final ServerConfig config, final RoutePolicy policy,
                         final SessionAuthenticator sessionAuth, final BearerAuthenticator bearerAuth) {
    this.config = config;
    this.policy = policy;
    this.sessionAuth = sessionAuth;
    this.bearerAuth = bearerAuth;
  }

  /** @return a router with the verify endpoint (all methods) and a health check. */
  public Router router() {
    final Router router = new Router();
    router.route("GET", "/health", ctx -> HttpResponse.json(200, Map.of("status", "ok")));
    for (final String method : METHODS) {
      router.route(method, "/verify", this::verify);
    }
    return router;
  }

  private HttpResponse verify(final RequestContext ctx) {
    final String method = forwarded(ctx, "X-Forwarded-Method", "X-Original-Method", "GET");
    final String uri = forwarded(ctx, "X-Forwarded-Uri", "X-Original-URI", "/");
    final String path = pathOf(uri);

    final Optional<AuthenticatedUser> user = authenticate(ctx);
    final RoutePolicy.Outcome outcome = policy.evaluate(method, path, user);
    return switch (outcome) {
      case ALLOW -> allow(user);
      case FORBIDDEN -> HttpResponse.json(403, Map.of("error", "forbidden"));
      case UNAUTHENTICATED -> unauthenticated(ctx, uri);
    };
  }

  /** Bearer first (API clients), then the shared SSO session cookie (browsers). */
  private Optional<AuthenticatedUser> authenticate(final RequestContext ctx) {
    if (bearerAuth != null) {
      final Optional<AuthenticatedUser> byToken = bearerAuth.authenticate(ctx.header("Authorization"));
      if (byToken.isPresent()) {
        return byToken;
      }
    }
    return sessionAuth.authenticate(ctx.cookie(config.cookieName()));
  }

  private HttpResponse allow(final Optional<AuthenticatedUser> user) {
    HttpResponse response = HttpResponse.json(200, Map.of("allow", true));
    if (user.isPresent()) {
      final AuthenticatedUser caller = user.get();
      response = response
          .header(HEADER_SUBJECT, caller.subject())
          .header(HEADER_SCOPE, String.join(" ", caller.scopes()))
          .header(HEADER_SOURCE, caller.source());
    }
    return response;
  }

  private HttpResponse unauthenticated(final RequestContext ctx, final String uri) {
    if (isBrowser(ctx) && config.loginUrl() != null && !config.loginUrl().isBlank()) {
      final String original = originalUrl(ctx, uri);
      final String sep = config.loginUrl().contains("?") ? "&" : "?";
      final String location = config.loginUrl() + sep + config.returnParam() + "="
          + URLEncoder.encode(original, StandardCharsets.UTF_8);
      return HttpResponse.redirect(location);
    }
    return HttpResponse.json(401, Map.of("error", "unauthorized"))
        .header("WWW-Authenticate", "Bearer");
  }

  // ---- Helpers -------------------------------------------------------------------------------

  /** A browser navigation wants HTML (or says so via Sec-Fetch-Mode), so it can follow a redirect. */
  private static boolean isBrowser(final RequestContext ctx) {
    final String accept = ctx.header("Accept");
    if (accept != null && accept.contains("text/html")) {
      return true;
    }
    return "navigate".equalsIgnoreCase(ctx.header("Sec-Fetch-Mode"));
  }

  private static String originalUrl(final RequestContext ctx, final String uri) {
    final String proto = firstNonBlank(ctx.header("X-Forwarded-Proto"), "http");
    final String host = firstNonBlank(ctx.header("X-Forwarded-Host"), ctx.header("Host"), "localhost");
    return proto + "://" + host + uri;
  }

  private static String forwarded(final RequestContext ctx, final String primary,
                                  final String secondary, final String fallback) {
    return firstNonBlank(ctx.header(primary), ctx.header(secondary), fallback);
  }

  private static String pathOf(final String uri) {
    final int q = uri.indexOf('?');
    return q < 0 ? uri : uri.substring(0, q);
  }

  private static String firstNonBlank(final String... values) {
    for (final String value : values) {
      if (value != null && !value.isBlank()) {
        return value;
      }
    }
    return "";
  }
}
