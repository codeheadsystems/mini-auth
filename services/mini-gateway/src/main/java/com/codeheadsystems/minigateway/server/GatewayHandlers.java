package com.codeheadsystems.minigateway.server;

import com.codeheadsystems.minigateway.auth.AuthenticatedUser;
import com.codeheadsystems.minigateway.auth.BearerAuthenticator;
import com.codeheadsystems.minigateway.auth.SessionAuthenticator;
import com.codeheadsystems.minigateway.server.http.HttpResponse;
import com.codeheadsystems.minigateway.server.http.RequestContext;
import com.codeheadsystems.minigateway.server.http.Router;
import com.codeheadsystems.minigateway.service.RoutePolicy;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
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
    final String path = normalizePath(pathOf(uri));
    if (path == null) {
      // A path we cannot safely canonicalize (traversal above root, undecodable, NUL) must never
      // be matched against a rule — a hostile `/public/../admin` could otherwise dodge the prefix
      // check and fall through to a permissive rule. Deny outright.
      return HttpResponse.json(403, Map.of("error", "forbidden"));
    }

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
    final AuthenticatedUser caller = user.orElse(null);
    // Always emit the identity headers (empty when there is no authenticated caller — e.g. a PUBLIC
    // route) so a proxy configured to copy them onto the upstream OVERWRITES, never passes through,
    // any client-supplied X-Auth-* value. The proxy must still be configured to set these from our
    // response and to strip the client's own copies.
    return HttpResponse.json(200, Map.of("allow", true))
        .header(HEADER_SUBJECT, caller == null ? "" : caller.subject())
        .header(HEADER_SCOPE, caller == null ? "" : String.join(" ", caller.scopes()))
        .header(HEADER_SOURCE, caller == null ? "" : caller.source());
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

  /**
   * Canonicalize a request path before route matching: percent-decode once (preserving a literal
   * {@code +}), then collapse {@code //}, {@code .} and {@code ..} segments. Returns {@code null}
   * for anything that cannot be safely canonicalized — a traversal above root, an undecodable
   * escape, or an embedded NUL — so the caller can refuse it. Decoding once (never twice) means an
   * upstream that also normalizes once sees the same path we matched, closing path-confusion gaps.
   */
  static String normalizePath(final String rawPath) {
    if (rawPath == null || rawPath.isBlank()) {
      return "/";
    }
    final String decoded;
    try {
      // Protect a literal '+' (URLDecoder would turn it into a space, which is wrong for a path),
      // then decode %XX exactly once.
      decoded = URLDecoder.decode(rawPath.replace("+", "%2B"), StandardCharsets.UTF_8);
    } catch (final RuntimeException e) {
      return null;
    }
    if (decoded.indexOf('\0') >= 0) {
      return null;
    }
    final Deque<String> segments = new ArrayDeque<>();
    for (final String segment : decoded.split("/", -1)) {
      if (segment.isEmpty() || ".".equals(segment)) {
        continue;
      }
      if ("..".equals(segment)) {
        if (segments.isEmpty()) {
          return null; // traversal above root
        }
        segments.removeLast();
      } else {
        segments.addLast(segment);
      }
    }
    return "/" + String.join("/", segments);
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
