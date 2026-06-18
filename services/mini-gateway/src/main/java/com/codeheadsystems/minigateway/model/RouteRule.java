package com.codeheadsystems.minigateway.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;
import java.util.Locale;

/**
 * One config-driven route rule: which proxied paths (and optionally which methods) it covers, and
 * how they are gated. Rules are matched in order by path prefix; the first match wins.
 *
 * @param pathPrefix the path prefix this rule covers (e.g. {@code "/admin"}; {@code "/"} catches all).
 * @param methods    the HTTP methods it applies to (upper-case); empty/null means all methods.
 * @param access     how the matched request is gated.
 * @param scope      for {@link RouteAccess#SCOPE}, the scope the principal must hold; else ignored.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RouteRule(String pathPrefix, List<String> methods, RouteAccess access, String scope) {

  public RouteRule {
    if (pathPrefix == null || pathPrefix.isBlank()) {
      throw new IllegalArgumentException("route pathPrefix must not be blank");
    }
    if (access == null) {
      throw new IllegalArgumentException("route access must not be null");
    }
    if (access == RouteAccess.SCOPE && (scope == null || scope.isBlank())) {
      throw new IllegalArgumentException("a SCOPE route must name a scope");
    }
    methods = methods == null ? List.of() : List.copyOf(methods);
  }

  /** @return whether this rule covers the given request method + path. */
  public boolean matches(final String method, final String path) {
    if (!pathCovers(path)) {
      return false;
    }
    return methods.isEmpty() || methods.contains(method.toUpperCase(Locale.ROOT));
  }

  /**
   * Segment-aware prefix match: {@code /admin} covers {@code /admin} and {@code /admin/x} but NOT
   * {@code /admin-public}. A raw {@code startsWith} would over-match the latter and silently widen
   * a rule's reach. {@code "/"} is the catch-all. The request path is assumed already canonicalized
   * (see {@code GatewayHandlers.normalizePath}).
   */
  private boolean pathCovers(final String path) {
    if ("/".equals(pathPrefix)) {
      return true;
    }
    final String prefix = pathPrefix.endsWith("/")
        ? pathPrefix.substring(0, pathPrefix.length() - 1) : pathPrefix;
    return path.equals(prefix) || path.startsWith(prefix + "/");
  }

  /** A catch-all rule requiring any authenticated caller — the default when none is configured. */
  public static RouteRule defaultAuthenticated() {
    return new RouteRule("/", List.of(), RouteAccess.AUTHENTICATED, null);
  }
}
