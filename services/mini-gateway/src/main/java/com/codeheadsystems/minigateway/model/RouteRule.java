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
    if (!path.startsWith(pathPrefix)) {
      return false;
    }
    return methods.isEmpty() || methods.contains(method.toUpperCase(Locale.ROOT));
  }

  /** A catch-all rule requiring any authenticated caller — the default when none is configured. */
  public static RouteRule defaultAuthenticated() {
    return new RouteRule("/", List.of(), RouteAccess.AUTHENTICATED, null);
  }
}
